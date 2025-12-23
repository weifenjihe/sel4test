/*
 * HyperAMP Server for seL4
 * Compatible with HighSpeedCProxy and new Linux client
 * 
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <autoconf.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include <arch_stdio.h>

// 引入 HyperAMP 共享内存队列头文件
#include "shm/hyperamp_shm_queue.h"
#include "highspeed_proxy_protocol.h"
#include "highspeed_proxy_frontend_sim.h"  // 前端协议栈模拟器

/* ==================== 配置常量 ==================== */
#if defined(CONFIG_PLAT_IMX8MP_EVK)
    // imx8MP 平台共享内存配置
    #define SHM_TX_QUEUE_PADDR  0x7E000000UL
    #define SHM_RX_QUEUE_PADDR  0x7E001000UL
    #define SHM_DATA_PADDR      0x7E002000UL

#elif defined(CONFIG_PLAT_PHYTIUM_PI)
    // Phytium-Pi 平台共享内存配置
    #define SHM_TX_QUEUE_PADDR  0xDE000000UL
    #define SHM_RX_QUEUE_PADDR  0xDE001000UL
    #define SHM_DATA_PADDR      0xDE002000UL

#else
    #error "Unknown Platform! Please define addresses for this board."
#endif
// 物理地址定义 (与 kernel 配置匹配)
// #define SHM_TX_QUEUE_PADDR  0x7E000000UL
// #define SHM_RX_QUEUE_PADDR  0x7E001000UL
// #define SHM_DATA_PADDR      0x7E002000UL

// HyperAMP 布局 (与 Linux 端和内核配置匹配)
#define SHM_TX_QUEUE_SIZE       (4 * 1024)        // 4KB TX Queue
#define SHM_RX_QUEUE_SIZE       (4 * 1024)        // 4KB RX Queue
#define SHM_DATA_SIZE           (4 * 1024 * 1024)  // 4MB Data Region


#define ZONE_ID_LINUX           0
#define ZONE_ID_SEL4            1

/* ==================== 全局变量 ==================== */

// HyperAMP 双向通信 - 正确的架构理解：
// - seL4 运行前端协议栈 (Frontend)：负责生成请求，处理响应
// - Linux 运行后端协议栈 (Backend)：负责转发请求到网络，返回响应
//
// TX Queue: seL4 → Linux (seL4 写入请求，Linux 读取并转发到网络)
// RX Queue: Linux → seL4 (Linux 写入响应，seL4 读取并交给应用)
static volatile HyperampShmQueue *g_tx_queue = NULL;  // seL4 → Linux (seL4 写请求)
static volatile HyperampShmQueue *g_rx_queue = NULL;  // Linux → seL4 (seL4 读响应)
volatile void *g_data_region = NULL;  // 全局变量，供 highspeed_proxy_frontend_sim.h 使用

static int g_message_count = 0;
static int g_error_count = 0;

/* 测试模式选择 */
#define TEST_MODE_LISTEN    0  // 监听后端响应（原模式）
#define TEST_MODE_FRONTEND  1  // 运行前端协议栈模拟器
#define CURRENT_TEST_MODE   TEST_MODE_LISTEN  // 切换测试模式

/* ==================== 辅助函数 ==================== */

void __plat_putchar(int c);

static void print_hex(const uint8_t *data, size_t len, size_t max_display)
{
    printf("  [HEX] ");
    for (size_t i = 0; i < len && i < max_display; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n        ");
    }
    if (len > max_display) printf("... (%zu bytes total)", len);
    printf("\n");
}

static void print_string(const char *data, size_t len, size_t max_display)
{
    printf("  [STR] \"");
    for (size_t i = 0; i < len && i < max_display; i++) {
        char c = data[i];
        if (c >= 32 && c <= 126) {
            printf("%c", c);
        } else if (c == '\0') {
            break;
        } else {
            printf("\\x%02x", (unsigned char)c);
        }
    }
    if (len > max_display) printf("...");
    printf("\"\n");
}

/* ==================== 服务处理函数 ==================== */

/**
 * @brief Echo 服务 - 简单回显
 */
static int service_echo(volatile void *data_ptr, size_t length)
{
    printf("[seL4] Echo service: %zu bytes\n", length);
    print_string((const char *)data_ptr, length, 64);
    return HYPERAMP_OK;
}

/**
 * @brief 加密服务 - XOR 加密
 */
static int service_encrypt(volatile void *data_ptr, size_t length)
{
    printf("[seL4] Encrypting %zu bytes\n", length);
    
    volatile uint8_t *buf = (volatile uint8_t *)data_ptr;
    for (size_t i = 0; i < length; i++) {
        buf[i] ^= 0x5A;  // XOR 密钥
    }
    
    printf("[seL4] Encryption complete\n");
    return HYPERAMP_OK;
}

/**
 * @brief 解密服务 - XOR 解密 (与加密相同)
 */
static int service_decrypt(volatile void *data_ptr, size_t length)
{
    printf("[seL4] Decrypting %zu bytes\n", length);
    return service_encrypt(data_ptr, length);  // XOR 是对称的
}

/**
 * @brief 代理消息解析服务 - 真实的 HighSpeedCProxy 场景处理
 */
static int service_proxy_message(volatile void *data_ptr, size_t length, uint8_t msg_type)
{
    const char *type_names[] = {"DEVICE", "STRATEGY", "SESSION", "DATA"};
    printf("\n[seL4] ========== Proxy Message (%s) ==========\n", 
           msg_type <= 3 ? type_names[msg_type] : "UNKNOWN");
    printf("[seL4] Payload length: %zu bytes\n", length);
    
    switch (msg_type) {
        case HYPERAMP_MSG_TYPE_DEV:  // 0 - 设备消息
            printf("[seL4] Device Control Message\n");
            printf("[seL4] TODO: Parse device configuration (TAP/TUN creation)\n");
            // 真实场景：解析 JSON 或二进制设备配置
            // 例如：{"cmd":"create_tap", "name":"tap0", "ip":"192.168.1.100"}
            print_string((const char *)data_ptr, length, 256);
            break;
            
        case HYPERAMP_MSG_TYPE_STRGY:  // 1 - 策略消息
            printf("[seL4] Proxy Strategy Message\n");
            printf("[seL4] TODO: Update forwarding rules\n");
            // 真实场景：更新路由表或防火墙规则
            // 例如：{"src":"192.168.1.0/24", "dst":"10.0.0.0/8", "action":"forward"}
            print_string((const char *)data_ptr, length, 256);
            break;
            
        case HYPERAMP_MSG_TYPE_SESS:  // 2 - 会话消息
            printf("[seL4] Session Management Message\n");
            
            if (length >= sizeof(SessionCreatePayload)) {
                SessionCreatePayload *sess = (SessionCreatePayload *)data_ptr;
                
                // 解析会话信息
                const char *proto_name = (sess->protocol == PROXY_PROTO_TCP) ? "TCP" : "UDP";
                const char *state_name;
                switch (sess->state) {
                    case PROXY_STATE_SYN_SENT: state_name = "SYN_SENT"; break;
                    case PROXY_STATE_ESTABLISHED: state_name = "ESTABLISHED"; break;
                    case PROXY_STATE_FIN_WAIT: state_name = "FIN_WAIT"; break;
                    case PROXY_STATE_CLOSED: state_name = "CLOSED"; break;
                    default: state_name = "UNKNOWN"; break;
                }
                
                // 解析 IP 地址
                char src_ip_str[16], dst_ip_str[16];
                ip_to_str(sess->src_ip, src_ip_str);
                ip_to_str(sess->dst_ip, dst_ip_str);
                
                printf("[seL4] Session Details:\n");
                printf("[seL4]   Protocol: %s\n", proto_name);
                printf("[seL4]   State: %s\n", state_name);
                printf("[seL4]   Source: %s:%u\n", src_ip_str, sess->src_port);
                printf("[seL4]   Destination: %s:%u\n", dst_ip_str, sess->dst_port);
                
                // 真实场景：在 seL4 端创建对应的 socket 连接
                printf("[seL4] TODO: Create socket on seL4 side\n");
                printf("[seL4]   -> socket(%s, %s)\n", 
                       proto_name,
                       sess->protocol == PROXY_PROTO_TCP ? "SOCK_STREAM" : "SOCK_DGRAM");
                printf("[seL4]   -> connect(%s:%u)\n", dst_ip_str, sess->dst_port);
            } else {
                printf("[seL4] ERROR: Session payload too short (%zu < %zu)\n",
                       length, sizeof(SessionCreatePayload));
            }
            break;
            
        case HYPERAMP_MSG_TYPE_DATA:  // 3 - 数据消息
            printf("[seL4] Network Data Message\n");
            
            // 尝试解析为 HTTP 请求
            if (length >= sizeof(HttpRequestHeader)) {
                HttpRequestHeader *http_req = (HttpRequestHeader *)data_ptr;
                
                // 检查是否是有效的 HTTP 请求
                if (http_req->method[0] >= 'A' && http_req->method[0] <= 'Z') {
                    printf("[seL4] HTTP Request Detected:\n");
                    printf("[seL4]   Method: %.8s\n", http_req->method);
                    printf("[seL4]   URI: %.256s\n", http_req->uri);
                    printf("[seL4]   Host: %.128s\n", http_req->host);
                    printf("[seL4]   Content-Length: %u\n", http_req->content_length);
                    
                    // 真实场景：通过 seL4 的网络栈发送 HTTP 请求
                    printf("[seL4] TODO: Forward HTTP request via seL4 network stack\n");
                    printf("[seL4]   -> lwip_connect() or picotcp_connect()\n");
                    printf("[seL4]   -> send(%s %s HTTP/1.1)\n", 
                           http_req->method, http_req->uri);
                } else {
                    // 不是 HTTP，可能是其他协议或原始数据
                    printf("[seL4] Raw Network Data:\n");
                    print_hex((const uint8_t *)data_ptr, length, 64);
                    print_string((const char *)data_ptr, length, 128);
                }
            } else {
                // 数据太短，直接显示
                printf("[seL4] Short Data Packet:\n");
                print_hex((const uint8_t *)data_ptr, length, 64);
                print_string((const char *)data_ptr, length, 128);
            }
            
            // 真实场景：将数据通过网络发送出去
            printf("[seL4] TODO: Transmit data via seL4 network interface\n");
            break;
            
        default:
            printf("[seL4] ERROR: Unknown message type: %u\n", msg_type);
            return HYPERAMP_ERROR;
    }
    
    printf("[seL4] ==========================================\n\n");
    return HYPERAMP_OK;
}

/**
 * @brief 处理单个消息
 */
static int process_message(volatile void *data_ptr, size_t length, uint16_t service_id)
{
    switch (service_id) {
        case 0:  // Echo
            return service_echo(data_ptr, length);
            
        case 1:  // 加密
            return service_encrypt(data_ptr, length);
            
        case 2:  // 解密
            return service_decrypt(data_ptr, length);
            
        case 10:  // 设备消息
            return service_proxy_message(data_ptr, length, 0);
            
        case 11:  // 策略消息
            return service_proxy_message(data_ptr, length, 1);
            
        case 12:  // 会话消息
            return service_proxy_message(data_ptr, length, 2);
            
        case 13:  // 数据消息
            return service_proxy_message(data_ptr, length, 3);
            
        default:
            printf("[seL4] Unknown service %u, echoing\n", service_id);
            return service_echo(data_ptr, length);
    }
}

/**
 * @brief 发送回复消息到 Linux
 */
static int send_reply_to_linux(const char *reply_data, size_t reply_len, 
                                uint16_t frontend_sess, uint16_t backend_sess)
{
    // 构造消息头
    HyperampMsgHeader msg_hdr = {
        .version = 1,
        .proxy_msg_type = HYPERAMP_MSG_TYPE_DATA,
        .frontend_sess_id = frontend_sess,
        .backend_sess_id = backend_sess,
        .payload_len = (uint16_t)reply_len,
    };
    
    // 计算总大小
    size_t total_size = sizeof(HyperampMsgHeader) + reply_len;
    if (total_size > g_rx_queue->block_size) {
        printf("[seL4] Reply too large: %zu bytes\n", total_size);
        return HYPERAMP_ERROR;
    }
    
    // 准备完整消息
    char msg_buf[4096];
    hyperamp_safe_memcpy(msg_buf, &msg_hdr, sizeof(HyperampMsgHeader));
    if (reply_len > 0) {
        hyperamp_safe_memcpy(msg_buf + sizeof(HyperampMsgHeader), 
                            reply_data, reply_len);
    }
    
    // 入队到 TX Queue (seL4 → Linux)
    // 重要：数据区使用独立的共享内存区域 (0xDE002000)
    volatile void *tx_data_base = g_data_region;
    
    int ret = hyperamp_queue_enqueue(g_tx_queue, ZONE_ID_SEL4,
                                     msg_buf, total_size, tx_data_base);
    if (ret == HYPERAMP_OK) {
        printf("[seL4] Message sent to Linux: %zu bytes\n", total_size);
    } else {
        printf("[seL4] Failed to send message to Linux\n");
    }
    
    return ret;
}

/* ==================== 安全的测试函数 ==================== */
#define TEST_IRQ_NUMBER  74 //软中断号

//手动指定一个很可能为空的槽位索引,通常 RootTask 的 CNode 至少有 12位 (4096个槽位)
#define TEST_HARDCODED_SLOT  2000 // 前几百个被系统占用

static void test_interrupt_registration_blind(void) 
{
    printf("\n[seL4] ========== Interrupt Registration Test (Blind Slot Mode) ==========\n");
    printf("[seL4] Note: Skipping BootInfo. Assuming Slot %d is empty.\n", TEST_HARDCODED_SLOT);

    seL4_CPtr irq_handler_cap = (seL4_CPtr)TEST_HARDCODED_SLOT;

    printf("[seL4] Step 1: Trying to get IRQ Handler Cap for IRQ %d into Slot %lu...\n", 
           TEST_IRQ_NUMBER, irq_handler_cap);
    
    // 请求中断权能
    int error = seL4_IRQControl_Get(seL4_CapIRQControl, TEST_IRQ_NUMBER, 
                                    seL4_CapInitThreadCNode, irq_handler_cap, seL4_WordBits);

    if (error == seL4_NoError) {
        printf("[seL4] ✓ SUCCESS: Kernel granted IRQ Handler Cap for IRQ %d!\n", TEST_IRQ_NUMBER);
        printf("[seL4]   -> This CONFIRMS the Kernel GIC driver is working.\n");
    } else {
        printf("[seL4] ✗ FAILED: Could not get IRQ Cap. Error: %d\n", error);
        
        if (error == 8) { // seL4_DeleteFirst
            printf("[seL4]   -> Error 8: Slot %d is ALREADY OCCUPIED.\n", TEST_HARDCODED_SLOT);
            printf("[seL4]      Try changing TEST_HARDCODED_SLOT to a different number.\n");
        } else if (error == 2) { // seL4_FailedLookup
            printf("[seL4]   -> Error 2: Slot %d is OUT OF BOUNDS (CNode too small).\n", TEST_HARDCODED_SLOT);
            printf("[seL4]      Try a smaller number (e.g., 500).\n");
        } else {
            printf("[seL4]   -> Other error. Check Kernel IRQ configuration.\n");
        }
    }

    printf("[seL4] =============================================================\n\n");
}
/* ==================== 主消息循环 ==================== */

/**
 * @brief HyperAMP 消息服务器主循环
 */
void hyperamp_server_main_loop(void)
{
    printf("\n[seL4] ========================================\n");
    printf("[seL4] HyperAMP Frontend (seL4 Side) Starting...\n");
    printf("[seL4] ========================================\n");
    printf("[seL4] Architecture:\n");
    printf("[seL4]   - seL4: Frontend Protocol Stack (生成请求，处理响应)\n");
    printf("[seL4]   - Linux: Backend Protocol Stack (转发到网络)\n");
    printf("[seL4] TX Queue (seL4->Linux): %p\n", (void *)g_tx_queue);
    printf("[seL4] RX Queue (Linux->seL4): %p\n", (void *)g_rx_queue);
    printf("[seL4] Data Region: %p\n", (void *)g_data_region);
    printf("[seL4] Zone ID: %d\n", ZONE_ID_SEL4);
    
    // seL4 自己初始化队列（对等通信架构）
    printf("[seL4] Initializing queues (seL4 as creator)...\n");
    
    // 配置 TX Queue (seL4 → Linux, seL4 写请求)
    HyperampQueueConfig tx_config = {
        .map_mode = HYPERAMP_MAP_MODE_CONTIGUOUS_BOTH,
        .capacity = 256,
        .block_size = 4096,
        .phy_addr = SHM_TX_QUEUE_PADDR,
        .virt_addr = (uint64_t)g_tx_queue,
    };
    
    // 配置 RX Queue (Linux → seL4, seL4 读响应)
    HyperampQueueConfig rx_config = {
        .map_mode = HYPERAMP_MAP_MODE_CONTIGUOUS_BOTH,
        .capacity = 256,
        .block_size = 4096,
        .phy_addr = SHM_RX_QUEUE_PADDR,
        .virt_addr = (uint64_t)g_rx_queue,
    };
    
    // 初始化 TX Queue (is_creator=1, seL4 作为创建者)
    printf("[seL4] About to initialize TX Queue at address %p\n", (void *)g_tx_queue);
    printf("[seL4] TX Queue should map to physical address: 0x%lx\n", SHM_TX_QUEUE_PADDR);
    
    // 在初始化之前读取内存内容
    printf("[seL4] TX Queue BEFORE init (first 16 bytes): ");
    volatile uint8_t *tx_bytes_before = (volatile uint8_t *)g_tx_queue;
    for (int i = 0; i < 16; i++) {
        printf("%02x ", tx_bytes_before[i]);
    }
    printf("\n");
    
    if (hyperamp_queue_init(g_tx_queue, &tx_config, 1) != HYPERAMP_OK) {
        printf("[seL4] ERROR: Failed to initialize TX queue!\n");
        return;
    }
    printf("[seL4] TX Queue initialized\n");
    
    /* 关键：失效缓存，确保打印的是从物理内存读取的最新数据 */
    hyperamp_cache_invalidate((volatile void *)g_tx_queue, 64);
    
    // 在初始化之后读取内存内容
    printf("[seL4] TX Queue AFTER init (first 16 bytes): ");
    volatile uint8_t *tx_bytes_after = (volatile uint8_t *)g_tx_queue;
    for (int i = 0; i < 16; i++) {
        printf("%02x ", tx_bytes_after[i]);
    }
    printf("\n");
    
    // 初始化 RX Queue
    printf("[seL4] About to initialize RX Queue at address %p\n", (void *)g_rx_queue);
    
    printf("[seL4] RX Queue BEFORE init (first 16 bytes): ");
    volatile uint8_t *rx_bytes_before = (volatile uint8_t *)g_rx_queue;
    for (int i = 0; i < 16; i++) {
        printf("%02x ", rx_bytes_before[i]);
    }
    printf("\n");
    
    if (hyperamp_queue_init(g_rx_queue, &rx_config, 1) != HYPERAMP_OK) {
        printf("[seL4] ERROR: Failed to initialize RX queue!\n");
        return;
    }
    printf("[seL4] RX Queue initialized\n");
    
    /* 关键：失效缓存，确保打印的是从物理内存读取的最新数据 */
    hyperamp_cache_invalidate((volatile void *)g_rx_queue, 64);
    
    printf("[seL4] RX Queue AFTER init (first 16 bytes): ");
    volatile uint8_t *rx_bytes_after = (volatile uint8_t *)g_rx_queue;
    for (int i = 0; i < 16; i++) {
        printf("%02x ", rx_bytes_after[i]);
    }
    printf("\n");
    
    printf("[seL4] Both queues ready for communication\n");
    
    printf("[seL4] About to read queue metadata...\n");
    printf("[seL4] TX Queue address: %p\n", (void *)g_tx_queue);
    printf("[seL4] RX Queue address: %p\n", (void *)g_rx_queue);
    printf("[seL4] capacity offset: %zu\n", offsetof(HyperampShmQueue, capacity));
    printf("[seL4] Reading TX capacity at address: %p\n", 
           (void *)((uintptr_t)g_tx_queue + offsetof(HyperampShmQueue, capacity)));
    
    // 读取队列信息
    uint16_t tx_capacity = hyperamp_safe_read_u16(g_tx_queue, 
                                                   offsetof(HyperampShmQueue, capacity));
    printf("[seL4] TX capacity read successful: %u\n", tx_capacity);
    
    uint16_t tx_block_size = hyperamp_safe_read_u16(g_tx_queue,
                                                     offsetof(HyperampShmQueue, block_size));
    printf("[seL4] TX block_size read successful: %u\n", tx_block_size);
    
    uint16_t rx_capacity = hyperamp_safe_read_u16(g_rx_queue,
                                                   offsetof(HyperampShmQueue, capacity));
    printf("[seL4] RX capacity read successful: %u\n", rx_capacity);
    
    uint16_t rx_block_size = hyperamp_safe_read_u16(g_rx_queue,
                                                     offsetof(HyperampShmQueue, block_size));
    printf("[seL4] RX block_size read successful: %u\n", rx_block_size);
    
    printf("[seL4] TX Queue: capacity=%u, block_size=%u\n", tx_capacity, tx_block_size);
    printf("[seL4] RX Queue: capacity=%u, block_size=%u\n", rx_capacity, rx_block_size);
    printf("[seL4] ========================================\n");
    
    /* 根据测试模式选择不同的执行路径 */
    if (CURRENT_TEST_MODE == TEST_MODE_FRONTEND) {
        printf("[seL4] Running in FRONTEND TEST MODE\n");
        printf("[seL4] Will send requests and wait for responses\n\n");
        
        // 准备前端上下文
        FrontendProxyContext frontend_ctx;
        frontend_proxy_init(&frontend_ctx, g_tx_queue, g_rx_queue);
        
        // 运行测试场景
        printf("[seL4] Starting test scenario...\n\n");
        frontend_run_test_scenario(&frontend_ctx);
        
        printf("\n[seL4] Test scenario completed!\n");
        printf("[seL4] Check backend logs to verify message exchange\n");
        
        // 进入监听循环，继续接收可能的后续响应
        printf("\n[seL4] Switching to listen mode for additional responses...\n");
    } else {
        printf("[seL4] Running in LISTEN MODE\n");
        printf("[seL4] Waiting for responses from Backend...\n\n");
        printf("[seL4] NOTE: In production, seL4 应用通过前端协议栈发送请求到 TX Queue\n");
        printf("[seL4]       当前测试模式：监听 RX Queue，接收 Linux 后端的响应\n\n");
    }
    
    // 消息处理缓冲区
    char msg_buf[4096];
    size_t msg_len;
    
    // 主循环：监听来自 Linux 后端的响应
    while (1) {
        /* 关键：在读取队列状态前失效缓存，确保读取到 Linux 写入的最新数据 */
        hyperamp_cache_invalidate(g_rx_queue, 64);
        
        // 检查 RX Queue 是否有来自 Linux 后端的响应
        uint16_t rx_header = hyperamp_safe_read_u16(g_rx_queue,
                                                     offsetof(HyperampShmQueue, header));
        uint16_t rx_tail = hyperamp_safe_read_u16(g_rx_queue,
                                                   offsetof(HyperampShmQueue, tail));
        
        if (rx_tail != rx_header) {
            // 有响应消息,出队
            // 重要：数据区使用独立的共享内存区域 (0xDE002000)
            volatile void *rx_data_base = g_data_region;
            printf("debug: rx_header=%u, rx_tail=%u, rx_data_base=%p,msg_len=%zu,msg_buf=%p\n", rx_header, rx_tail, rx_data_base, msg_len, msg_buf);
            int ret = hyperamp_queue_dequeue(g_rx_queue, ZONE_ID_SEL4,
                                            msg_buf, sizeof(msg_buf), &msg_len,
                                            rx_data_base);
            
            if (ret == HYPERAMP_OK && msg_len >= sizeof(HyperampMsgHeader)) {
                g_message_count++;
                
                HyperampMsgHeader *hdr = (HyperampMsgHeader *)msg_buf;
                printf("\n[seL4] === Response #%d from Backend ===\n", g_message_count);
                printf("[seL4] Version: %u, Type: %u\n", hdr->version, hdr->proxy_msg_type);
                printf("[seL4] Sessions: %u/%u\n", hdr->frontend_sess_id, hdr->backend_sess_id);
                printf("[seL4] Payload: %u bytes\n", hdr->payload_len);
                
                // 提取载荷数据
                void *payload_ptr = msg_buf + sizeof(HyperampMsgHeader);
                size_t payload_len = hdr->payload_len;
                
                // 根据消息类型处理响应
                int service_id = hdr->proxy_msg_type + 10;  // 映射到服务ID
                int result = process_message(payload_ptr, payload_len, service_id);
                
                if (result == HYPERAMP_OK) {
                    printf("[seL4] ✓ Response processed successfully\n");
                    // 真实场景：将响应交给 seL4 应用程序
                } else {
                    g_error_count++;
                    printf("[seL4] ✗ Failed to process response\n");
                }
                
                printf("[seL4] === Response processed ===\n\n");
            } else {
                g_error_count++;
                printf("[seL4] Dequeue failed or invalid response\n");
            }
        }
        
        // 简单延迟,避免过度占用 CPU
        for (volatile int i = 0; i < 10000; i++);
    }
}


/* ==================== 主函数 ==================== */

int main(void)
{
    printf("\n");
    printf("================================================\n");
    printf("  HyperAMP Server for seL4\n");
    printf("  Compatible with HighSpeedCProxy\n");
    printf("================================================\n\n");

    test_interrupt_registration_blind();
    // 从 IPC buffer 获取共享内存地址
    // boot.c 存储方式: IPC buffer 第一个 word 存储指向地址数组的指针
    // 该数组包含: [TX Queue vaddr, RX Queue vaddr, Data Region vaddr]
    seL4_Word *ipc_buf = (seL4_Word *)seL4_GetIPCBuffer();
    unsigned long long *vaddrs = (unsigned long long *)*ipc_buf;
    
    // HyperAMP 4KB 队列布局 (与 Linux 端和内核配置匹配)
    // 正确的架构：
    // - TX Queue (0xDE000000): seL4 → Linux (seL4 前端发送请求，Linux 后端接收)
    // - RX Queue (0xDE001000): Linux → seL4 (Linux 后端发送响应，seL4 前端接收)

    // g_tx_queue = (volatile HyperampShmQueue *)vaddrs[0];    // TX: seL4 → Linux (seL4 写请求)
    // g_rx_queue = (volatile HyperampShmQueue *)vaddrs[1];    // RX: Linux → seL4 (seL4 读响应)
    // g_data_region = (volatile void *)vaddrs[2];             // Data Region: 4MB
    g_tx_queue = (volatile HyperampShmQueue *)0x54e000;
    g_rx_queue = (volatile HyperampShmQueue *)0x54f000;
    g_data_region = (volatile void *)0x550000;
    printf("[seL4] Shared Memory Addresses:\n");
    printf("  TX Queue (seL4->Linux): %p\n", (void *)g_tx_queue);
    printf("  RX Queue (Linux->seL4): %p\n", (void *)g_rx_queue);
    printf("  Data Region:            %p\n", (void *)g_data_region);
    
    // 验证地址有效性
    if (!g_tx_queue || !g_rx_queue || !g_data_region) {
        printf("[seL4] ERROR: Invalid shared memory addresses!\n");
        return -1;
    }
    
    // // 地址访问测试 - 测试三个区域是否都能正常访问
    // printf("[seL4] Testing memory access...\n");
    
    // // 测试 TX Queue 访问 (读取第一个字节)
    // printf("[seL4] Testing TX Queue access at %p...", (void *)g_tx_queue);
    // volatile uint8_t *tx_test = (volatile uint8_t *)g_tx_queue;
    // volatile uint8_t tx_byte = tx_test[0];  // 读取第一个字节
    // tx_test[0] = tx_byte;  // 写回
    // printf(" OK (first byte: 0x%02x)\n", tx_byte);
    
    // // 测试 RX Queue 访问
    // printf("[seL4] Testing RX Queue access at %p...", (void *)g_rx_queue);
    // volatile uint8_t *rx_test = (volatile uint8_t *)g_rx_queue;
    // volatile uint8_t rx_byte = rx_test[0];
    // rx_test[0] = rx_byte;
    // printf(" OK (first byte: 0x%02x)\n", rx_byte);
    
    // // 测试 Data Region 访问
    // printf("[seL4] Testing Data Region access at %p...", (void *)g_data_region);
    // volatile uint8_t *data_test = (volatile uint8_t *)g_data_region;
    // volatile uint8_t data_byte = data_test[0];
    // data_test[0] = data_byte;
    // printf(" OK (first byte: 0x%02x)\n", data_byte);
    
    // printf("[seL4] Memory access test PASSED!\n");
    
    // 检查结构体大小
    printf("[seL4] HyperampShmQueue size: %zu bytes\n", sizeof(HyperampShmQueue));
    printf("[seL4] HYPERAMP_MAX_MAP_TABLE_ENTRIES: %d\n", HYPERAMP_MAX_MAP_TABLE_ENTRIES);
    printf("[seL4] magic field offset: %zu bytes\n", offsetof(HyperampShmQueue, magic));
    printf("[seL4] WARNING: If offset > 4096, accessing magic will page fault!\n");
    
    printf("[seL4] Shared memory initialized successfully\n\n");
    
    // 启动消息处理循环
    hyperamp_server_main_loop();
   
    // 永不返回
    return 0;
}
