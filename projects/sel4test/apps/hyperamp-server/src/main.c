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

/* ==================== 配置常量 ==================== */

// 物理地址定义 (与 kernel 配置匹配)
#define SHM_TX_QUEUE_PADDR  0xDE000000UL
#define SHM_RX_QUEUE_PADDR  0xDE001000UL
#define SHM_DATA_PADDR      0xDE002000UL

// HyperAMP 布局 (与 Linux 端和内核配置匹配)
#define SHM_TX_QUEUE_SIZE       (4 * 1024)        // 4KB TX Queue
#define SHM_RX_QUEUE_SIZE       (4 * 1024)        // 4KB RX Queue
#define SHM_DATA_SIZE           (4 * 1024 * 1024)  // 4MB Data Region


#define ZONE_ID_LINUX           0
#define ZONE_ID_SEL4            1

/* ==================== 全局变量 ==================== */

// HyperAMP 双向通信
// TX Queue: Linux → seL4 (seL4 从此队列读取)
// RX Queue: seL4 → Linux (seL4 向此队列写入)
static volatile HyperampShmQueue *g_tx_queue = NULL;  // Linux → seL4 (seL4 读)
static volatile HyperampShmQueue *g_rx_queue = NULL;  // seL4 → Linux (seL4 写)
static volatile void *g_data_region = NULL;

static int g_message_count = 0;
static int g_error_count = 0;

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
 * @brief 代理消息解析服务 - 直接显示载荷数据
 */
static int service_proxy_message(volatile void *data_ptr, size_t length, uint8_t msg_type)
{
    const char *type_names[] = {"DEVICE", "STRATEGY", "SESSION", "DATA"};
    printf("[seL4] Proxy Message (%s):\n", 
           msg_type <= 3 ? type_names[msg_type] : "UNKNOWN");
    printf("[seL4]   Payload length: %zu bytes\n", length);
    
    // 显示载荷数据（十六进制）
    if (length > 0) {
        print_hex((const uint8_t *)data_ptr, length, 64);
    }
    
    // 显示载荷数据（字符串，如果是可打印字符）
    if (length > 0) {
        print_string((const char *)data_ptr, length, 128);
    }
    
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
    
    // 入队
    // 数据区紧跟在队列控制块之后
    volatile void *rx_data_base = (volatile void *)((char *)g_rx_queue + sizeof(HyperampShmQueue));
    
    int ret = hyperamp_queue_enqueue(g_rx_queue, ZONE_ID_SEL4,
                                     msg_buf, total_size, rx_data_base);
    if (ret == HYPERAMP_OK) {
        printf("[seL4] Reply sent: %zu bytes\n", total_size);
    } else {
        printf("[seL4] Failed to send reply\n");
    }
    
    return ret;
}

/* ==================== 主消息循环 ==================== */

/**
 * @brief HyperAMP 消息服务器主循环
 */
void hyperamp_server_main_loop(void)
{
    printf("\n[seL4] ========================================\n");
    printf("[seL4] HyperAMP Server Starting...\n");
    printf("[seL4] ========================================\n");
    printf("[seL4] TX Queue (Linux->seL4): %p\n", (void *)g_tx_queue);
    printf("[seL4] RX Queue (seL4->Linux): %p\n", (void *)g_rx_queue);
    printf("[seL4] Data Region: %p\n", (void *)g_data_region);
    printf("[seL4] Zone ID: %d\n", ZONE_ID_SEL4);
    
    // seL4 自己初始化队列（对等通信架构）
    printf("[seL4] Initializing queues (seL4 as creator)...\n");
    
    // 配置 TX Queue (Linux → seL4, seL4 负责创建)
    HyperampQueueConfig tx_config = {
        .map_mode = HYPERAMP_MAP_MODE_CONTIGUOUS_BOTH,
        .capacity = 256,
        .block_size = 4096,
        .phy_addr = SHM_TX_QUEUE_PADDR,
        .virt_addr = (uint64_t)g_tx_queue,
    };
    
    // 配置 RX Queue (seL4 → Linux, seL4 负责创建)
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
    printf("[seL4] Server ready! Waiting for messages...\n\n");
    
    // 消息处理缓冲区
    char msg_buf[4096];
    size_t msg_len;
    
    // 主循环
    while (1) {
        /* 关键：在读取队列状态前失效缓存，确保读取到 Linux 写入的最新数据 */
        hyperamp_cache_invalidate(g_tx_queue, 64);
        
        // 检查是否有消息
        uint16_t tx_header = hyperamp_safe_read_u16(g_tx_queue,
                                                     offsetof(HyperampShmQueue, header));
        uint16_t tx_tail = hyperamp_safe_read_u16(g_tx_queue,
                                                   offsetof(HyperampShmQueue, tail));
        
        if (tx_tail != tx_header) {
            // 有消息,出队
            // 数据区紧跟在队列控制块之后
            volatile void *tx_data_base = (volatile void *)((char *)g_tx_queue + sizeof(HyperampShmQueue));
            
            int ret = hyperamp_queue_dequeue(g_tx_queue, ZONE_ID_SEL4,
                                            msg_buf, sizeof(msg_buf), &msg_len,
                                            tx_data_base);
            
            if (ret == HYPERAMP_OK && msg_len >= sizeof(HyperampMsgHeader)) {
                g_message_count++;
                
                HyperampMsgHeader *hdr = (HyperampMsgHeader *)msg_buf;
                printf("\n[seL4] === Message #%d ===\n", g_message_count);
                printf("[seL4] Version: %u, Type: %u\n", hdr->version, hdr->proxy_msg_type);
                printf("[seL4] Sessions: %u/%u\n", hdr->frontend_sess_id, hdr->backend_sess_id);
                printf("[seL4] Payload: %u bytes\n", hdr->payload_len);
                
                // 提取载荷数据
                void *payload_ptr = msg_buf + sizeof(HyperampMsgHeader);
                size_t payload_len = hdr->payload_len;
                
                // 根据消息类型处理
                int service_id = hdr->proxy_msg_type + 10;  // 映射到服务ID
                int result = process_message(payload_ptr, payload_len, service_id);
                
                if (result == HYPERAMP_OK) {
                    // 发送回复 (简单的 ACK)
                    const char *ack = "OK";
                    send_reply_to_linux(ack, 3, hdr->frontend_sess_id, hdr->backend_sess_id);
                } else {
                    g_error_count++;
                    printf("[seL4] Service failed\n");
                }
                
                printf("[seL4] === Message processed ===\n\n");
            } else {
                g_error_count++;
                printf("[seL4] Dequeue failed or invalid message\n");
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
    
    // 从 IPC buffer 获取共享内存地址
    // boot.c 存储方式: IPC buffer 第一个 word 存储指向地址数组的指针
    // 该数组包含: [TX Queue vaddr, RX Queue vaddr, Data Region vaddr]
    seL4_Word *ipc_buf = (seL4_Word *)seL4_GetIPCBuffer();
    unsigned long long *vaddrs = (unsigned long long *)*ipc_buf;
    
    // HyperAMP 4KB 队列布局 (与 Linux 端和内核配置匹配)
    // 从 Linux 视角: TX = Linux->seL4, RX = seL4->Linux
    // 从 seL4 视角: 读取 TX, 写入 RX
    g_tx_queue = (volatile HyperampShmQueue *)vaddrs[0];    // TX Queue: Linux → seL4 (seL4 读)
    g_rx_queue = (volatile HyperampShmQueue *)vaddrs[1];    // RX Queue: seL4 → Linux (seL4 写)
    g_data_region = (volatile void *)vaddrs[2];             // Data Region: 4MB
    
    printf("[seL4] Shared Memory Addresses:\n");
    printf("  TX Queue (Linux->seL4): %p\n", (void *)g_tx_queue);
    printf("  RX Queue (seL4->Linux): %p\n", (void *)g_rx_queue);
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
