/*
 * Copyright 2024, seL4 Project
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <types.h>
#include <api/failures.h>
#include <api/syscall.h>
#include <kernel/thread.h>
#include <machine/io.h>
#include <arch/machine.h>
#include <arch/kernel/vspace.h>
#include <plat/machine/hardware.h>
#include <arch/machine/hardware.h>
#include <util.h>
#include <stdint.h>
#include <string.h>

// 共享内存物理地址定义 (与hvisor配置一致)
#define SHM_PADDR_DATA      0xDE000000UL
#define SHM_SIZE_DATA       0x00400000UL  /* 4MB */
#define SHM_PADDR_ROOT_Q    0xDE400000UL  /* Root Linux队列 */
#define SHM_PADDR_SEL4_Q    0xDE410000UL  /* seL4队列 */
#define SHM_PAGE_SIZE       0x1000UL

// 消息队列初始化标记
#define INIT_MARK_INITIALIZED  (0xEEEEEEEEU)
#define MSG_QUEUE_MARK_IDLE    (0xBBBBBBBBU)

// 消息处理状态 - 与Linux端保持一致
#define MSG_DEAL_STATE_NO      (0)  // not dealt yet
#define MSG_DEAL_STATE_YES     (1)  // has dealt

// 服务处理结果 - 与Linux端保持一致  
#define MSG_SERVICE_RET_NONE       (0)  // 消息还未被处理
#define MSG_SERVICE_RET_SUCCESS    (1)  // 服务正确响应
#define MSG_SERVICE_RET_FAIL       (2)  // 服务未曾正确服务，或参数错误等
#define MSG_SERVICE_RET_NOT_EXITS  (3)  // 请求的服务不存在
#define MSG_SERVICE_RET_WAIT       (4)  // 被引入用户态，等待处理

// AMP消息队列结构
struct AmpMsgQueue {
    unsigned int working_mark;
    unsigned short buf_size;
    unsigned short empty_h;
    unsigned short wait_h;
    unsigned short proc_ing_h;
};

// 消息标志结构 - 必须与Linux端完全一致！
struct MsgFlag {
    unsigned short deal_state : 1;     // 1位：消息是否被处理
    unsigned short service_result : 2; // 2位：消息对应的服务是否被正确服务
    unsigned short reserved : 13;      // 13位：保留位，确保总共16位
};

// 消息结构 - 必须与Linux端字段顺序和类型完全一致！
struct Msg {
    struct MsgFlag flag;         // 消息标志 (2字节，位于开头)
    unsigned short service_id;   // 服务ID (2字节，不是4字节!)
    unsigned int offset;         // 数据在共享缓冲区中的偏移 (4字节)
    unsigned int length;         // 数据长度 (4字节)
};

// 消息实体结构
struct MsgEntry {
    struct Msg msg;
    unsigned short nxt_idx;      // 下一个消息的索引
};

// 内核中的虚拟地址映射 (通过内核页表直接访问物理内存)
static volatile char *g_data_vaddr = NULL;
static volatile struct AmpMsgQueue *g_root_q_vaddr = NULL;
static volatile struct AmpMsgQueue *g_sel4_q_vaddr = NULL;

// 轮询状态控制
static int g_polling_enabled = 0;
static int g_message_count = 0;
static int g_server_running = 0;

// 内核级消息服务器状态
static int g_check_counter = 0;
static int g_wait_timeout_ms = 100;  // 轮询间隔

// ================== 代理消息数据结构定义 ==================

// | 消息类型 | proxy_msg_type| 内层消息头类型   |    典型用途          |
// | 设备消息 |     0         | DevMsgHeader    | 设备启用/禁用/查询 |
// | 策略消息 |     1         | StrgyMsgHeader  | 负载均衡策略设置/查询 |
// | 会话消息 |     2         | SessMsgHeader   | TCP/UDP会话创建/关闭 |
// | 数据消息 |     3         | ProxyMsgHeader  | 实际网络数据转发 |

// 外层消息头 (ProxyMsgHeader - 8字节)
typedef struct {
    uint8_t  version;             // 协议版本
    uint8_t  proxy_msg_type;      // 消息类型: 0=设备, 1=策略, 2=会话, 3=数据
    uint16_t frontend_sess_id;    // 前端会话ID
    uint16_t backend_sess_id;     // 后端会话ID
    uint16_t payload_len;         // 载荷长度
} __attribute__((packed)) ProxyMsgHeader;

// 设备消息头 (DevMsgHeader - 10字节)
typedef struct {
    uint16_t version;        // 协议版本
    uint16_t msg_type;       // 消息类型: 0=禁用, 1=启用, 2=查询
    uint16_t msg_id;         // 消息ID
    uint16_t action_type;    // 动作类型: 0=命令, 1=响应
    uint16_t payload_len;    // 载荷长度
} __attribute__((packed)) DevMsgHeader;

// 策略消息头 (StrgyMsgHeader - 10字节)
typedef struct {
    uint16_t version;       // 协议版本
    uint16_t msg_type;      // 消息类型: 0=设置, 1=查询
    uint16_t msg_id;        // 消息ID
    uint16_t action_type;   // 动作类型: 0=命令, 1=响应
    uint16_t payload_len;   // 载荷长度
} __attribute__((packed)) StrgyMsgHeader;

// 会话消息头 (SessMsgHeader - 10字节)
typedef struct {
    uint16_t version;        // 协议版本
    uint16_t msg_type;       // 消息类型: 0=关闭, 1=创建
    uint16_t action_type;    // 动作类型: 0=命令, 1=响应
    uint16_t ip_version;     // IP版本: 4=IPv4, 6=IPv6
    uint16_t payload_len;    // 载荷长度
} __attribute__((packed)) SessMsgHeader;

// 设备消息载荷 (2字节)
typedef struct {
    uint16_t data;   // 设备掩码或状态数据
} __attribute__((packed)) DevMsgMask;

// 设备查询响应 (4字节)
typedef struct {
    uint8_t  status;    // 状态码
    uint8_t  error;     // 错误码
    uint16_t data;      // 设备掩码
} __attribute__((packed)) DevMsgReport;

// 策略响应 (4字节)
typedef struct {
    uint8_t  status;    // 状态码
    uint8_t  error;     // 错误码
    uint16_t data;      // 策略数据
} __attribute__((packed)) StrgyMsgReport;

// 会话操作响应 (2字节)
typedef struct {
    uint8_t status;     // 状态: 0=成功, 1=失败
    uint8_t code;       // 错误码
} __attribute__((packed)) SessOpRespData;

// IPv4地址结构
typedef struct {
    uint8_t data[4];
} __attribute__((packed)) IPv4Address;

// IPv4会话参数 (10字节)
typedef struct {
    uint16_t      device_selection;       // 设备选择
    uint16_t      transport_layer_proto;  // 传输层协议: 0=UDP, 1=TCP
    IPv4Address   dest_ipv4;              // 目标IPv4地址
    uint16_t      dest_port;              // 目标端口
} __attribute__((packed)) SessIPv4Params;

// ================== 消息解析函数 ==================

// 解析设备消息
static void parse_device_message(const char *data_ptr, unsigned int length)
{
    if (length < sizeof(ProxyMsgHeader) + sizeof(DevMsgHeader)) {
        printf("[proxy] Device message too short: %u bytes\n", length);
        return;
    }
    
    // 解析外层消息头
    const ProxyMsgHeader *outer_hdr = (const ProxyMsgHeader *)data_ptr;
    printf("[proxy] === Device Message ===\n");
    printf("[proxy] Outer Header:\n");
    printf("[proxy]   version: %u\n", outer_hdr->version);
    printf("[proxy]   proxy_msg_type: %u (DEVICE)\n", outer_hdr->proxy_msg_type);
    printf("[proxy]   frontend_sess_id: %u\n", outer_hdr->frontend_sess_id);
    printf("[proxy]   backend_sess_id: %u\n", outer_hdr->backend_sess_id);
    printf("[proxy]   payload_len: %u\n", outer_hdr->payload_len);
    
    // 解析内层消息头
    const DevMsgHeader *inner_hdr = (const DevMsgHeader *)(data_ptr + sizeof(ProxyMsgHeader));
    printf("[proxy] Device Header:\n");
    printf("[proxy]   version: %u\n", inner_hdr->version);
    
    const char *msg_type_str[] = {"DISABLE", "ENABLE", "QUERY"};
    printf("[proxy]   msg_type: %u (%s)\n", inner_hdr->msg_type, 
           inner_hdr->msg_type <= 2 ? msg_type_str[inner_hdr->msg_type] : "UNKNOWN");
    
    printf("[proxy]   msg_id: %u\n", inner_hdr->msg_id);
    printf("[proxy]   action_type: %u (%s)\n", inner_hdr->action_type,
           inner_hdr->action_type == 0 ? "COMMAND" : "RESPONSE");
    printf("[proxy]   payload_len: %u\n", inner_hdr->payload_len);
    
    // 解析载荷
    const uint8_t *payload = (const uint8_t *)(data_ptr + sizeof(ProxyMsgHeader) + sizeof(DevMsgHeader));
    
    if (inner_hdr->msg_type == 2 && inner_hdr->action_type == 1) {
        // 查询响应: 4字节
        if (inner_hdr->payload_len >= sizeof(DevMsgReport)) {
            const DevMsgReport *report = (const DevMsgReport *)payload;
            printf("[proxy] Device Query Response:\n");
            printf("[proxy]   status: %u\n", report->status);
            printf("[proxy]   error: %u\n", report->error);
            printf("[proxy]   active_devices: 0x%04x\n", report->data);
        }
    } else {
        // 启用/禁用: 2字节
        if (inner_hdr->payload_len >= sizeof(DevMsgMask)) {
            const DevMsgMask *mask = (const DevMsgMask *)payload;
            printf("[proxy] Device Mask: 0x%04x\n", mask->data);
        }
    }
}

// 解析策略消息
static void parse_strategy_message(const char *data_ptr, unsigned int length)
{
    if (length < sizeof(ProxyMsgHeader) + sizeof(StrgyMsgHeader)) {
        printf("[proxy] Strategy message too short: %u bytes\n", length);
        return;
    }
    
    const ProxyMsgHeader *outer_hdr = (const ProxyMsgHeader *)data_ptr;
    printf("[proxy] === Strategy Message ===\n");
    printf("[proxy] Outer Header:\n");
    printf("[proxy]   version: %u\n", outer_hdr->version);
    printf("[proxy]   proxy_msg_type: %u (STRATEGY)\n", outer_hdr->proxy_msg_type);
    printf("[proxy]   frontend_sess_id: %u\n", outer_hdr->frontend_sess_id);
    printf("[proxy]   backend_sess_id: %u\n", outer_hdr->backend_sess_id);
    printf("[proxy]   payload_len: %u\n", outer_hdr->payload_len);
    
    const StrgyMsgHeader *inner_hdr = (const StrgyMsgHeader *)(data_ptr + sizeof(ProxyMsgHeader));
    printf("[proxy] Strategy Header:\n");
    printf("[proxy]   version: %u\n", inner_hdr->version);
    
    const char *msg_type_str[] = {"SET", "QUERY"};
    printf("[proxy]   msg_type: %u (%s)\n", inner_hdr->msg_type,
           inner_hdr->msg_type <= 1 ? msg_type_str[inner_hdr->msg_type] : "UNKNOWN");
    
    printf("[proxy]   msg_id: %u\n", inner_hdr->msg_id);
    printf("[proxy]   action_type: %u (%s)\n", inner_hdr->action_type,
           inner_hdr->action_type == 0 ? "COMMAND" : "RESPONSE");
    printf("[proxy]   payload_len: %u\n", inner_hdr->payload_len);
    
    const uint8_t *payload = (const uint8_t *)(data_ptr + sizeof(ProxyMsgHeader) + sizeof(StrgyMsgHeader));
    
    if (inner_hdr->msg_type == 1 && inner_hdr->action_type == 1) {
        // 查询响应
        if (inner_hdr->payload_len >= sizeof(StrgyMsgReport)) {
            const StrgyMsgReport *report = (const StrgyMsgReport *)payload;
            printf("[proxy] Strategy Query Response:\n");
            printf("[proxy]   status: %u\n", report->status);
            printf("[proxy]   error: %u\n", report->error);
            printf("[proxy]   current_strategy: %u\n", report->data);
        }
    } else {
        // 设置命令/响应
        if (inner_hdr->payload_len >= 2) {
            uint16_t strategy = *(const uint16_t *)payload;
            printf("[proxy] Strategy Parameter: %u\n", strategy);
        }
    }
}

// 解析会话消息
static void parse_session_message(const char *data_ptr, unsigned int length)
{
    if (length < sizeof(ProxyMsgHeader) + sizeof(SessMsgHeader)) {
        printf("[proxy] Session message too short: %u bytes\n", length);
        return;
    }
    
    const ProxyMsgHeader *outer_hdr = (const ProxyMsgHeader *)data_ptr;
    printf("[proxy] === Session Message ===\n");
    printf("[proxy] Outer Header:\n");
    printf("[proxy]   version: %u\n", outer_hdr->version);
    printf("[proxy]   proxy_msg_type: %u (SESSION)\n", outer_hdr->proxy_msg_type);
    printf("[proxy]   frontend_sess_id: %u\n", outer_hdr->frontend_sess_id);
    printf("[proxy]   backend_sess_id: %u\n", outer_hdr->backend_sess_id);
    printf("[proxy]   payload_len: %u\n", outer_hdr->payload_len);
    
    const SessMsgHeader *inner_hdr = (const SessMsgHeader *)(data_ptr + sizeof(ProxyMsgHeader));
    printf("[proxy] Session Header:\n");
    printf("[proxy]   version: %u\n", inner_hdr->version);
    
    const char *msg_type_str[] = {"CLOSE", "CREATE"};
    printf("[proxy]   msg_type: %u (%s)\n", inner_hdr->msg_type,
           inner_hdr->msg_type <= 1 ? msg_type_str[inner_hdr->msg_type] : "UNKNOWN");
    
    printf("[proxy]   action_type: %u (%s)\n", inner_hdr->action_type,
           inner_hdr->action_type == 0 ? "COMMAND" : "RESPONSE");
    printf("[proxy]   ip_version: %u (IPv%u)\n", inner_hdr->ip_version, inner_hdr->ip_version);
    printf("[proxy]   payload_len: %u\n", inner_hdr->payload_len);
    
    const uint8_t *payload = (const uint8_t *)(data_ptr + sizeof(ProxyMsgHeader) + sizeof(SessMsgHeader));
    
    if (inner_hdr->action_type == 1) {
        // 响应消息
        if (inner_hdr->payload_len >= sizeof(SessOpRespData)) {
            const SessOpRespData *resp = (const SessOpRespData *)payload;
            printf("[proxy] Session Response:\n");
            printf("[proxy]   status: %u (%s)\n", resp->status, 
                   resp->status == 0 ? "SUCCESS" : "FAIL");
            printf("[proxy]   code: %u\n", resp->code);
        }
    } else {
        // 命令消息 - 会话参数
        if (inner_hdr->ip_version == 4 && inner_hdr->payload_len >= sizeof(SessIPv4Params)) {
            const SessIPv4Params *params = (const SessIPv4Params *)payload;
            printf("[proxy] IPv4 Session Parameters:\n");
            printf("[proxy]   device: %u\n", params->device_selection);
            printf("[proxy]   protocol: %u (%s)\n", params->transport_layer_proto,
                   params->transport_layer_proto == 1 ? "TCP" : "UDP");
            printf("[proxy]   dest_ip: %u.%u.%u.%u\n",
                   params->dest_ipv4.data[0], params->dest_ipv4.data[1],
                   params->dest_ipv4.data[2], params->dest_ipv4.data[3]);
            printf("[proxy]   dest_port: %u\n", params->dest_port);
        }
    }
}

// 解析数据消息
static void parse_data_message(const char *data_ptr, unsigned int length)
{
    if (length < sizeof(ProxyMsgHeader)) {
        printf("[proxy] Data message too short: %u bytes\n", length);
        return;
    }
    
    const ProxyMsgHeader *outer_hdr = (const ProxyMsgHeader *)data_ptr;
    printf("[proxy] === Data Message ===\n");
    printf("[proxy] Outer Header:\n");
    printf("[proxy]   version: %u\n", outer_hdr->version);
    printf("[proxy]   proxy_msg_type: %u (DATA)\n", outer_hdr->proxy_msg_type);
    printf("[proxy]   frontend_sess_id: %u\n", outer_hdr->frontend_sess_id);
    printf("[proxy]   backend_sess_id: %u\n", outer_hdr->backend_sess_id);
    printf("[proxy]   payload_len: %u\n", outer_hdr->payload_len);
    
    // 数据消息没有内层消息头,直接是载荷
    const uint8_t *payload = (const uint8_t *)(data_ptr + sizeof(ProxyMsgHeader));
    unsigned int payload_len = outer_hdr->payload_len;
    
    printf("[proxy] Data Payload (%u bytes):\n", payload_len);
    
    // 尝试判断是否为HTTP数据
    if (payload_len > 4) {
        // 手动比较字符串，避免使用memcmp，使用int代替bool
        int is_http = (payload[0] == 'H' && payload[1] == 'T' && 
                       payload[2] == 'T' && payload[3] == 'P');
        int is_get = (payload[0] == 'G' && payload[1] == 'E' && 
                      payload[2] == 'T' && payload[3] == ' ');
        int is_post = (payload[0] == 'P' && payload[1] == 'O' && 
                       payload[2] == 'S' && payload[3] == 'T');
        
        if (is_http || is_get || is_post) {
            printf("[proxy]   [HTTP Data] ");
            for (unsigned int i = 0; i < payload_len && i < 100; i++) {
                if (payload[i] >= 32 && payload[i] <= 126) {
                    printf("%c", payload[i]);
                } else if (payload[i] == '\r' || payload[i] == '\n') {
                    printf("\\n");
                } else {
                    printf(".");
                }
            }
            if (payload_len > 100) printf("...");
            printf("\n");
        } else {
            // 十六进制显示
            printf("[proxy]   [HEX] ");
            for (unsigned int i = 0; i < payload_len && i < 64; i++) {
                printf("%02x ", payload[i]);
            }
            if (payload_len > 64) printf("...");
            printf("\n");
        }
    } else {
        // 十六进制显示
        printf("[proxy]   [HEX] ");
        for (unsigned int i = 0; i < payload_len && i < 64; i++) {
            printf("%02x ", payload[i]);
        }
        if (payload_len > 64) printf("...");
        printf("\n");
    }
}

// 将单个十六进制字符转换为数值 ('0'-'9', 'a'-'f', 'A'-'F')
static int hex_char_to_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;  // 无效字符
}

// 将十六进制字符串转换为二进制数据
// 输入: hex_str = "0100000000000c00" (ASCII字符串)
// 输出: binary_buf = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00}
// 返回值: 转换后的字节数，失败返回-1
static int hex_string_to_binary(const char *hex_str, unsigned int hex_len, 
                                 unsigned char *binary_buf, unsigned int buf_size)
{
    // 容错处理：如果长度为奇数，检查最后一个字符是否为无效字符（如'\0'或'\n'）
    if (hex_len % 2 != 0) {
        // 检查最后一个字符
        char last_char = hex_str[hex_len - 1];
        if (last_char == '\0' || last_char == '\n' || last_char == '\r' || last_char < 32) {
            // 忽略最后一个无效字符
            printf("[kernel] [HEX] Warning: Ignoring trailing byte 0x%02x at position %u\n", 
                   (unsigned char)last_char, hex_len - 1);
            hex_len--;  // 减去1，变成偶数
        } else {
            printf("[kernel] [HEX] Invalid hex string length: %u (must be even)\n", hex_len);
            printf("[kernel] [HEX] Last char: 0x%02x ('%c')\n", 
                   (unsigned char)last_char, 
                   (last_char >= 32 && last_char <= 126) ? last_char : '.');
            return -1;
        }
    }
    
    // 如果调整后长度为0，则无有效数据
    if (hex_len == 0) {
        printf("[kernel] [HEX] Error: no valid hex characters after adjustment\n");
        return -1;
    }
    
    unsigned int binary_len = hex_len / 2;
    
    // 检查输出缓冲区大小
    if (binary_len > buf_size) {
        printf("[kernel] [HEX] Buffer too small: need %u, have %u\n", binary_len, buf_size);
        return -1;
    }
    
    printf("[kernel] [HEX] Converting %u chars to %u bytes\n", hex_len, binary_len);
    
    // 转换每两个十六进制字符为一个字节
    for (unsigned int i = 0; i < binary_len; i++) {
        int high = hex_char_to_value(hex_str[i * 2]);
        int low = hex_char_to_value(hex_str[i * 2 + 1]);
        
        if (high < 0 || low < 0) {
            printf("[kernel] [HEX] Invalid hex character at position %u\n", i * 2);
            return -1;
        }
        
        binary_buf[i] = (unsigned char)((high << 4) | low);
    }
    
    // 显示转换结果的前几个字节用于调试
    printf("[kernel] [HEX] Converted: ");
    for (unsigned int i = 0; i < binary_len && i < 8; i++) {
        printf("%02x ", binary_buf[i]);
    }
    if (binary_len > 8) printf("...");
    printf("(%u bytes total)\n", binary_len);
    
    return binary_len;
}

// !!!!! 新增：强制缓存同步函数，解决缓存一致性问题 !!!!!
static void force_cache_sync_for_shared_memory(void)
{
    if (!g_data_vaddr || !g_root_q_vaddr || !g_sel4_q_vaddr) {
        return;
    }
    
    // ARM64缓存管理：强制将所有共享内存数据写回主内存
    
    // 1. 数据同步屏障
    asm volatile("dsb sy" : : : "memory");
    
    // 2. 清理数据区域的缓存（按64字节缓存行）
    unsigned long data_start = (unsigned long)g_data_vaddr;
    for (unsigned long addr = data_start; addr < data_start + SHM_SIZE_DATA; addr += 64) {
        asm volatile("dc civac, %0" : : "r" (addr) : "memory");
    }
    
    // 3. 清理Root队列缓存
    unsigned long root_q_start = (unsigned long)g_root_q_vaddr;
    for (unsigned long addr = root_q_start; addr < root_q_start + SHM_PAGE_SIZE; addr += 64) {
        asm volatile("dc civac, %0" : : "r" (addr) : "memory");
    }
    
    // 4. 清理seL4队列缓存
    unsigned long sel4_q_start = (unsigned long)g_sel4_q_vaddr;
    for (unsigned long addr = sel4_q_start; addr < sel4_q_start + SHM_PAGE_SIZE; addr += 64) {
        asm volatile("dc civac, %0" : : "r" (addr) : "memory");
    }
    
    // 5. 最终的内存屏障
    asm volatile("dsb sy" : : : "memory");
    asm volatile("isb" : : : "memory");
}

// 简单的加密服务实现 (XOR加密)
static int hyperamp_encrypt_service(char *data, int data_len, int buf_size)
{
    if (!data || data_len <= 0 || buf_size <= data_len) {
        return -1;
    }
    
    // 简单的XOR加密，密钥为0x5A
    for (int i = 0; i < data_len; i++) {
        data[i] ^= 0x5A;
    }
    
    return 0;
}

// 简单的解密服务实现 (XOR解密)
static int hyperamp_decrypt_service(char *data, int data_len, int buf_size)
{
    // XOR加密是对称的，所以解密和加密使用相同的操作
    return hyperamp_encrypt_service(data, data_len, buf_size);
}

// 初始化Root Linux队列 (帮助Root Linux设置队列)
static void init_root_linux_queue(void)
{
    if (!g_root_q_vaddr) {
        printf("[kernel] Root queue not available for initialization\n");
        return;
    }
    
    printf("[kernel] Initializing Root Linux message queue...\n");
    
    // 检查当前状态
    printf("[kernel] Before init - Root Linux queue status:\n");
    printf("[kernel]   working_mark: 0x%x\n", g_root_q_vaddr->working_mark);
    printf("[kernel]   buf_size: %u\n", g_root_q_vaddr->buf_size);
    printf("[kernel]   empty_h: %u, wait_h: %u, proc_ing_h: %u\n", 
           g_root_q_vaddr->empty_h, g_root_q_vaddr->wait_h, g_root_q_vaddr->proc_ing_h);
    
    // 如果Root Linux队列还没有初始化，我们帮它初始化
    if (g_root_q_vaddr->working_mark != INIT_MARK_INITIALIZED) {
        printf("[kernel] Root Linux queue not initialized, initializing it...\n");
        g_root_q_vaddr->working_mark = MSG_QUEUE_MARK_IDLE;  // 设置为空闲状态
        g_root_q_vaddr->buf_size = 16;  // 支持16个消息
        g_root_q_vaddr->empty_h = 0;
        g_root_q_vaddr->wait_h = 0;
        g_root_q_vaddr->proc_ing_h = 0;
        
        // !!!!! 强制缓存同步，确保Root队列初始化对Root Linux可见 !!!!!
        printf("[kernel] Forcing cache sync for Root queue initialization...\n");
        force_cache_sync_for_shared_memory();
        
        printf("[kernel] Root Linux queue initialized by seL4 kernel\n");
    }
    
    printf("[kernel] After init - Root Linux queue status:\n");
    printf("[kernel]   working_mark: 0x%x\n", g_root_q_vaddr->working_mark);
    printf("[kernel]   buf_size: %u\n", g_root_q_vaddr->buf_size);
    printf("[kernel]   empty_h: %u, wait_h: %u, proc_ing_h: %u\n", 
           g_root_q_vaddr->empty_h, g_root_q_vaddr->wait_h, g_root_q_vaddr->proc_ing_h);
}
static void init_sel4_queue(void)
{
    if (!g_sel4_q_vaddr) {
        printf("[kernel] sel4 not available for initialization\n");
        return;
    }
    
    printf("[kernel] Initializing sel4 message queue...\n");
    
    // 检查当前状态
    printf("[kernel] Before init - sel4 queue status:\n");
    printf("[kernel]   working_mark: 0x%x\n", g_sel4_q_vaddr->working_mark);
    printf("[kernel]   buf_size: %u\n", g_sel4_q_vaddr->buf_size);
    printf("[kernel]   empty_h: %u, wait_h: %u, proc_ing_h: %u\n", 
           g_sel4_q_vaddr->empty_h, g_sel4_q_vaddr->wait_h, g_sel4_q_vaddr->proc_ing_h);
    
    // 如果seL4队列还没有初始化，我们初始化它
    if (g_sel4_q_vaddr->working_mark != INIT_MARK_INITIALIZED) {
        printf("[kernel] sel4 queue not initialized, initializing it...\n");
        g_sel4_q_vaddr->working_mark = INIT_MARK_INITIALIZED;  // 设置为已初始化状态
        g_sel4_q_vaddr->buf_size = 16;  // 支持16个消息
        g_sel4_q_vaddr->empty_h = 0;
        g_sel4_q_vaddr->wait_h = 0;
        g_sel4_q_vaddr->proc_ing_h = 0;
        
        // !!!!! 强制缓存同步，确保seL4队列初始化对Root Linux可见 !!!!!
        printf("[kernel] Forcing cache sync for seL4 queue initialization...\n");
        force_cache_sync_for_shared_memory();
        
        printf("[kernel] sel4 queue initialized by seL4 kernel\n");
    } else {
        printf("[kernel] sel4 queue already initialized\n");
    }
    
    printf("[kernel] After init - sel4 queue status:\n");
    printf("[kernel]   working_mark: 0x%x\n", g_sel4_q_vaddr->working_mark);
    printf("[kernel]   buf_size: %u\n", g_sel4_q_vaddr->buf_size);
    printf("[kernel]   empty_h: %u, wait_h: %u, proc_ing_h: %u\n", 
           g_sel4_q_vaddr->empty_h, g_sel4_q_vaddr->wait_h, g_sel4_q_vaddr->proc_ing_h);
}
// 内核级HyperAMP消息服务器主循环
void hyperamp_server_main_loop(int max_messages)
{
    if (!g_polling_enabled || !g_root_q_vaddr || !g_data_vaddr) {
        printf("[kernel] HyperAMP server cannot start - shared memory not ready\n");
        return;
    }
    
    printf("\n[kernel] === Starting HyperAMP Message Server ===\n");
    printf("[kernel] Waiting for messages from Root Linux...\n");
    printf("[kernel] Continuous polling mode (no message limit)\n");
    printf("[kernel] Polling interval: %dms\n", g_wait_timeout_ms);
    
    g_server_running = 1;
    g_message_count = 0;
    g_check_counter = 0;
    
    // 帮助Root Linux初始化队列
    init_root_linux_queue();
    init_sel4_queue();
    
    printf("[kernel] Testing shared buffer access...\n");
    
    // 计算消息实体数组的起始地址
    volatile struct MsgEntry* root_msg_entries = (volatile struct MsgEntry*)((char*)g_root_q_vaddr + sizeof(struct AmpMsgQueue));
    printf("[kernel] Root message entries start at: %p\n", (void*)root_msg_entries);
    printf("[kernel] *** Server ready, monitoring for valid messages ***\n");
    
    int consecutive_invalid_count = 0;
    int status_report_counter = 0;
    
    // 主消息处理循环 - 持续运行
    while (g_server_running) {
        int found_valid_message = 0;
        g_check_counter++;
        
        // 极限优化策略：每次循环都执行完整缓存清理，确保零消息丢失
        // 虽然CPU开销增加，但在高频连续发送场景下，这是确保消息实时性的最可靠方法
        
        // 数据同步屏障 + 完整共享内存缓存清理（包含队列和数据区域）
        force_cache_sync_for_shared_memory();
        
        // 检查队列头是否发生变化
        unsigned short current_proc_head = g_root_q_vaddr->proc_ing_h;
        
        // 如果队列头在合理范围内且有数据等待处理
        if (current_proc_head < g_root_q_vaddr->buf_size) {
            volatile struct MsgEntry* msg_entry = &root_msg_entries[current_proc_head];
            volatile struct Msg* msg = &msg_entry->msg;
            
            // 只处理有效消息：length > 0 且 offset 合理
            if (msg->length > 0 && msg->length < SHM_SIZE_DATA && 
                msg->offset < SHM_SIZE_DATA && msg->flag.deal_state != MSG_DEAL_STATE_YES) {
                
                found_valid_message = 1;
                consecutive_invalid_count = 0;
                
                printf("\n[kernel] *** VALID MESSAGE FROM ROOT LINUX *** #%d\n", ++g_message_count);
                printf("[kernel]   Index: %u, Service ID: %u, Offset: 0x%x, Length: %u\n", 
                       current_proc_head, msg->service_id, msg->offset, msg->length);
                
                // 读取并显示数据
                volatile char* data_ptr = g_data_vaddr + msg->offset;
                printf("[kernel]   *** DATA: [");
                
                // 先显示前64个字符（智能显示）
                int printable_count = 0;
                for (int i = 0; i < msg->length && i < 64; i++) {
                    char c = data_ptr[i];
                    if (c >= 32 && c <= 126) {
                        printf("%c", c);
                        printable_count++;
                    } else if (c == '\0' && printable_count > 0) {
                        // 遇到字符串结束符，停止显示
                        break;
                    } else {
                        printf("\\x%02x", (unsigned char)c);
                    }
                }
                if (msg->length > 64) printf("...");
                printf("] ***\n");
                
                // 如果数据长度超过64字符，显示完整的十六进制数据用于调试
                if (msg->length > 64) {
                    printf("[kernel]   *** FULL HEX DATA: ");
                    for (int i = 0; i < msg->length && i < 256; i++) {  // 最多显示256字节
                        printf("%02x", (unsigned char)data_ptr[i]);
                    }
                    if (msg->length > 256) printf("...");
                    printf(" (%u bytes) ***\n", msg->length);
                }
                
                // 处理服务请求
                int service_result = MSG_SERVICE_RET_SUCCESS;
                int data_modified = 0;
                
                // 代理消息处理需要的缓冲区（在switch之前声明，避免重复声明）
                unsigned char binary_buf[2048];
                int binary_len;

                switch (msg->service_id) {
                    case 1:  // 加密服务
                        printf("[kernel]   [HyperAMP] Executing ENCRYPTION service\n");
                        if (hyperamp_encrypt_service((char*)data_ptr, msg->length, SHM_SIZE_DATA - msg->offset) == 0) {
                            printf("[kernel]   [HyperAMP] Encryption completed\n");
                            data_modified = 1;
                        } else {
                            service_result = MSG_SERVICE_RET_FAIL;
                        }
                        break;
                        
                    case 2:  // 解密服务
                        printf("[kernel]   [HyperAMP] Executing DECRYPTION service\n");
                        if (hyperamp_decrypt_service((char*)data_ptr, msg->length, SHM_SIZE_DATA - msg->offset) == 0) {
                            printf("[kernel]   [HyperAMP] Decryption completed\n");
                            data_modified = 1;
                        } else {
                            service_result = MSG_SERVICE_RET_FAIL;
                        }
                        break;
                    
                    case 10:  // 设备消息服务
                        binary_len = hex_string_to_binary((const char*)data_ptr, msg->length,
                                                         binary_buf, sizeof(binary_buf));
                        if (binary_len > 0) {
                            printf("[kernel]   [Proxy] Processing DEVICE message (Service ID: 10)\n");
                            parse_device_message((const char*)binary_buf, binary_len);
                            service_result = MSG_SERVICE_RET_SUCCESS;
                        } else {
                            service_result = MSG_SERVICE_RET_FAIL;
                        }
                        break;
                        
                    case 11:  // 策略消息服务
                        binary_len = hex_string_to_binary((const char*)data_ptr, msg->length,
                                                         binary_buf, sizeof(binary_buf));
                        if (binary_len > 0) {
                            printf("[kernel]   [Proxy] Processing STRATEGY message (Service ID: 11)\n");
                            parse_strategy_message((const char*)binary_buf, binary_len);
                            service_result = MSG_SERVICE_RET_SUCCESS;
                        } else {
                            service_result = MSG_SERVICE_RET_FAIL;
                        }
                        break;
                        
                    case 12:  // 会话消息服务
                        binary_len = hex_string_to_binary((const char*)data_ptr, msg->length,
                                                         binary_buf, sizeof(binary_buf));
                        if (binary_len > 0) {
                            printf("[kernel]   [Proxy] Processing SESSION message (Service ID: 12)\n");
                            parse_session_message((const char*)binary_buf, binary_len);
                            service_result = MSG_SERVICE_RET_SUCCESS;
                        } else {
                            service_result = MSG_SERVICE_RET_FAIL;
                        }
                        break;
                        
                    case 13:  // 数据消息服务
                        binary_len = hex_string_to_binary((const char*)data_ptr, msg->length,
                                                         binary_buf, sizeof(binary_buf));
                        if (binary_len > 0) {
                            printf("[kernel]   [Proxy] Processing DATA message (Service ID: 13)\n");
                            parse_data_message((const char*)binary_buf, binary_len);
                            service_result = MSG_SERVICE_RET_SUCCESS;
                        } else {
                            service_result = MSG_SERVICE_RET_FAIL;
                        }
                        break;
                        
                    default:
                        printf("[kernel]   [HyperAMP] Echo service (ID: %u)\n", msg->service_id);
                        break;
                }
                
                // 如果数据被修改，显示处理结果
                if (data_modified) {
                    printf("[kernel]   *** RESULT: [");
                    for (int i = 0; i < msg->length && i < 32; i++) {
                        char c = data_ptr[i];
                        if (c >= 32 && c <= 126) {
                            printf("%c", c);
                        } else {
                            printf("\\x%02x", (unsigned char)c);
                        }
                    }
                    printf("] ***\n");
                }
                
                // 标记消息已处理
                msg->flag.deal_state = MSG_DEAL_STATE_YES;
                msg->flag.service_result = service_result;
                
                // 更新队列头
                unsigned short new_head;
                if (msg_entry->nxt_idx < g_root_q_vaddr->buf_size) {
                    new_head = msg_entry->nxt_idx;
                } else {
                    new_head = (current_proc_head + 1) % g_root_q_vaddr->buf_size;
                }
                
                g_root_q_vaddr->proc_ing_h = new_head;
                g_root_q_vaddr->working_mark = MSG_QUEUE_MARK_IDLE;
                
                // 强制缓存同步
                force_cache_sync_for_shared_memory();
                
                printf("[kernel]   *** Message processed successfully! ***\n");
                
            } else {
                // 无效消息，静默跳过
                consecutive_invalid_count++;
                
                // 如果连续遇到太多无效消息，重置队列状态
                if (consecutive_invalid_count >= 32) {
                    // printf("[kernel] Too many invalid messages, resetting queue state\n");
                    g_root_q_vaddr->proc_ing_h = 0;
                    g_root_q_vaddr->working_mark = MSG_QUEUE_MARK_IDLE;
                    force_cache_sync_for_shared_memory();
                    consecutive_invalid_count = 0;
                }
            }
        }
        
        // 定期显示监控状态（不要太频繁）
        if (!found_valid_message) {
            status_report_counter++;
            if (status_report_counter >= 600000) {  // 大幅增加间隔，减少噪音日志
                printf("[kernel] Monitoring... (processed: %d messages, checks: %d, queue_head: %u)\n", 
                       g_message_count, g_check_counter, g_root_q_vaddr->proc_ing_h);
                status_report_counter = 0;
            }
        }
        
    }
    
    printf("\n[kernel] === HyperAMP Message Server Stopped ===\n");
    printf("[kernel] Total valid messages processed: %d\n", g_message_count);
}

// 初始化共享内存映射 (内核启动时调用)
void init_shared_memory_kernel(void)
{
    printf("[kernel] Initializing shared memory communication\n");
    
    // !!!!! 关键问题：PPTR_BASE_OFFSET映射可能不适用于hvisor共享内存 !!!!!
    // hvisor的共享内存可能需要特殊的映射方式
    printf("[kernel] *** DEBUGGING MEMORY MAPPING ISSUE ***\n");
    
    printf("[kernel] Available physical memory range: [0xb0000000..0xe0000000)\n");
    printf("[kernel] Shared memory regions:\n");
    printf("[kernel]   Data: 0x%lx\n", (unsigned long)SHM_PADDR_DATA);
    printf("[kernel]   Root Queue: 0x%lx\n", (unsigned long)SHM_PADDR_ROOT_Q);
    printf("[kernel]   seL4 Queue: 0x%lx\n", (unsigned long)SHM_PADDR_SEL4_Q);
    
    // 首先尝试直接使用内核线性映射
    printf("[kernel] Attempting kernel linear mapping (PPTR_BASE_OFFSET + paddr)...\n");
    
    // 计算虚拟地址
    g_data_vaddr = (volatile char*)(SHM_PADDR_DATA + PPTR_BASE_OFFSET);
    g_root_q_vaddr = (volatile struct AmpMsgQueue*)(SHM_PADDR_ROOT_Q + PPTR_BASE_OFFSET);
    g_sel4_q_vaddr = (volatile struct AmpMsgQueue*)(SHM_PADDR_SEL4_Q + PPTR_BASE_OFFSET);
    
    printf("[kernel] Calculated virtual addresses:\n");
    printf("[kernel]   PPTR_BASE_OFFSET = 0x%lx\n", (unsigned long)PPTR_BASE_OFFSET);
    printf("[kernel]   Data vaddr: %p\n", (void*)g_data_vaddr);
    printf("[kernel]   Root Queue vaddr: %p\n", (void*)g_root_q_vaddr);
    printf("[kernel]   seL4 Queue vaddr: %p\n", (void*)g_sel4_q_vaddr);
    
    // // !!!!! 重要测试：验证虚拟地址是否真的映射到正确的物理地址 !!!!!
    // printf("[kernel] *** CRITICAL TEST: Verifying virtual-to-physical mapping ***\n");
    
    // // 测试1: 写入不同的测试值到每个区域，看是否能从Root Linux端读到
    // printf("[kernel] Test 1: Writing distinctive test patterns...\n");
    
    // // 写入到seL4队列区域
    // volatile unsigned int *sel4_test_ptr = (volatile unsigned int*)g_sel4_q_vaddr;
    // printf("[kernel] Writing 0xDEADBEEF to seL4 queue virtual address %p...\n", (void*)sel4_test_ptr);
    // sel4_test_ptr[0] = 0xDEADBEEF;
    
    // // 立即读回验证内核端能否读到
    // unsigned int readback_sel4 = sel4_test_ptr[0];
    // printf("[kernel] seL4 queue readback from kernel: 0x%x %s\n", readback_sel4, 
    //        (readback_sel4 == 0xDEADBEEF) ? "[OK]" : "[FAILED]");
    
    // // 写入到Root队列区域
    // volatile unsigned int *root_test_ptr = (volatile unsigned int*)g_root_q_vaddr;
    // printf("[kernel] Writing 0xCAFEBABE to Root queue virtual address %p...\n", (void*)root_test_ptr);
    // root_test_ptr[0] = 0xCAFEBABE;
    
    // // 立即读回验证
    // unsigned int readback_root = root_test_ptr[0];
    // printf("[kernel] Root queue readback from kernel: 0x%x %s\n", readback_root,
    //        (readback_root == 0xCAFEBABE) ? "[OK]" : "[FAILED]");
    
    // 写入到数据区域
    // printf("[kernel] Writing test string to data region virtual address %p...\n", (void*)g_data_vaddr);
    // const char* test_pattern = "seL4_TEST_PATTERN_12345";
    // int pattern_len = 0;
    // while (test_pattern[pattern_len] != '\0' && pattern_len < 63) {
    //     pattern_len++;
    // }
    // for (int i = 0; i < pattern_len; i++) {
    //     g_data_vaddr[i] = test_pattern[i];
    // }
    // g_data_vaddr[pattern_len] = '\0';
    
    // // 读回验证
    // char readback_data[64];
    // for (int i = 0; i < pattern_len && i < 63; i++) {
    //     readback_data[i] = g_data_vaddr[i];
    // }
    // readback_data[pattern_len] = '\0';
    // printf("[kernel] Data region readback from kernel: '%.32s' %s\n", readback_data,
    //        (readback_data[0] == 's' && readback_data[1] == 'e') ? "[OK]" : "[FAILED]");
    
    // // !!!!! 关键诊断信息 !!!!!
    // printf("[kernel] *** IMPORTANT: Check if Root Linux can see these values: ***\n");
    // printf("[kernel] Root Linux should read from physical 0x%lx and see: 0xCAFEBABE\n", 
    //        (unsigned long)SHM_PADDR_ROOT_Q);
    // printf("[kernel] Root Linux should read from physical 0x%lx and see: 0xDEADBEEF\n", 
    //        (unsigned long)SHM_PADDR_SEL4_Q);
    // printf("[kernel] Root Linux should read from physical 0x%lx and see: '%s'\n", 
    //        (unsigned long)SHM_PADDR_DATA, test_pattern);
    
    // !!!!! CRITICAL: 强制缓存同步以解决缓存一致性问题 !!!!!
    // printf("[kernel] *** CRITICAL: Forcing cache synchronization for shared memory ***\n");
    
    // // ARM64缓存管理：强制将缓存数据写回主内存并使缓存无效
    // // 这确保seL4写入的数据能被Root Linux看到
    // printf("[kernel] Executing cache maintenance operations...\n");
    
    // // 使用内联汇编进行缓存管理
    // // DSB (Data Synchronization Barrier) - 确保所有数据操作完成
    // asm volatile("dsb sy" : : : "memory");
    // printf("[kernel] DSB (Data Synchronization Barrier) executed\n");
    
    // // ISB (Instruction Synchronization Barrier) - 确保指令流同步
    // asm volatile("isb" : : : "memory");
    // printf("[kernel] ISB (Instruction Synchronization Barrier) executed\n");
    
    // // 对于每个共享内存区域，执行缓存清理操作
    // printf("[kernel] Cleaning cache lines for shared memory regions...\n");
    
    // // 清理数据区域的缓存 (4MB)
    // unsigned long data_start = (unsigned long)g_data_vaddr;
    // unsigned long data_end = data_start + SHM_SIZE_DATA;
    // printf("[kernel] Cleaning data region cache: 0x%lx - 0x%lx\n", data_start, data_end);
    
    // // 按缓存行大小（通常64字节）清理
    // for (unsigned long addr = data_start; addr < data_end; addr += 64) {
    //     asm volatile("dc civac, %0" : : "r" (addr) : "memory");
    // }
    
    // // 清理Root队列区域的缓存 (4KB)
    // unsigned long root_q_start = (unsigned long)g_root_q_vaddr;
    // unsigned long root_q_end = root_q_start + SHM_PAGE_SIZE;
    // printf("[kernel] Cleaning root queue cache: 0x%lx - 0x%lx\n", root_q_start, root_q_end);
    
    // for (unsigned long addr = root_q_start; addr < root_q_end; addr += 64) {
    //     asm volatile("dc civac, %0" : : "r" (addr) : "memory");
    // }
    
    // // 清理seL4队列区域的缓存 (4KB)
    // unsigned long sel4_q_start = (unsigned long)g_sel4_q_vaddr;
    // unsigned long sel4_q_end = sel4_q_start + SHM_PAGE_SIZE;
    // printf("[kernel] Cleaning seL4 queue cache: 0x%lx - 0x%lx\n", sel4_q_start, sel4_q_end);
    
    // for (unsigned long addr = sel4_q_start; addr < sel4_q_end; addr += 64) {
    //     asm volatile("dc civac, %0" : : "r" (addr) : "memory");
    // }
    
    // // 最终的内存屏障确保所有缓存操作完成
    // asm volatile("dsb sy" : : : "memory");
    // asm volatile("isb" : : : "memory");
    
    // printf("[kernel] *** Cache synchronization completed ***\n");
    // printf("[kernel] *** All shared memory data should now be visible to Root Linux ***\n");
    
    // // 如果内核端读写都正常，但Root Linux读不到，说明虚拟地址没有正确映射到物理地址
    // if (readback_sel4 == 0xDEADBEEF && readback_root == 0xCAFEBABE) {
    //     printf("[kernel] *** CONCLUSION: Kernel virtual addresses work internally ***\n");
    //     printf("[kernel] *** If Root Linux still reads 0x0, then virtual mapping is WRONG ***\n");
    //     printf("[kernel] *** This means PPTR_BASE_OFFSET mapping doesn't reach hvisor shared memory ***\n");
    
    // // 继续初始化队列以便测试
    // printf("[kernel] *** Continuing with queue initialization for testing ***\n");
    
    // // 现在进行seL4队列的正式初始化
    // printf("[kernel] Initializing seL4 queue with expected values...\n");
    // g_sel4_q_vaddr->working_mark = INIT_MARK_INITIALIZED;  // 0xEEEEEEEE
    // g_sel4_q_vaddr->buf_size = 16;
    // g_sel4_q_vaddr->empty_h = 0;
    // g_sel4_q_vaddr->wait_h = 0;
    // g_sel4_q_vaddr->proc_ing_h = 0;
    
    // // 立即验证写入
    // printf("[kernel] Verification after seL4 queue initialization:\n");
    // printf("[kernel]   working_mark: 0x%x (expect 0xEEEEEEEE)\n", g_sel4_q_vaddr->working_mark);
    // printf("[kernel]   buf_size: %u (expect 16)\n", g_sel4_q_vaddr->buf_size);
    
    // // !!!!! 关键：强制缓存同步，确保working_mark写入对Root Linux可见 !!!!!
    // printf("[kernel] *** CRITICAL: Forcing cache sync for working_mark write ***\n");
    
    // // 对seL4队列区域执行缓存清理
    // unsigned long queue_addr = (unsigned long)g_sel4_q_vaddr;
    // printf("[kernel] Cleaning seL4 queue cache at 0x%lx for working_mark visibility\n", queue_addr);
    
    // // 清理整个队列结构的缓存行
    // for (unsigned long addr = queue_addr; addr < queue_addr + sizeof(struct AmpMsgQueue); addr += 64) {
    //     asm volatile("dc civac, %0" : : "r" (addr) : "memory");
    // }
    
    // // 确保缓存操作完成
    // asm volatile("dsb sy" : : : "memory");
    // asm volatile("isb" : : : "memory");
    
    // printf("[kernel] *** Cache sync completed for working_mark ***\n");
    
    // if (g_sel4_q_vaddr->working_mark == INIT_MARK_INITIALIZED) {
    //     printf("[kernel] *** seL4 queue initialization SUCCESS ***\n");
    //     printf("[kernel] *** ROOT LINUX SHOULD NOW READ 0xEEEEEEEE from physical 0x%lx ***\n", 
    //            (unsigned long)SHM_PADDR_SEL4_Q);
    //     printf("[kernel] *** CACHE SYNC ENSURES DATA IS IN MAIN MEMORY ***\n");
    // } else {
    //     printf("[kernel] *** seL4 queue initialization FAILED ***\n");
    // }
    
    // 初始化其他共享内存状态
    g_polling_enabled = 1;
    printf("[kernel] *** SHARED MEMORY COMMUNICATION READY ***\n");
    printf("[kernel] *** CRITICAL: Wait for Root Linux to detect seL4 working_mark = 0xEEEEEEEE ***\n");
// }
}

// 处理来自Root Linux的消息
static void process_root_linux_message(void)
{
    if (!g_root_q_vaddr || !g_data_vaddr) {
        return;
    }
    
    // 检查Root Linux队列是否有消息
    if (g_root_q_vaddr->proc_ing_h < g_root_q_vaddr->buf_size) {
        printf("\n[kernel] *** MESSAGE FROM ROOT LINUX DETECTED *** Processing message #%d\n", ++g_message_count);
        
        // 计算消息实体的起始地址
        volatile struct MsgEntry* msg_entries = (volatile struct MsgEntry*)((char*)g_root_q_vaddr + sizeof(struct AmpMsgQueue));
        volatile struct MsgEntry* msg_entry = &msg_entries[g_root_q_vaddr->proc_ing_h];
        volatile struct Msg* msg = &msg_entry->msg;
        
        printf("[kernel]   Service ID: %u\n", msg->service_id);
        printf("[kernel]   Offset: 0x%x\n", msg->offset);
        printf("[kernel]   Length: %u\n", msg->length);
        printf("[kernel]   Deal state: %u\n", msg->flag.deal_state);
        
        // 处理消息数据
        if (msg->length > 0 && msg->offset < SHM_SIZE_DATA) {
            volatile char* data_ptr = g_data_vaddr + msg->offset;
            
            printf("[kernel]   Reading data from offset 0x%x, length %u\n", msg->offset, msg->length);
            
            // 显示接收到的数据 (安全地)
            printf("[kernel]   *** DATA FROM ROOT LINUX: [");
            for (int i = 0; i < msg->length && i < 32; i++) {
                char c = data_ptr[i];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf("\\x%02x", (unsigned char)c);
                }
            }
            if (msg->length > 32) printf("...");
            printf("] *** \n");
            
            // 处理不同的服务
            int service_result = MSG_SERVICE_RET_SUCCESS;
            int data_modified = 0;
            
            switch (msg->service_id) {
                case 1:  // 加密服务
                    printf("[kernel]   [HyperAMP] Executing ENCRYPTION service\n");
                    if (hyperamp_encrypt_service((char*)data_ptr, msg->length, SHM_SIZE_DATA - msg->offset) == 0) {
                        printf("[kernel]   [HyperAMP] Encryption completed successfully\n");
                        data_modified = 1;
                    } else {
                        printf("[kernel]   [HyperAMP] Encryption failed\n");
                        service_result = MSG_SERVICE_RET_FAIL;
                    }
                    break;
                    
                case 2:  // 解密服务
                    printf("[kernel]   [HyperAMP] Executing DECRYPTION service\n");
                    if (hyperamp_decrypt_service((char*)data_ptr, msg->length, SHM_SIZE_DATA - msg->offset) == 0) {
                        printf("[kernel]   [HyperAMP] Decryption completed successfully\n");
                        data_modified = 1;
                    } else {
                        printf("[kernel]   [HyperAMP] Decryption failed\n");
                        service_result = MSG_SERVICE_RET_FAIL;
                    }
                    break;
                    
                case 66:  // 测试服务 (Echo)
                    printf("[kernel]   [HyperAMP] Executing ECHO test service\n");
                    break;
                    
                default:
                    printf("[kernel]   [HyperAMP] Unknown service ID: %u, treating as echo\n", msg->service_id);
                    break;
            }
            
            // 如果数据被修改，显示处理后的结果
            if (data_modified) {
                printf("[kernel]   *** PROCESSED DATA: [");
                for (int i = 0; i < msg->length && i < 32; i++) {
                    char c = data_ptr[i];
                    if (c >= 32 && c <= 126) {
                        printf("%c", c);
                    } else {
                        printf("\\x%02x", (unsigned char)c);
                    }
                }
                if (msg->length > 32) printf("...");
                printf("] *** \n");
            }
            
            // 标记消息已处理
            msg->flag.deal_state = MSG_DEAL_STATE_YES;
            msg->flag.service_result = service_result;
            
            printf("[kernel]   Message marked as processed\n");
        } else {
            printf("[kernel]   Invalid message (length=%u, offset=0x%x)\n", msg->length, msg->offset);
            msg->flag.deal_state = MSG_DEAL_STATE_YES;
            msg->flag.service_result = MSG_SERVICE_RET_FAIL;
        }
        
        // 更新队列头
        unsigned short old_head = g_root_q_vaddr->proc_ing_h;
        unsigned short new_head = msg_entry->nxt_idx;
        g_root_q_vaddr->proc_ing_h = new_head;
        msg_entry->nxt_idx = g_root_q_vaddr->buf_size; // 标记为无效
        
        // 重置工作状态，允许下一次通信
        g_root_q_vaddr->working_mark = MSG_QUEUE_MARK_IDLE;
        
        printf("[kernel]   Updated Root Linux proc_ing_h: %u -> %u\n", old_head, new_head);
        printf("[kernel]   Reset working_mark to IDLE (0x%x)\n", MSG_QUEUE_MARK_IDLE);
        printf("[kernel]   *** HYPERAMP SERVICE COMPLETED! ***\n");
    }
}

// 轮询检查共享内存消息 (定期调用)
void poll_shared_memory_messages(void)
{
    if (!g_polling_enabled) {
        return;
    }
    
    // 检查并处理来自Root Linux的消息
    process_root_linux_message();
}

// 获取共享内存状态 (供内核其他模块调用)
void get_shared_memory_status(void)
{
    if (!g_root_q_vaddr || !g_sel4_q_vaddr) {
        printf("[kernel] Shared memory not initialized\n");
        return;
    }
    
    printf("[kernel] === Shared Memory Status ===\n");
    printf("[kernel] Root Linux queue:\n");
    printf("[kernel]   working_mark = 0x%x\n", g_root_q_vaddr->working_mark);
    printf("[kernel]   buf_size = %u\n", g_root_q_vaddr->buf_size);
    printf("[kernel]   empty_h = %u\n", g_root_q_vaddr->empty_h);
    printf("[kernel]   wait_h = %u\n", g_root_q_vaddr->wait_h);
    printf("[kernel]   proc_ing_h = %u\n", g_root_q_vaddr->proc_ing_h);
    
    printf("[kernel] seL4 queue:\n");
    printf("[kernel]   working_mark = 0x%x\n", g_sel4_q_vaddr->working_mark);
    printf("[kernel]   buf_size = %u\n", g_sel4_q_vaddr->buf_size);
    printf("[kernel]   empty_h = %u\n", g_sel4_q_vaddr->empty_h);
    printf("[kernel]   wait_h = %u\n", g_sel4_q_vaddr->wait_h);
    printf("[kernel]   proc_ing_h = %u\n", g_sel4_q_vaddr->proc_ing_h);
    
    // 显示数据区的前64字节
    printf("[kernel] Data region content: '%.64s'\n", (const char*)g_data_vaddr);
    
    printf("[kernel] Polling enabled: %s\n", g_polling_enabled ? "YES" : "NO");
    printf("[kernel] Messages processed: %d\n", g_message_count);
}

// 连续监控共享内存消息 (无限循环模式)
// void hyperamp_server_continuous_mode(void)
// {
//     printf("[kernel] Starting HyperAMP server in continuous mode\n");
//     g_server_running = 1;  // 确保服务器保持运行
//     hyperamp_server_main_loop(0);  // 参数被忽略，函数内部使用无限循环
// }

// 简单的消息收发测试 (供内核模块调用)
void test_shared_memory_communication(void)
{
    if (!g_data_vaddr || !g_sel4_q_vaddr) {
        printf("[kernel] Shared memory not available for testing\n");
        return;
    }
    
    printf("[kernel] Testing shared memory communication...\n");
    
    // 向Root Linux发送测试消息
    const char *test_msg = "Hello from seL4 kernel!";
    int msg_len = 0;
    // 手动计算字符串长度
    while (test_msg[msg_len] != '\0' && msg_len < 63) {
        msg_len++;
    }
    
    // 写入数据区的偏移64字节处 (避免与现有数据冲突)
    for (int i = 0; i < msg_len; i++) {
        g_data_vaddr[64 + i] = test_msg[i];
    }
    g_data_vaddr[64 + msg_len] = '\0';
    
    printf("[kernel] Message sent to Root Linux: '%.32s'\n", test_msg);
    printf("[kernel] HyperAMP server will handle incoming messages\n");
    printf("[kernel] Shared memory communication test complete\n");
}
