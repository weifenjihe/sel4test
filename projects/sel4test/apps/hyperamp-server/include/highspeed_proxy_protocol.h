/*
 * HighSpeedCProxy Protocol Definitions
 * 
 * 定义网络代理场景中的真实数据结构
 * 用于 SESSION 和 DATA 消息的载荷格式
 * 
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef HIGHSPEED_PROXY_PROTOCOL_H
#define HIGHSPEED_PROXY_PROTOCOL_H

#include <stdint.h>

/* ==================== 协议常量 ==================== */

#define PROXY_PROTO_TCP     6
#define PROXY_PROTO_UDP     17

#define PROXY_STATE_SYN_SENT    1
#define PROXY_STATE_ESTABLISHED 2
#define PROXY_STATE_FIN_WAIT    3
#define PROXY_STATE_CLOSED      4

/* ==================== SESSION 消息载荷 ==================== */

/**
 * @brief SESSION 消息：创建新连接
 */
typedef struct {
    uint8_t  protocol;      // 6=TCP, 17=UDP
    uint8_t  state;         // 1=SYN_SENT, 2=ESTABLISHED, 3=FIN_WAIT, 4=CLOSED
    uint16_t src_port;      // 源端口 (主机字节序)
    uint32_t src_ip;        // 源IP (网络字节序)
    uint16_t dst_port;      // 目标端口 (主机字节序)
    uint16_t reserved;
    uint32_t dst_ip;        // 目标IP (网络字节序)
} __attribute__((packed)) SessionCreatePayload;

/**
 * @brief SESSION 消息：连接状态更新
 */
typedef struct {
    uint8_t  old_state;
    uint8_t  new_state;
    uint16_t reserved;
} __attribute__((packed)) SessionStatePayload;

/* ==================== DATA 消息载荷 ==================== */

/**
 * @brief DATA 消息：HTTP 请求头 (简化版)
 */
typedef struct {
    char method[8];         // "GET", "POST", "PUT", etc.
    char uri[256];          // "/index.html", "/api/data", etc.
    char host[128];         // "www.example.com"
    uint16_t content_length;
    uint16_t reserved;
    // 后面跟随实际的 HTTP body (如果有)
} __attribute__((packed)) HttpRequestHeader;

/**
 * @brief DATA 消息：HTTP 响应头 (简化版)
 */
typedef struct {
    uint16_t status_code;   // 200, 404, 500, etc.
    uint16_t content_length;
    char content_type[64];  // "text/html", "application/json", etc.
} __attribute__((packed)) HttpResponseHeader;

/* ==================== 辅助函数：IP 地址转换 ==================== */

/**
 * @brief 将 32 位 IP 转为点分十进制字符串
 * @param ip_net IP 地址（网络字节序）
 * @param buf 输出缓冲区（至少 16 字节）
 */
static inline void ip_to_str(uint32_t ip_net, char *buf)
{
    uint8_t *bytes = (uint8_t *)&ip_net;
    // 网络字节序是大端，直接按字节读取
    sprintf(buf, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/**
 * @brief 将点分十进制字符串转为 32 位 IP（网络字节序）
 * @param str "192.168.1.100"
 * @return 网络字节序的 IP
 */
static inline uint32_t str_to_ip(const char *str)
{
    unsigned int a, b, c, d;
    sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d);
    uint32_t ip = (a << 0) | (b << 8) | (c << 16) | (d << 24);
    return ip;  // 已经是网络字节序
}

/* ==================== 协议版本检查 ==================== */

#define PROXY_PROTOCOL_VERSION  1

#endif /* HIGHSPEED_PROXY_PROTOCOL_H */
