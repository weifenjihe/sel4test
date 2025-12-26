/**
 * @file highspeed_proxy_frontend_sim.h
 * @brief 前端协议栈模拟器 - 用于 seL4 端测试
 * 
 * 功能：
 * 1. 模拟应用程序发起 TCP 连接请求
 * 2. 生成 SESSION 消息发送到 TX Queue
 * 3. 生成 HTTP GET/POST 请求发送到 TX Queue
 * 4. 从 RX Queue 接收后端响应
 * 
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef HIGHSPEED_PROXY_FRONTEND_SIM_H
#define HIGHSPEED_PROXY_FRONTEND_SIM_H

#include <stdint.h>
#include <string.h>
#include "shm/hyperamp_shm_queue.h"
#include "highspeed_proxy_protocol.h"

/* Zone ID 定义 */
#ifndef ZONE_ID_SEL4
#define ZONE_ID_SEL4    1
#endif

/* ==================== 前端协议栈模拟器 ==================== */

/**
 * @brief 前端协议栈上下文
 */
typedef struct {
    volatile HyperampShmQueue *tx_queue;  // seL4 → Linux
    volatile HyperampShmQueue *rx_queue;  // Linux → seL4
    uint16_t next_session_id;              // 下一个会话 ID
    uint32_t messages_sent;
    uint32_t responses_received;
} FrontendProxyContext;

/**
 * @brief 初始化前端协议栈
 */
static inline void frontend_proxy_init(FrontendProxyContext *ctx,
                                        volatile HyperampShmQueue *tx_queue,
                                        volatile HyperampShmQueue *rx_queue)
{
    ctx->tx_queue = tx_queue;
    ctx->rx_queue = rx_queue;
    ctx->next_session_id = 1000;  // 前端会话 ID 从 1000 开始
    ctx->messages_sent = 0;
    ctx->responses_received = 0;
}

/**
 * @brief 构造并发送代理协议消息到发送队列 (seL4 -> Linux)
 * @param ctx 输入：前端代理上下文（包含发送队列指针）
 * @param msg_type 输入：消息类型（如 HYPERAMP_MSG_TYPE_SESS 或 HYPERAMP_MSG_TYPE_DATA）
 * @param frontend_sess 输入：前端会话 ID（源端会话标识）
 * @param backend_sess 输入：后端会话 ID（目的端会话标识）
 * @param payload 输入：消息载荷数据的指针（如果无载荷可传 NULL）
 * @param payload_len 输入：消息载荷的长度
 * @return HYPERAMP_OK 成功, HYPERAMP_ERROR 失败（队列满、参数错误或数据过长）
 */
static inline int frontend_send_message(FrontendProxyContext *ctx,
                                         uint8_t msg_type,
                                         uint16_t frontend_sess,
                                         uint16_t backend_sess,
                                         const void *payload,
                                         uint16_t payload_len)
{
    // 准备完整消息
    char msg_buf[4096];
    HyperampMsgHeader *hdr = (HyperampMsgHeader *)msg_buf;
    
    hdr->version = 1;
    hdr->proxy_msg_type = msg_type;
    hdr->frontend_sess_id = frontend_sess;
    hdr->backend_sess_id = backend_sess;
    hdr->payload_len = payload_len;
    
    // 复制载荷
    if (payload && payload_len > 0) {
        hyperamp_safe_memcpy(msg_buf + sizeof(HyperampMsgHeader), 
                            payload, payload_len);
    }
    
    size_t total_len = sizeof(HyperampMsgHeader) + payload_len;
    
    // 数据区是独立的共享内存区域 (0xDE002000)
    extern volatile void *g_data_region;
    volatile void *tx_data_base = g_data_region;
    // printf("debug: frontend_send_message:TX Queue(ctx->tx_queue):%p,tx_data_base=%p\n", ctx->tx_queue, tx_data_base);
    //tx_queue: 0xde000000
    int ret = hyperamp_queue_enqueue(ctx->tx_queue, ZONE_ID_SEL4,
                                     msg_buf, total_len, tx_data_base);
    
    if (ret == HYPERAMP_OK) {
        ctx->messages_sent++;
    }
    
    return ret;
}

/**
 * @brief 发送建立 TCP 连接的请求消息 (模拟 TCP 握手的第一步)
 * @param ctx 输入：前端代理上下文（维护会话 ID 和发送队列）
 * @param dst_ip_str 输入：目标服务器的 IP 地址字符串 (例如 "192.168.1.1")
 * @param dst_port 输入：目标服务器的端口号
 * @return 成功返回分配的 frontend_sess_id (>=0)，失败返回 -1
 */
static inline int frontend_tcp_connect(FrontendProxyContext *ctx,
                                        const char *dst_ip_str,
                                        uint16_t dst_port)
{
    printf("[Frontend] Creating TCP connection to %s:%u\n", dst_ip_str, dst_port);
    
    SessionCreatePayload sess = {
        .protocol = PROXY_PROTO_TCP,
        .state = PROXY_STATE_SYN_SENT,
        .src_ip = str_to_ip("192.168.1.100"),  // seL4 端模拟 IP
        .src_port = 50000 + ctx->next_session_id,
        .dst_ip = str_to_ip(dst_ip_str),
        .dst_port = dst_port,
        .reserved = 0
    };
    
    uint16_t frontend_sess = ctx->next_session_id++;
    
    int ret = frontend_send_message(ctx, HYPERAMP_MSG_TYPE_SESS,
                                    frontend_sess, 0,
                                    &sess, sizeof(sess));
    
    if (ret == HYPERAMP_OK) {
        printf("[Frontend] ✓ SESSION message sent (frontend_sess=%u)\n", frontend_sess);
        return frontend_sess;  // 返回会话 ID
    } else {
        printf("[Frontend] ✗ Failed to send SESSION message\n");
        return -1;
    }
}

/**
 * @brief 发送 HTTP GET 请求消息
 * @param ctx 输入：前端代理上下文
 * @param frontend_sess 输入：前端会话 ID（由 frontend_tcp_connect 返回）
 * @param backend_sess 输入：后端会话 ID（由后端响应消息中获取，首次请求通常填 0 或由后端分配）
 * @param host 输入：目标主机名 (例如 "www.example.com")
 * @param uri 输入：请求的资源路径 (例如 "/index.html")
 * @return HYPERAMP_OK 成功, HYPERAMP_ERROR 失败
 */
static inline int frontend_http_get(FrontendProxyContext *ctx,
                                     uint16_t frontend_sess,
                                     uint16_t backend_sess,
                                     const char *host,
                                     const char *uri)
{
    printf("[Frontend] Sending HTTP GET: %s%s\n", host, uri);
    
    HttpRequestHeader http = {0};
    strncpy(http.method, "GET", sizeof(http.method));
    strncpy(http.uri, uri, sizeof(http.uri));
    strncpy(http.host, host, sizeof(http.host));
    http.content_length = 0;
    
    int ret = frontend_send_message(ctx, HYPERAMP_MSG_TYPE_DATA,
                                    frontend_sess, backend_sess,
                                    &http, sizeof(http));
    
    if (ret == HYPERAMP_OK) {
        printf("[Frontend] ✓ HTTP GET sent\n");
    } else {
        printf("[Frontend] ✗ Failed to send HTTP GET\n");
    }
    
    return ret;
}

/**
 * @brief 发送 HTTP POST 请求消息（包含消息体）
 * @param ctx 输入：前端代理上下文
 * @param frontend_sess 输入：前端会话 ID
 * @param backend_sess 输入：后端会话 ID
 * @param host 输入：目标主机名
 * @param uri 输入：请求资源路径
 * @param body 输入：POST 请求体内容 (例如 JSON 字符串)
 * @return HYPERAMP_OK 成功, HYPERAMP_ERROR 失败
 */
static inline int frontend_http_post(FrontendProxyContext *ctx,
                                      uint16_t frontend_sess,
                                      uint16_t backend_sess,
                                      const char *host,
                                      const char *uri,
                                      const char *body)
{
    printf("[Frontend] Sending HTTP POST: %s%s\n", host, uri);
    printf("[Frontend]   Body: %s\n", body);
    
    char full_req[512];
    HttpRequestHeader *http = (HttpRequestHeader *)full_req;
    
    strncpy(http->method, "POST", sizeof(http->method));
    strncpy(http->uri, uri, sizeof(http->uri));
    strncpy(http->host, host, sizeof(http->host));
    http->content_length = strlen(body);
    
    size_t header_size = sizeof(HttpRequestHeader);
    memcpy(full_req + header_size, body, strlen(body));
    size_t total_size = header_size + strlen(body);
    
    int ret = frontend_send_message(ctx, HYPERAMP_MSG_TYPE_DATA,
                                    frontend_sess, backend_sess,
                                    full_req, total_size);
    
    if (ret == HYPERAMP_OK) {
        printf("[Frontend] ✓ HTTP POST sent\n");
    } else {
        printf("[Frontend] ✗ Failed to send HTTP POST\n");
    }
    
    return ret;
}

/**
 * @brief 接收来自后端的响应消息 (Linux -> seL4)
 * @param ctx 输入：前端代理上下文（包含接收队列指针和统计信息）
 * @param out_hdr 输出：用于存储解析后的消息头
 * @param out_payload 输出：用户缓冲区，用于存储消息载荷
 * @param max_payload_len 输入：用户缓冲区的最大容量（防止溢出）
 * @param actual_len 输出：实际复制的载荷字节数（如果不关心可传 NULL）
 * @return HYPERAMP_OK 成功, HYPERAMP_ERROR 失败（队列为空、消息长度非法等）
 */
static inline int frontend_receive_response(FrontendProxyContext *ctx,
                                             HyperampMsgHeader *out_hdr,
                                             void *out_payload,
                                             size_t max_payload_len,
                                             size_t *actual_len)
{
    char msg_buf[4096];
    size_t msg_len;
    
    // 数据区是独立的共享内存区域 (0xDE002000)
    extern volatile void *g_data_region;
    volatile void *rx_data_base = g_data_region;
    
    int ret = hyperamp_queue_dequeue(ctx->rx_queue, ZONE_ID_SEL4,
                                     msg_buf, sizeof(msg_buf), &msg_len,
                                     rx_data_base);
    
    if (ret != HYPERAMP_OK) {
        return ret;  // 队列空
    }
    
    if (msg_len < sizeof(HyperampMsgHeader)) {
        printf("[Frontend] ERROR: Invalid response (too short)\n");
        return HYPERAMP_ERROR;
    }
    
    // 解析消息头
    HyperampMsgHeader *hdr = (HyperampMsgHeader *)msg_buf;
    if (out_hdr) {
        memcpy(out_hdr, hdr, sizeof(HyperampMsgHeader));
    }
    
    // 复制载荷
    size_t payload_len = hdr->payload_len;
    if (payload_len > max_payload_len) {
        payload_len = max_payload_len;
    }
    
    if (out_payload && payload_len > 0) {
        memcpy(out_payload, msg_buf + sizeof(HyperampMsgHeader), payload_len);
    }
    
    if (actual_len) {
        *actual_len = payload_len;
    }
    
    ctx->responses_received++;
    
    printf("[Frontend] ✓ Response received: type=%u, sess=%u/%u, len=%u\n",
           hdr->proxy_msg_type, hdr->frontend_sess_id, hdr->backend_sess_id,
           hdr->payload_len);
    
    return HYPERAMP_OK;
}

/**
 * @brief 运行完整的测试场景
 */
static inline void frontend_run_test_scenario(FrontendProxyContext *ctx)
{
    printf("\n[Frontend] ========== Starting Test Scenario ==========\n");
    
    // 场景 1: 建立 TCP 连接
    printf("\n[Frontend] --- Scenario 1: TCP Connect ---\n");
    int sess_id = frontend_tcp_connect(ctx, "8.8.8.8", 80);
    
    if (sess_id < 0) {
        printf("[Frontend] Test aborted due to connection failure\n");
        return;
    }
    
    // 等待 SESSION 响应 (后端应该返回 backend_sess_id)
    printf("[Frontend] Waiting for SESSION response...\n");
    for (int i = 0; i < 10; i++) {
        HyperampMsgHeader resp_hdr;
        char resp_payload[512];
        size_t resp_len;
        
        if (frontend_receive_response(ctx, &resp_hdr, resp_payload, sizeof(resp_payload), &resp_len) == HYPERAMP_OK) {
            if (resp_hdr.proxy_msg_type == HYPERAMP_MSG_TYPE_SESS) {
                uint16_t backend_sess = resp_hdr.backend_sess_id;
                printf("[Frontend] ✓ Connection established! backend_sess=%u\n", backend_sess);
                
                // 场景 2: 发送 HTTP GET 请求
                printf("\n[Frontend] --- Scenario 2: HTTP GET ---\n");
                frontend_http_get(ctx, sess_id, backend_sess, "www.example.com", "/index.html");
                
                // 等待 HTTP 响应
                printf("[Frontend] Waiting for HTTP response...\n");
                for (int j = 0; j < 10; j++) {
                    if (frontend_receive_response(ctx, &resp_hdr, resp_payload, sizeof(resp_payload), &resp_len) == HYPERAMP_OK) {
                        if (resp_hdr.proxy_msg_type == HYPERAMP_MSG_TYPE_DATA) {
                            resp_payload[resp_len < 511 ? resp_len : 511] = '\0';
                            printf("[Frontend] ✓ HTTP Response:\n");
                            printf("[Frontend]   %s\n", resp_payload);
                            break;
                        }
                    }
                    // 延迟
                    for (volatile int k = 0; k < 100000; k++);
                }
                
                break;
            }
        }
        
        // 延迟
        for (volatile int k = 0; k < 100000; k++);
    }
    
    printf("\n[Frontend] ========== Test Scenario Complete ==========\n");
    printf("[Frontend] Messages sent: %u\n", ctx->messages_sent);
    printf("[Frontend] Responses received: %u\n", ctx->responses_received);
}

#endif /* HIGHSPEED_PROXY_FRONTEND_SIM_H */
