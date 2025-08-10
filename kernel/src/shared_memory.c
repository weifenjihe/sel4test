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

// 共享内存物理地址定义 (与hvisor配置一致)
#define SHM_PADDR_DATA      0xDE000000UL
#define SHM_SIZE_DATA       0x00400000UL  /* 4MB */
#define SHM_PADDR_ROOT_Q    0xDE400000UL  /* Root Linux队列 */
#define SHM_PADDR_SEL4_Q    0xDE410000UL  /* seL4队列 */
#define SHM_PAGE_SIZE       0x1000UL

// 消息队列初始化标记
#define INIT_MARK_INITIALIZED  (0xEEEEEEEEU)
#define MSG_QUEUE_MARK_IDLE    (0xBBBBBBBBU)

// 消息处理状态
#define MSG_DEAL_STATE_NO      (0)
#define MSG_DEAL_STATE_YES     (1)

// 服务处理结果
#define MSG_SERVICE_RET_SUCCESS (0)
#define MSG_SERVICE_RET_FAIL    (1)

// AMP消息队列结构
struct AmpMsgQueue {
    unsigned int working_mark;
    unsigned short buf_size;
    unsigned short empty_h;
    unsigned short wait_h;
    unsigned short proc_ing_h;
};

// 消息标志结构
struct MsgFlag {
    unsigned char deal_state;    // 处理状态
    unsigned char service_result; // 服务结果
};

// 消息结构
struct Msg {
    unsigned int service_id;     // 服务ID
    unsigned int offset;         // 数据在共享缓冲区中的偏移
    unsigned int length;         // 数据长度
    struct MsgFlag flag;         // 消息标志
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
        
        printf("[kernel] Root Linux queue initialized by seL4 kernel\n");
    }
    
    printf("[kernel] After init - Root Linux queue status:\n");
    printf("[kernel]   working_mark: 0x%x\n", g_root_q_vaddr->working_mark);
    printf("[kernel]   buf_size: %u\n", g_root_q_vaddr->buf_size);
    printf("[kernel]   empty_h: %u, wait_h: %u, proc_ing_h: %u\n", 
           g_root_q_vaddr->empty_h, g_root_q_vaddr->wait_h, g_root_q_vaddr->proc_ing_h);
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
    printf("[kernel] Max messages to process: %d\n", max_messages);
    printf("[kernel] Polling interval: %dms\n", g_wait_timeout_ms);
    
    g_server_running = 1;
    g_message_count = 0;
    g_check_counter = 0;
    
    // 帮助Root Linux初始化队列
    init_root_linux_queue();
    
    // 测试共享缓冲区访问
    printf("[kernel] Testing shared buffer access...\n");
    if (g_data_vaddr != NULL) {
        // 读取第一个字节测试
        volatile char first_byte = g_data_vaddr[0];
        printf("[kernel] First byte read successful: 0x%02x\n", first_byte);
        
        // 写入测试数据
        const char* server_ready_msg = "seL4 HyperAMP Server Ready";
        int msg_len = 0;
        while (server_ready_msg[msg_len] != '\0' && msg_len < 63) {
            msg_len++;
        }
        for (int i = 0; i < msg_len; i++) {
            g_data_vaddr[i] = server_ready_msg[i];
        }
        g_data_vaddr[msg_len] = '\0';
        
        printf("[kernel] Server ready message written to shared buffer\n");
    }
    
    // 计算消息实体数组的起始地址
    volatile struct MsgEntry* root_msg_entries = (volatile struct MsgEntry*)((char*)g_root_q_vaddr + sizeof(struct AmpMsgQueue));
    printf("[kernel] Root message entries start at: %p\n", (void*)root_msg_entries);
    
    // 主消息处理循环
    while (g_server_running && g_message_count < max_messages) {
        int found_message = 0;
        
        // 检查Root Linux队列中的消息
        if (g_root_q_vaddr->proc_ing_h < g_root_q_vaddr->buf_size) {
            printf("\n[kernel] *** PROCESSING MESSAGE FROM ROOT LINUX *** Message #%d\n", ++g_message_count);
            found_message = 1;
            
            // 获取当前消息
            unsigned short head = g_root_q_vaddr->proc_ing_h;
            volatile struct MsgEntry* msg_entry = &root_msg_entries[head];
            volatile struct Msg* msg = &msg_entry->msg;
            
            printf("[kernel]   Message Index: %u\n", head);
            printf("[kernel]   Service ID: %u\n", msg->service_id);
            printf("[kernel]   Offset: 0x%x\n", msg->offset);
            printf("[kernel]   Length: %u\n", msg->length);
            printf("[kernel]   Deal state: %u\n", msg->flag.deal_state);
            
            // 处理消息数据
            if (msg->length > 0 && msg->offset < SHM_SIZE_DATA) {
                volatile char* data_ptr = g_data_vaddr + msg->offset;
                
                printf("[kernel]   Reading data from offset 0x%x, length %u\n", msg->offset, msg->length);
                
                // 安全地显示接收到的数据
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
                
                // 处理不同的HyperAMP服务
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
            printf("[kernel]   Root Linux should now detect completion and read processed data\n");
        }
        
        // 如果没有找到消息，定期显示等待状态
        if (!found_message) {
            g_check_counter++;
            if (g_check_counter % 50 == 0) {  // 每5秒显示一次状态
                printf("[kernel] Waiting... (Check #%d, Root queue proc_ing_h=%u, buf_size=%u)\n", 
                       g_check_counter, g_root_q_vaddr->proc_ing_h, g_root_q_vaddr->buf_size);
            }
        }
        
        // 简单的延时机制 (在内核中我们使用循环代替sleep)
        for (volatile int i = 0; i < 100000; i++) {
            // 空循环实现延时，约100ms
        }
    }
    
    g_server_running = 0;
    printf("\n[kernel] === HyperAMP Message Server Stopped ===\n");
    printf("[kernel] Total messages processed: %d\n", g_message_count);
    printf("[kernel] Total polling checks: %d\n", g_check_counter);
}

// 初始化共享内存映射 (内核启动时调用)
void init_shared_memory_kernel(void)
{
    printf("[kernel] Initializing shared memory communication\n");
    
    // 在ARM64系统中，直接使用物理地址加上内核偏移
    g_data_vaddr = (volatile char*)(SHM_PADDR_DATA + PPTR_BASE_OFFSET);
    g_root_q_vaddr = (volatile struct AmpMsgQueue*)(SHM_PADDR_ROOT_Q + PPTR_BASE_OFFSET);
    g_sel4_q_vaddr = (volatile struct AmpMsgQueue*)(SHM_PADDR_SEL4_Q + PPTR_BASE_OFFSET);
    
    printf("[kernel] Physical to kernel virtual mapping:\n");
    printf("[kernel]   Data: 0x%lx -> %p\n", (unsigned long)SHM_PADDR_DATA, (void*)g_data_vaddr);
    printf("[kernel]   Root Queue: 0x%lx -> %p\n", (unsigned long)SHM_PADDR_ROOT_Q, (void*)g_root_q_vaddr);
    printf("[kernel]   seL4 Queue: 0x%lx -> %p\n", (unsigned long)SHM_PADDR_SEL4_Q, (void*)g_sel4_q_vaddr);
    
    // 验证地址映射关系
    printf("[kernel] Address mapping verification:\n");
    printf("[kernel]   PPTR_BASE_OFFSET = 0x%lx\n", (unsigned long)PPTR_BASE_OFFSET);
    printf("[kernel]   Physical 0x%lx + Offset 0x%lx = Virtual %p\n", 
           (unsigned long)SHM_PADDR_DATA, (unsigned long)PPTR_BASE_OFFSET, (void*)g_data_vaddr);
    printf("[kernel] Root Linux writes to PHYSICAL 0x%lx, seL4 reads from VIRTUAL %p\n",
           (unsigned long)SHM_PADDR_DATA, (void*)g_data_vaddr);
    printf("[kernel] Both addresses point to THE SAME physical memory!\n");
    
    if (g_data_vaddr && g_root_q_vaddr && g_sel4_q_vaddr) {
        printf("[kernel] Shared memory mapped successfully\n");
               
        // 初始化seL4队列
        g_sel4_q_vaddr->working_mark = INIT_MARK_INITIALIZED;
        g_sel4_q_vaddr->buf_size = 16;
        g_sel4_q_vaddr->empty_h = 0;
        g_sel4_q_vaddr->wait_h = 0;
        g_sel4_q_vaddr->proc_ing_h = 0;
        
        // 在数据区写入测试消息
        const char *test_msg = "seL4 kernel shared memory initialized!";
        int msg_len = 0;
        // 手动计算字符串长度，避免使用strlen
        while (test_msg[msg_len] != '\0' && msg_len < 63) {
            msg_len++;
        }
        
        for (int i = 0; i < msg_len; i++) {
            g_data_vaddr[i] = test_msg[i];
        }
        g_data_vaddr[msg_len] = '\0';
        
        printf("[kernel] Test message written: '%.32s'\n", (const char*)g_data_vaddr);
        printf("[kernel] seL4 queue initialized with mark=0x%x\n", g_sel4_q_vaddr->working_mark);
        
        // 启用轮询功能
        g_polling_enabled = 1;
        printf("[kernel] Polling for Root Linux messages enabled\n");
        printf("[kernel] Shared memory communication ready!\n");
    } else {
        printf("[kernel] Failed to map shared memory regions\n");
    }
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
