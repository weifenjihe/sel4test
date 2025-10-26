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
                
                // 智能显示：如果是可打印字符，直接显示；否则显示十六进制
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
                
                // 处理服务请求
                int service_result = MSG_SERVICE_RET_SUCCESS;
                int data_modified = 0;
                
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
                        
                    case 66:  // 测试服务
                        printf("[kernel]   [HyperAMP] Echo test service\n");
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
