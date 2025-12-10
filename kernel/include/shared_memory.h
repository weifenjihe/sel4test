/*
 * Copyright 2024, seL4 Project
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <types.h>
#include <api/failures.h>

// 共享内存物理地址定义 4KB 队列
// 与 Linux 端布局匹配 (统一使用 4KB 对齐)
#define SHM_TX_QUEUE_PADDR  0xDE000000UL  /* TX Queue: Linux → seL4, 4KB */
#define SHM_RX_QUEUE_PADDR  0xDE001000UL  /* RX Queue: seL4 → Linux, 4KB (4KB aligned) */
#define SHM_DATA_PADDR      0xDE002000UL  /* Data Region, 4MB (8KB offset) */

#define SHM_QUEUE_SIZE      (4 * 1024)    /* 4KB per queue (1 page, actual: ~4068 bytes) */
#define SHM_DATA_SIZE       (4 * 1024 * 1024)  /* 4MB */

// 虚拟地址定义
#define SHM_TX_QUEUE_VADDR  (SHM_TX_QUEUE_PADDR + PPTR_BASE_OFFSET)
#define SHM_RX_QUEUE_VADDR  (SHM_RX_QUEUE_PADDR + PPTR_BASE_OFFSET)
#define SHM_DATA_VADDR      (SHM_DATA_PADDR + PPTR_BASE_OFFSET)
// 初始化共享内存 (内核启动时调用)
void init_shared_memory_kernel(void);

// 获取共享内存状态 (供内核其他模块调用)
void get_shared_memory_status(void);

// 简单的消息收发测试 (供内核模块调用)
void test_shared_memory_communication(void);

// 轮询检查共享内存消息 (定期调用)
void poll_shared_memory_messages(void);

// 内核级HyperAMP消息服务器主循环
void hyperamp_server_main_loop(int max_messages);