/*
 * Copyright 2024, seL4 Project
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <types.h>
#include <api/failures.h>

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