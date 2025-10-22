/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <autoconf.h>
#include <stdio.h>
#include <sel4/sel4.h>
#include <arch_stdio.h>

void __plat_putchar(int c);
static size_t write_buf(void *data, size_t count)
{
    char *buf = data;
    for (int i = 0; i < count; i++) {
        __plat_putchar(buf[i]);
    }
    return count;
}

int main(void)
{

     printf("----------------ROOTSERVER--------------------\n");
    seL4_Word* Ptr2ShmemCommBuff= (seL4_Word*)seL4_GetIPCBuffer();
    const char *ShmemCommBuff=(char *)*Ptr2ShmemCommBuff;
    printf("RootServer: Got ShmemComm Buffer:%lx\n",*Ptr2ShmemCommBuff); 
    printf("RootServer: Got kernel ShmemComm buffer msg:\n");
    // const char *ShmemCommBuff = (const char *)0x719d25;
    size_t max_len = 1024;/* 为安全起见，可以限制最大读长度，避免读到非法内存 */
    size_t i = 0;
    putchar('"');
    while (i < max_len) {
        char c = ShmemCommBuff[i];
        if (c == '\0') 
        {
            // printf("\0");
            break;
        }
        putchar(c);
        i++;
    }
    putchar('"');
    putchar('\n');
    // sel4muslcsys_register_stdio_write_fn(write_buf);
    
    // printf("=== seL4 User Application ===\n");
    // printf("User application running successfully!\n");
    return 0;
}