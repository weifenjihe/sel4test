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

void printString(char* str)
{
    size_t max_len = 1024;/* 为安全起见，可以限制最大读长度，避免读到非法内存 */
    size_t i = 0;
    putchar('"');
    while (i < max_len) {
        char c = str[i];
        if (c == '\0') 
        {
            break;
        }
        putchar(c);
        i++;
    }
    putchar('"');
    putchar('\n');
}

int main(void) {
    printf("----------------ROOTSERVER--------------------\n");
    seL4_Word* Ptr2ShmemCommBuff= (seL4_Word*)seL4_GetIPCBuffer();
    unsigned long long *vaddrs=(unsigned long long *)*Ptr2ShmemCommBuff;
    
    // 打印三个共享内存区域的虚拟地址
    printf("Shmem Comm VAddrs:\n");
    printf("  DATA VADDR: 0x%llx\n", vaddrs[0]);
    printf("  ROOT_Q VADDR: 0x%llx\n", vaddrs[1]);
    printf("  SEL4_Q VADDR: 0x%llx\n", vaddrs[2]);
    printf("--------------------------------------------\n");
    printString((char*)(0x53f000));
    while (1)
    {
        /* code */
    }
    
    for (size_t i = 0; i < 3; i++)
    {
        printString((char*)(vaddrs[i]));
    }
    while (1)
    {
        /* infinite loop */
    }
    return 0;
}