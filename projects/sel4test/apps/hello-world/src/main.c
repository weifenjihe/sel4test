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
    sel4muslcsys_register_stdio_write_fn(write_buf);
    
    printf("=== seL4 User Application ===\n");
    printf("User application running successfully!\n");
    return 0;
}