/*
 * rk3588 serial platform definitions
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

/* Physical base addresses from rk3588.dts */
#define UART0_PADDR  0xFD890000
#define UART1_PADDR  0xFEB40000
#define UART2_PADDR  0xFEB50000
#define UART3_PADDR  0xFEB60000
#define UART4_PADDR  0xFEB70000
#define UART5_PADDR  0xFEB80000
#define UART6_PADDR  0xFEB90000
#define UART7_PADDR  0xFEBA0000
#define UART8_PADDR  0xFEBB0000
#define UART9_PADDR  0xFEBC0000

/* IRQ numbers derived from dtb (second cell): */
#define UART0_IRQ    331 /* 0x14b */
#define UART1_IRQ    332 /* 0x14c */
#define UART2_IRQ    333 /* 0x14d */
#define UART3_IRQ    334 /* 0x14e */
#define UART4_IRQ    335 /* 0x14f */
#define UART5_IRQ    336 /* 0x150 */
#define UART6_IRQ    337 /* 0x151 */
#define UART7_IRQ    338 /* 0x152 */
#define UART8_IRQ    339 /* 0x153 */
#define UART9_IRQ    340 /* 0x154 */

enum chardev_id {
    RP_UART0,
    RP_UART1,
    RP_UART2,
    RP_UART3,
    RP_UART4,
    RP_UART5,
    RP_UART6,
    RP_UART7,
    RP_UART8,
    RP_UART9,
    /* Aliases */
    PS_SERIAL0 = RP_UART0,
    PS_SERIAL1 = RP_UART1,
    PS_SERIAL2 = RP_UART2,
    PS_SERIAL3 = RP_UART3,
    PS_SERIAL4 = RP_UART4,
    PS_SERIAL5 = RP_UART5,
    PS_SERIAL6 = RP_UART6,
    PS_SERIAL7 = RP_UART7,
    PS_SERIAL8 = RP_UART8,
    PS_SERIAL9 = RP_UART9,
    /* defaults */
    PS_SERIAL_DEFAULT = RP_UART2
};

#define DEFAULT_SERIAL_PADDR UART2_PADDR
#define DEFAULT_SERIAL_INTERRUPT UART2_IRQ
