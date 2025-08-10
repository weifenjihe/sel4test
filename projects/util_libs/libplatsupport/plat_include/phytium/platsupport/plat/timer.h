/*
 * Copyright 2025, seL4 Project
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <platsupport/timer.h>
#include <platsupport/ltimer.h>

// Phytium Pi timer configuration (based on PE2204 official DTS)
#define ARM_GENERIC_TIMER_FREQ  (50000000)  // 50MHz (0x2faf080 from DTS)
#define TIMER_FREQUENCY         ARM_GENERIC_TIMER_FREQ

/* Simple timer properties for basic functionality */
static UNUSED timer_properties_t phytium_timer_properties = {
    .upcounter = true,
    .timeouts = true,
    .relative_timeouts = true,
    .periodic_timeouts = true,
    .bit_width = 64,
    .irqs = 0  /* No IRQs for simple implementation */
};

// System timer definitions
typedef struct phytium_timer {
    void* vaddr;
    uint32_t freq;
} phytium_timer_t;

// Timer functions - HVISOR SAFE VERSION
static inline uint64_t phytium_get_time(phytium_timer_t *timer)
{
    // Use ARM generic timer virtual counter (safe to read in hypervisor)
    uint64_t time;
    asm volatile("mrs %0, cntvct_el0" : "=r" (time));
    return time;
}

static inline void phytium_init_timer(phytium_timer_t *timer)
{
    timer->freq = TIMER_FREQUENCY;
    // Skip timer control register access - causes capability fault in hvisor
    // NOTE: Timer should still function for reading time without control access
}
