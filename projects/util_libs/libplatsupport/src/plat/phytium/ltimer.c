/*
 * Copyright 2025, seL4 Project
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
 * Logical timer implementation for Phytium Pi platform.
 * Uses ARM generic timer for basic timer functionality.
 */

#include <errno.h>
#include <platsupport/io.h>
#include <platsupport/ltimer.h>
#include <platsupport/arch/generic_timer.h>
#include <utils/util.h>

#include "../../ltimer.h"

typedef struct {
    generic_timer_t generic_timer;
    ps_io_ops_t ops;
    uint64_t timeout_time;
    bool timeout_set;
} phytium_ltimer_t;

static int get_time(void *data, uint64_t *time)
{
    assert(data != NULL);
    assert(time != NULL);

    phytium_ltimer_t *ltimer = data;
    *time = generic_timer_get_time(&ltimer->generic_timer);
    return 0;
}

static int set_timeout(void *data, uint64_t ns, timeout_type_t type)
{
    phytium_ltimer_t *ltimer = data;
    
    if (type == TIMEOUT_ABSOLUTE) {
        ltimer->timeout_time = ns;
    } else {
        uint64_t current_time = generic_timer_get_time(&ltimer->generic_timer);
        ltimer->timeout_time = current_time + ns;
    }
    
    ltimer->timeout_set = true;
    return 0;
}

static int get_resolution(void *data, uint64_t *resolution)
{
    phytium_ltimer_t *ltimer = data;
    /* Resolution is 1/frequency seconds in nanoseconds */
    *resolution = NS_IN_S / ltimer->generic_timer.freq;
    return 0;
}

static int reset(void *data)
{
    phytium_ltimer_t *ltimer = data;
    ltimer->timeout_set = false;
    ltimer->timeout_time = 0;
    return 0;
}

static void destroy(void *data)
{
    assert(data);
    phytium_ltimer_t *ltimer = data;
    ps_free(&ltimer->ops.malloc_ops, sizeof(*ltimer), ltimer);
}

int ltimer_default_init(ltimer_t *ltimer, ps_io_ops_t ops, ltimer_callback_fn_t callback, void *callback_token)
{
    int error;

    if (ltimer == NULL) {
        ZF_LOGE("ltimer cannot be NULL");
        return EINVAL;
    }

    error = create_ltimer_simple(
                ltimer, ops, sizeof(phytium_ltimer_t),
                get_time, set_timeout, reset, destroy
            );
    if (error) {
        ZF_LOGE("Failed to create ltimer for phytium");
        return error;
    }

    /* Set additional function pointers that create_ltimer_simple doesn't set */
    ltimer->get_resolution = get_resolution;

    phytium_ltimer_t *phytium_ltimer = ltimer->data;
    phytium_ltimer->ops = ops;
    phytium_ltimer->timeout_set = false;
    phytium_ltimer->timeout_time = 0;

    /* Initialize ARM generic timer */
    error = generic_timer_get_init(&phytium_ltimer->generic_timer);
    if (error) {
        ZF_LOGE("Failed to init generic timer: %d", error);
        destroy(phytium_ltimer);
        return error;
    }

    ZF_LOGD("Phytium Pi ltimer initialized with frequency %u Hz", 
            phytium_ltimer->generic_timer.freq);
    return 0;
}

int ltimer_default_describe(ltimer_t *ltimer, ps_io_ops_t ops)
{
    ZF_LOGE("get_(nth/num)_(irqs/pmems) are not valid");
    return EINVAL;
}
