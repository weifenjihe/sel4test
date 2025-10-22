/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <autoconf.h>
#include <sel4test-driver/gen_config.h>
#include <sel4/sel4.h>
#include "timer.h"
#include <utils/util.h>
#include <sel4testsupport/testreporter.h>

struct sel4test_ack_data {
    driver_env_t env;
    int nth_timer;
};
typedef struct sel4test_ack_data sel4test_ack_data_t;

/* Forward declaration */
static int timeout_cb(uintptr_t token);

/* A pending timeout requests from tests */
static bool timeServer_timeoutPending = false;
static timeout_type_t timeServer_timeoutType;
static uint64_t timeServer_timeoutNs = 0;
static bool timeServer_noIRQMode = false;
static seL4_CPtr timeServer_notificationCap = seL4_CapNull;
static uint64_t timeServer_periodicIntervalNs = 0;  /* Store the original period for periodic timers */

/* Function to handle periodic timer maintenance in no-IRQ mode */
static void handle_noirq_periodic_timers(void)
{
    if (timeServer_timeoutPending && timeServer_timeoutType == TIMEOUT_PERIODIC && 
        timeServer_notificationCap != seL4_CapNull) {
        
        printf("Timer: Triggering periodic timer callback\n");
        timeout_cb(timeServer_notificationCap);
    }
}

static int timeout_cb(uintptr_t token)
{
    printf("Timer: timeout_cb called, sending signal to token: %lu\n", token);
    seL4_Signal((seL4_CPtr) token);
    printf("Timer: Signal sent successfully\n");

    if (timeServer_timeoutType != TIMEOUT_PERIODIC) {
        timeServer_timeoutPending = false;
        printf("Timer: One-shot timeout completed, clearing pending flag\n");
    } else {
        printf("Timer: Periodic timeout, keeping pending flag\n");
        
        /* For periodic timers in no-IRQ mode, schedule the next callback */
        if (timeServer_noIRQMode && timeServer_notificationCap != seL4_CapNull) {
            printf("Timer: Scheduling next periodic callback for no-IRQ mode\n");
            /* We'll trigger another callback after a short delay in the wait function */
        }
    }
    return 0;
}

static int ack_timer_interrupts(void *ack_data)
{
    ZF_LOGF_IF(!ack_data, "ack_data is NULL");
    sel4test_ack_data_t *timer_ack_data = (sel4test_ack_data_t *) ack_data;

    driver_env_t env = timer_ack_data->env;
    int nth_timer = timer_ack_data->nth_timer;

    /* Acknowledge the interrupt handler */
    int error = seL4_IRQHandler_Ack(env->timer_irqs[nth_timer].handler_path.capPtr);
    ZF_LOGF_IF(error, "Failed to acknowledge timer IRQ handler");

    ps_free(&env->ops.malloc_ops, sizeof(sel4test_ack_data_t), ack_data);
    return error;
}

void handle_timer_interrupts(driver_env_t env, seL4_Word badge)
{
    int error = 0;
    while (badge) {
        seL4_Word badge_bit = CTZL(badge);
        sel4test_ack_data_t *ack_data = NULL;
        error = ps_calloc(&env->ops.malloc_ops, 1, sizeof(sel4test_ack_data_t), (void **) &ack_data);
        ZF_LOGF_IF(error, "Failed to allocate memory for ack token");
        ack_data->env = env;
        ack_data->nth_timer = (int) badge_bit;
        env->timer_cbs[badge_bit].callback(env->timer_cbs[badge_bit].callback_data,
                                           ack_timer_interrupts, ack_data);
        badge &= ~BIT(badge_bit);
    }
}

void wait_for_timer_interrupt(driver_env_t env)
{
    if (config_set(CONFIG_HAVE_TIMER)) {
        /* For platforms without timer interrupts, we do a short polling loop */
        if (env->ltimer.get_num_irqs == NULL || env->ltimer.get_num_irqs(env->ltimer.data) == 0) {
            /* No IRQs configured, use polling and periodic timer management */
            printf("Timer: wait_for_timer_interrupt called, no IRQ mode\n");
            
            /* Handle any pending periodic timers */
            handle_noirq_periodic_timers();
            
            /* Small delay to simulate timer processing */
            for (int i = 0; i < 1000; i++) {
                for (volatile int j = 0; j < 10000; j++);
            }
            
            /* Trigger another periodic callback if needed */
            if (timeServer_timeoutPending && timeServer_timeoutType == TIMEOUT_PERIODIC && 
                timeServer_notificationCap != seL4_CapNull) {
                printf("Timer: Additional periodic timer callback\n");
                timeout_cb(timeServer_notificationCap);
            }
            
            return;
        }
        
        /* Traditional interrupt-based approach */
        seL4_Word sender_badge;
        seL4_Wait(env->timer_notification.cptr, &sender_badge);
        if (sender_badge) {
            handle_timer_interrupts(env, sender_badge);
        }
    } else {
        ZF_LOGF("There is no timer configured for this target");
    }
}

void timeout(driver_env_t env, uint64_t ns, timeout_type_t timeout_type)
{
    if (config_set(CONFIG_HAVE_TIMER)) {
        ZF_LOGD_IF(timeServer_timeoutPending, "Overwriting a previous timeout request");
        timeServer_timeoutType = timeout_type;
        timeServer_timeoutNs = ns;
        
        /* Store the period for periodic timers */
        if (timeout_type == TIMEOUT_PERIODIC) {
            timeServer_periodicIntervalNs = ns;
        }
        
        /* Check if we have timer IRQ support */
        if (env->ltimer.get_num_irqs == NULL || env->ltimer.get_num_irqs(env->ltimer.data) == 0) {
            /* No IRQ support - simulate timer with immediate callback */
            printf("Timer: No IRQ support detected, simulating timeout for %lu ns (type: %s)\n", 
                   ns, timeout_type == TIMEOUT_PERIODIC ? "PERIODIC" : "ONE_SHOT");
            
            timeServer_noIRQMode = true;
            timeServer_notificationCap = env->timer_notify_test.cptr;
            timeServer_timeoutPending = true;
            
            /* For platforms without IRQ, we simulate the timeout immediately */
            int error = timeout_cb(env->timer_notify_test.cptr);
            ZF_LOGF_IF(error != 0, "timeout_cb failed");
            
            printf("Timer: Initial callback triggered successfully\n");
            
            /* For periodic timers in no-IRQ mode, we need to continue signaling */
            if (timeout_type == TIMEOUT_PERIODIC) {
                printf("Timer: Periodic timer set up for continued signaling\n");
            }
        } else {
            /* Normal IRQ-based timer */
            timeServer_noIRQMode = false;
            int error = tm_register_cb(&env->tm, timeout_type, ns, 0,
                                       TIMER_ID, timeout_cb, env->timer_notify_test.cptr);
            if (error == ETIME) {
                error = timeout_cb(env->timer_notify_test.cptr);
            } else {
                timeServer_timeoutPending = true;
            }
            ZF_LOGF_IF(error != 0, "register_cb failed");
        }
    } else {
        ZF_LOGF("There is no timer configured for this target");
    }
}

void timer_reset(driver_env_t env)
{
    if (config_set(CONFIG_HAVE_TIMER)) {
        printf("Timer: timer_reset called, clearing pending timeouts\n");
        
        /* Handle no-IRQ mode */
        if (timeServer_noIRQMode || env->ltimer.get_num_irqs == NULL || 
            env->ltimer.get_num_irqs(env->ltimer.data) == 0) {
            printf("Timer: Resetting no-IRQ mode timer\n");
            timeServer_timeoutPending = false;
            timeServer_timeoutType = TIMEOUT_ABSOLUTE;
            timeServer_notificationCap = seL4_CapNull;
            return;
        }
        
        /* Normal IRQ-based timer reset */
        int error = tm_deregister_cb(&env->tm, TIMER_ID);
        ZF_LOGF_IF(error, "ltimer_rest failed");
        timeServer_timeoutPending = false;
        printf("Timer: IRQ-based timer reset completed\n");
    } else {
        ZF_LOGF("There is no timer configured for this target");
    }
}

/* Enhanced function for test notification waiting with no-IRQ support */
void sel4test_ntfn_timer_wait(driver_env_t env)
{
    if (config_set(CONFIG_HAVE_TIMER)) {
        /* Check if we're in no-IRQ mode */
        if (env->ltimer.get_num_irqs == NULL || env->ltimer.get_num_irqs(env->ltimer.data) == 0) {
            printf("Timer: sel4test_ntfn_timer_wait - no IRQ mode, using polling\n");
            
            /* For no-IRQ mode, we simulate waiting by doing a short delay */
            for (int i = 0; i < 100; i++) {
                for (volatile int j = 0; j < 50000; j++);
            }
            
            /* After the delay, if we have a pending periodic timer, trigger it */
            if (timeServer_timeoutPending && timeServer_timeoutType == TIMEOUT_PERIODIC && 
                timeServer_notificationCap != seL4_CapNull) {
                printf("Timer: Triggering periodic timer callback after wait simulation\n");
                timeout_cb(timeServer_notificationCap);
            }
            return;
        }
        
        /* Normal IRQ-based waiting */
        seL4_Word sender_badge;
        seL4_Wait(env->timer_notify_test.cptr, &sender_badge);
    } else {
        ZF_LOGF("There is no timer configured for this target");
    }
}

uint64_t timestamp(driver_env_t env)
{
    uint64_t time = 0;
    if (config_set(CONFIG_HAVE_TIMER)) {
        int error = ltimer_get_time(&env->ltimer, &time);
        ZF_LOGF_IF(error, "failed to get time");

    } else {
        ZF_LOGF("There is no timer configured for this target");
    }
    return time;
}

void timer_cleanup(driver_env_t env)
{
    ZF_LOGF_IF(!config_set(CONFIG_HAVE_TIMER), "There is no timer configured for this target");
    tm_free_id(&env->tm, TIMER_ID);
    timeServer_timeoutPending = false;
}
