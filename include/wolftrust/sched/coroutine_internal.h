/* coroutine_internal.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFTRUST_SCHED_COROUTINE_INTERNAL_H
#define WOLFTRUST_SCHED_COROUTINE_INTERNAL_H

#include "wolftrust/sched/coroutine.h"

/* Bootstrap plus one coroutine per generated partition and wolfHSM tasklet. */
#if defined(WT_TARGET_BUILD) && !defined(WT_CO_MAX)
#include "wolftrust_manifest_generated.h"
#if defined(WT_ENGINE_HSM)
#define WT_CO_MAX (WT_GEN_SP_COUNT + WT_MAX_GUESTS + 1u)
#else
#define WT_CO_MAX (WT_GEN_SP_COUNT + 1u)
#endif
#endif
#ifndef WT_CO_MAX
#define WT_CO_MAX 12u
#endif

/* Magic sentinel placed at the bottom of the stack to detect overflow.
 * Checked at every switch; mismatch causes wt_platform_panic(). */
#define WT_CO_STACK_CANARY 0xC0C0DEADu

struct wt_co {
    /* Saved MSP for this coroutine. Set to top-of-stack on creation,
     * updated on every switch-out, consumed on switch-in. Architecture-
     * specific code (coroutine_armv8m.c) is the ONLY writer once the
     * coroutine has started running. */
    uintptr_t sp;

    /* Stack region the caller gave us. base[0] must hold STACK_CANARY. */
    uint8_t *stack_base;
    size_t   stack_size;

    /* Entry function + arg (cleared once the coroutine has actually
     * started executing — useful for debug). */
    wt_co_entry_fn entry;
    void          *arg;

    wt_co_state_t state;
    uint32_t      id;          /* 0 = bootstrap, 1..N = created order */

    /* Linked-list link for wait queues (used by wt_mutex_t and friends).
     * Owned by whichever wait queue currently holds this coroutine.
     * NULL when not waiting. */
    struct wt_co *next_wait;

    /* Secure Partition protection domain (NULL for plain tasklets). The
     * ARMv8-M port programs these MPU regions around every switch-in and,
     * when unprivileged is set, returns to the coroutine thread with
     * CONTROL.nPRIV=1. PendSV asm reads unprivileged by fixed offset. */
    const struct wt_secure_domain *domain;
    uint8_t unprivileged;

    /* Sticky wake token: set when wt_co_wake targets a coroutine that is
     * already RUNNABLE/RUNNING (e.g. tick-preempted between a NOTREADY poll
     * and its block) so the wake survives until the next block/dispatch
     * instead of being discarded — the lost-wakeup behind the multi-chunk
     * HSM RNG hang. Placed after unprivileged: PendSV asm reads earlier
     * fields by fixed offset. */
    volatile uint8_t wake_pending;

    /* EXC_RETURN captured by PendSV when this coroutine is switched out and
     * replayed on switch-in. An NS exception that preempts the coroutine
     * stacks the extended signed secure context; resuming through a
     * hardcoded basic-frame EXC_RETURN unstacks it as an 8-word frame and
     * faults INVPC (H563 silicon). PendSV asm reads this by fixed offset. */
    uint32_t exc_return;
};

/* Field offsets the switch and fault asm use; coroutine_armv8m.c asserts
 * them against the struct. */
#define WT_CO_SP_OFFSET         0
#define WT_CO_STACK_BASE_OFFSET 4
#define WT_CO_UNPRIV_OFFSET     36
#define WT_CO_EXCRET_OFFSET     40
#define WT_CO_XSTR(x) #x
#define WT_CO_STR(x)  WT_CO_XSTR(x)

/* Exposed to the ARMv8-M exception-based switch path. */
extern struct wt_co  g_wt_co_bootstrap;
extern struct wt_co *g_wt_co_current;
extern struct wt_co *g_wt_co_pendsv_target;

/* Architecture hooks. The ARMv8-M port enters tasklets through
 * SVC-triggered Secure PendSV, then tasklets block back to bootstrap by
 * restoring the saved MSP_S bootstrap frame directly. Each call returns
 * only after control is back on the bootstrap MSP_S stack. */
void wt_co_arch_enter(struct wt_co *to);
void wt_co_arch_leave(void);
void wt_co_arch_request_preempt(void);

/* Architecture hook. Initialise `co`'s stack so that a subsequent
 * wt_co_arch_enter(co) returns into `entry(arg)`. Sets co->sp to the
 * prepared top-of-stack. Coroutine
 * must never return from `entry`; if it does, wt_platform_panic is
 * invoked via a trampoline frame the arch code installs at the
 * bottom of the saved frame. */
void wt_co_arch_init_stack(struct wt_co *co, wt_co_entry_fn entry, void *arg);

#endif
