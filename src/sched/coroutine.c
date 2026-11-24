/* coroutine.c
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

#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/platform.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Static coroutine table; slot 0 is reserved for the implicit bootstrap. */
static struct wt_co g_co_table[WT_CO_MAX - 1u];

/* Implicit bootstrap (monitor) context. */
struct wt_co g_wt_co_bootstrap;

/* Currently executing coroutine. Points to &g_wt_co_bootstrap while the
 * monitor is running.  Updated by the C scheduler before every switch. */
struct wt_co *g_wt_co_current;

/* Number of coroutine slots consumed (including bootstrap). */
static uint32_t g_co_count;

/* -------------------------------------------------------------------------
 * Runqueue helpers
 * ---------------------------------------------------------------------- */

static bool is_valid_co_pointer(const struct wt_co *co)
{
    uint32_t i;

    if (co == &g_wt_co_bootstrap) {
        return true;
    }

    for (i = 0u; i < WT_CO_MAX - 1u; i++) {
        if (co == &g_co_table[i]) {
            return true;
        }
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Canary check helper — only coroutines with a real stack are checked.
 * ---------------------------------------------------------------------- */

static void check_canary(struct wt_co *co)
{
    if (co == (struct wt_co *)0 || co->stack_base == (uint8_t *)0) {
        return; /* bootstrap has no stack buffer */
    }
    if (*(volatile uint32_t *)(void *)co->stack_base != WT_CO_STACK_CANARY) {
        wt_platform_panic();
    }
}

/* -------------------------------------------------------------------------
 * Switch helper: validate canary, update state bookkeeping, call arch.
 * ---------------------------------------------------------------------- */

static void do_switch(struct wt_co *to)
{
    if (to == (struct wt_co *)0 || !is_valid_co_pointer(to)) {
        to = &g_wt_co_bootstrap;
    }

    check_canary(g_wt_co_current);
    check_canary(to);
    g_wt_co_current = to;
    to->state = WT_CO_RUNNING;
    wt_co_arch_enter(to);
    /* Execution resumes here when `to` blocks or faults back to bootstrap. */
    check_canary(to);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void wt_co_init(void)
{
    (void)memset(g_co_table, 0, sizeof(g_co_table));
    (void)memset(&g_wt_co_bootstrap, 0, sizeof(g_wt_co_bootstrap));
    g_wt_co_bootstrap.state = WT_CO_RUNNING;
    g_wt_co_current = &g_wt_co_bootstrap;
    g_co_count = 1u; /* bootstrap counts as slot 0 */
}

static wt_co_t *wt_co_create_common(uint8_t *stack, size_t stack_size,
                                    wt_co_entry_fn entry, void *arg,
                                    uint8_t initial_state, size_t min_stack,
                                    int require_priv_stack)
{
    struct wt_co *co;
    uint32_t      id;

    /* Validate arguments. */
    if (entry == (wt_co_entry_fn)0) {
        return (wt_co_t *)0;
    }
    if (stack == (uint8_t *)0) {
        return (wt_co_t *)0;
    }
    if (stack_size < min_stack || stack_size < WT_CO_STACK_MIN) {
        return (wt_co_t *)0;
    }
    /* 8-byte alignment check. */
    if (((uintptr_t)stack & 7u) != 0u) {
        return (wt_co_t *)0;
    }
    if (g_co_count >= WT_CO_MAX) {
        return (wt_co_t *)0;
    }
    /* A coroutine that stays privileged must own an SPM-private stack, so a
     * partition can never hold a privileged frame (WT-FFM-0011). SP coroutines
     * are demoted after creation and keep their partition stacks, so exempt. */
    if (require_priv_stack != 0 &&
            wt_platform_priv_stack_ok(stack, stack_size) == 0) {
        return (wt_co_t *)0;
    }

    /* Assign a table slot (0 is taken by bootstrap). */
    id = g_co_count;
    g_co_count++;
    co = &g_co_table[id - 1u]; /* id 0 is the bootstrap, outside the table */

    co->id           = id;
    co->stack_base   = stack;
    co->stack_size   = stack_size;
    co->entry        = entry;
    co->arg          = arg;
    co->state        = (wt_co_state_t)initial_state;
    co->next_wait    = (struct wt_co *)0;
    co->domain       = (const struct wt_secure_domain *)0;
    co->unprivileged = 0u;

    /* Plant stack canary at the very bottom of the caller-provided buffer. */
    *(volatile uint32_t *)(void *)stack = WT_CO_STACK_CANARY;

    /* Let the arch code set up the initial register frame on this stack. */
    wt_co_arch_init_stack(co, entry, arg);

    return (wt_co_t *)co;
}

wt_co_t *wt_co_create_blocked(uint8_t *stack, size_t stack_size,
                              wt_co_entry_fn entry, void *arg)
{
    return wt_co_create_common(stack, stack_size, entry, arg, WT_CO_BLOCKED,
                               WT_CO_STACK_SIZE, 1);
}

wt_co_t *wt_co_create_blocked_ex(uint8_t *stack, size_t stack_size,
                                 wt_co_entry_fn entry, void *arg)
{
    return wt_co_create_common(stack, stack_size, entry, arg, WT_CO_BLOCKED,
                               WT_CO_STACK_MIN, 0);
}

void wt_co_set_domain(wt_co_t *co, const struct wt_secure_domain *domain,
                      uint8_t unprivileged)
{
    if (co == (wt_co_t *)0 || !is_valid_co_pointer(co) ||
        co == (wt_co_t *)&g_wt_co_bootstrap) {
        wt_platform_panic();
        return;
    }
    co->domain       = domain;
    co->unprivileged = (uint8_t)(unprivileged != 0u ? 1u : 0u);
}

void wt_co_block(void)
{
    struct wt_co *from;

    from = g_wt_co_current;

    if (from == &g_wt_co_bootstrap) {
        /* Blocking the bootstrap would deadlock the monitor. */
        wt_platform_panic();
    }

    from->state = WT_CO_BLOCKED;
    wt_co_arch_leave();
}

void wt_co_wake(wt_co_t *co)
{
    if (co == (wt_co_t *)0) {
        return;
    }
    if (!is_valid_co_pointer(co) || co == (wt_co_t *)&g_wt_co_bootstrap) {
        wt_platform_panic();
        return;
    }
    if (co->state == WT_CO_RUNNABLE || co->state == WT_CO_RUNNING) {
        /* Active coroutines may be about to block on a condition this wake
         * just satisfied (preempted between poll and block): latch the wake
         * so the block/dispatch path can consume it. */
        co->wake_pending = 1u;
        return;
    }
    if (co->state == WT_CO_FAULTED) {
        return; /* terminal — never wake again */
    }
    co->wake_pending = 0u;
    co->state = WT_CO_RUNNABLE;
}

void wt_co_mark_faulted(wt_co_t *co)
{
    if (co == (wt_co_t *)0) {
        return;
    }

    /* Leave next_wait intact: a coroutine parked in a mutex wait queue must
     * stay linked so recovery (wt_mutex_remove_waiter) can unlink it cleanly;
     * clearing it here would strand the waiters queued behind it. wt_co_reinit
     * resets next_wait when the coroutine is restarted. */
    co->state     = WT_CO_FAULTED;

    if (g_wt_co_current == co) {
        g_wt_co_current = &g_wt_co_bootstrap;
    }
}

int wt_co_reinit(wt_co_t *co, wt_co_entry_fn entry, void *arg)
{
    if (co == (wt_co_t *)0 || entry == (wt_co_entry_fn)0) {
        return -1;
    }
    if (!is_valid_co_pointer(co) || co == (wt_co_t *)&g_wt_co_bootstrap) {
        return -1;
    }
    if (co->stack_base == (uint8_t *)0) {
        return -1;
    }

    /* Reclaim the existing slot in place: a restart must not consume a new
     * g_co_table entry and must keep the SP's MPU domain binding. It stays
     * BLOCKED until its service signal next asserts, exactly as at boot. */
    if (g_wt_co_current == co) {
        g_wt_co_current = &g_wt_co_bootstrap;
    }

    co->sp        = 0u;
    co->entry     = entry;
    co->arg       = arg;
    co->state     = WT_CO_BLOCKED;
    co->next_wait = (struct wt_co *)0;
    co->wake_pending = 0u;

    *(volatile uint32_t *)(void *)co->stack_base = WT_CO_STACK_CANARY;
    wt_co_arch_init_stack(co, entry, arg);
    return 0;
}

wt_co_t *wt_co_current(void)
{
    if (g_wt_co_current == &g_wt_co_bootstrap) {
        return (wt_co_t *)0;
    }
    return (wt_co_t *)g_wt_co_current;
}

wt_co_state_t wt_co_state(const wt_co_t *co)
{
    if (co == (const wt_co_t *)0) {
        return WT_CO_FAULTED;
    }
    return co->state;
}

bool wt_co_wake_pending(const wt_co_t *co)
{
    return co != (const wt_co_t *)0 && co->wake_pending != 0u;
}

uint32_t wt_co_run(wt_co_t *co)
{
    if (co == (wt_co_t *)0) {
        return 0u;
    }

    if (g_wt_co_current != &g_wt_co_bootstrap) {
        return 0u;
    }
    if (!is_valid_co_pointer(co) || co == (wt_co_t *)&g_wt_co_bootstrap) {
        wt_platform_panic();
        return 0u;
    }
    if (co->state != WT_CO_RUNNABLE) {
        return 0u;
    }

    do_switch((struct wt_co *)co);
    return 1u;
}

bool wt_co_request_preempt(void)
{
    struct wt_co *current = g_wt_co_current;

    if (current == &g_wt_co_bootstrap || current == (struct wt_co *)0) {
        return false;
    }
    if (current->state != WT_CO_RUNNING) {
        return false;
    }

    current->state = WT_CO_RUNNABLE;
    g_wt_co_pendsv_target = (struct wt_co *)0;
    wt_co_arch_request_preempt();
    return true;
}
