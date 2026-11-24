/* coroutine.h
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

#ifndef WOLFTRUST_SCHED_COROUTINE_H
#define WOLFTRUST_SCHED_COROUTINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Default per-coroutine stack size (bytes). Target builds may override this
 * after measuring stack high-water marks for their HSM workload. */
#ifndef WT_CO_STACK_SIZE
#define WT_CO_STACK_SIZE (10u * 1024u)
#endif

/* Coroutine lifecycle states. Internal scheduler state, exposed because
 * mutex/condvar code inspects it. WT_CO_FAULTED is terminal: the
 * coroutine took a Secure-side fault (MemManage / UsageFault including
 * PSPLIM_S overflow) and was abandoned by the fault handler. */
typedef enum wt_co_state {
    WT_CO_RUNNABLE = 0,
    WT_CO_RUNNING,
    WT_CO_BLOCKED,
    WT_CO_FAULTED
} wt_co_state_t;

/* Forward declaration; full layout lives in src/sched/coroutine.c.
 * Consumers treat this as opaque except for the fields documented below. */
typedef struct wt_co wt_co_t;

/* Entry function signature. Coroutines never return — they must loop. */
typedef void (*wt_co_entry_fn)(void *arg);

/* Initialise the coroutine table and make the bootstrap (monitor) context
 * the implicit "outer" coroutine. Call once at boot, before any create. */
void wt_co_init(void);

/* A BLOCKED coroutine on `stack` (at least WT_CO_STACK_SIZE bytes, 8-byte
 * aligned and SPM-private) running `entry(arg)` once woken and run; NULL
 * when the table is full. Monitor init context only. */
wt_co_t *wt_co_create_blocked(uint8_t *stack, size_t stack_size,
                              wt_co_entry_fn entry, void *arg);

/* Floor for _ex creation: canary + initial register frame + call headroom.
 * Secure Partition stacks are manifest-sized and may be smaller than the
 * WT_CO_STACK_SIZE default the HSM tasklets use. */
#define WT_CO_STACK_MIN 1024u

wt_co_t *wt_co_create_blocked_ex(uint8_t *stack, size_t stack_size,
                                 wt_co_entry_fn entry, void *arg);

/* Bind a Secure Partition protection domain to `co`. When set, the
 * architecture switch programs the domain's MPU regions before the
 * coroutine runs, restores the SPM whitelist when it yields, and (when
 * unprivileged is non-zero) drops the coroutine thread to unprivileged
 * execution. The scheduler only stores the pointer; interpretation is
 * the architecture port's. */
struct wt_secure_domain;
void wt_co_set_domain(wt_co_t *co, const struct wt_secure_domain *domain,
                      uint8_t unprivileged);

/* Mark the current coroutine BLOCKED and switch away. Returns only when
 * some other code path calls wt_co_wake on this coroutine. Used by
 * wt_mutex_acquire and similar wait primitives. Calling from the
 * bootstrap context is forbidden — would deadlock the monitor. */
void wt_co_block(void);

/* Mark `co` as RUNNABLE. Safe to call from any coroutine, from the
 * bootstrap, or from an interrupt handler (callers must guarantee
 * single-threaded access — secure side is single-core). No-op if `co`
 * is already RUNNABLE or RUNNING. Does NOT switch — the woken
 * coroutine runs the next time its owner calls wt_co_run on it. */
void wt_co_wake(wt_co_t *co);

/* Return handle of currently executing coroutine, or NULL if running
 * in the bootstrap (monitor) context. */
wt_co_t *wt_co_current(void);

/* Read state — used by audit/instrumentation, not for scheduling
 * decisions in user code. A NULL handle reports WT_CO_FAULTED. */
wt_co_state_t wt_co_state(const wt_co_t *co);

/* True when a wake arrived while the coroutine was active and is latched
 * for the next block/dispatch (see wt_co_wake). */
bool wt_co_wake_pending(const wt_co_t *co);

/* Run one specific runnable coroutine from the bootstrap context.
 * Returns 1 if `co` ran and switched back, 0 if `co` was NULL, not
 * runnable, or the caller was not in the bootstrap context. */
uint32_t wt_co_run(wt_co_t *co);

/* Request preemption of the currently running coroutine from handler
 * mode. The interrupted coroutine becomes RUNNABLE again and Secure
 * PendSV returns execution to the bootstrap context. Returns false if
 * no coroutine is currently running. */
bool wt_co_request_preempt(void);

/* Mark `co` as terminally FAULTED; a mutex wait queue keeps its link for
 * recovery to remove. Called from the Secure-side fault handler when a
 * coroutine trips PSPLIM_S, MPU_S, or any UsageFault. After this returns, the
 * coroutine never runs again and wt_co_wake on it is a no-op. The fault
 * handler is responsible for unwinding back to the bootstrap context.
 * Safe to call from handler mode; the scheduler is cooperative so there
 * is no preemption to fence against. */
void wt_co_mark_faulted(wt_co_t *co);

/* Restart a faulted (or blocked) coroutine in place: reclaim the same table
 * slot with a fresh stack frame and BLOCKED state, preserving its id and its
 * Secure Partition MPU domain binding. Returns 0 on success, -1 for a bad
 * pointer or a coroutine with no stack. Used by the graceful SP fault-recovery
 * path (WT-SYS-0008 / WT-FFM-0017) so a restartable partition resumes without
 * consuming a new slot or resetting the platform. */
int wt_co_reinit(wt_co_t *co, wt_co_entry_fn entry, void *arg);

#endif
