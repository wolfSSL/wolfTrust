/* tasklet.h
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

#ifndef WOLFTRUST_SCHED_TASKLET_H
#define WOLFTRUST_SCHED_TASKLET_H

#include "wolftrust/sched/coroutine.h"

typedef wt_co_t wt_tasklet_t;
typedef wt_co_entry_fn wt_tasklet_entry_fn;
typedef wt_co_state_t wt_tasklet_state_t;

#define WT_TASKLET_RUNNABLE WT_CO_RUNNABLE
#define WT_TASKLET_RUNNING  WT_CO_RUNNING
#define WT_TASKLET_BLOCKED  WT_CO_BLOCKED
#define WT_TASKLET_FAULTED  WT_CO_FAULTED

static inline void wt_tasklet_init(void)
{
    wt_co_init();
}

static inline wt_tasklet_t *wt_tasklet_create_blocked(
    uint8_t *stack, size_t stack_size, wt_tasklet_entry_fn entry, void *arg)
{
    return wt_co_create_blocked(stack, stack_size, entry, arg);
}

static inline void wt_tasklet_block(void)
{
    wt_co_block();
}

static inline void wt_tasklet_wake(wt_tasklet_t *tasklet)
{
    wt_co_wake(tasklet);
}

static inline wt_tasklet_t *wt_tasklet_current(void)
{
    return wt_co_current();
}

static inline wt_tasklet_state_t wt_tasklet_state(const wt_tasklet_t *tasklet)
{
    return wt_co_state(tasklet);
}

static inline bool wt_tasklet_wake_pending(const wt_tasklet_t *tasklet)
{
    return wt_co_wake_pending(tasklet);
}

static inline uint32_t wt_tasklet_resume(wt_tasklet_t *tasklet)
{
    return wt_co_run(tasklet);
}

static inline bool wt_tasklet_request_preempt(void)
{
    return wt_co_request_preempt();
}

static inline void wt_tasklet_mark_faulted(wt_tasklet_t *tasklet)
{
    wt_co_mark_faulted(tasklet);
}

#endif /* WOLFTRUST_SCHED_TASKLET_H */
