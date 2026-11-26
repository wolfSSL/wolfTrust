/* mutex.c
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

#include "wolftrust/sync/mutex.h"
#include "wolftrust/sched/coroutine_internal.h"

/* NOTE ON ATOMICITY
 * -----------------
 * The secure side runs on a single core with cooperative scheduling.
 * The only point at which control can transfer to another tasklet is an
 * explicit blocking call. There are no such calls
 * between the holder-NULL check and the holder assignment in acquire, nor
 * between the holder check and the wake in release, so both operations are
 * logically atomic with respect to other coroutines.
 *
 * SysTick / interrupt handlers that run tasklets run from the bootstrap
 * context (id == 0 / wt_co_current() == NULL).  The API contract forbids
 * bootstrap code from holding mutexes, so no interrupt can be a mutex
 * participant.  Do NOT add a critical section (PRIMASK / BASEPRI disable)
 * here — it is unnecessary and would mask faults during the blocking path.
 */

void wt_mutex_init(wt_mutex_t *m)
{
    m->holder       = NULL;
    m->wait_head    = NULL;
    m->wait_tail    = NULL;
    m->acquire_count = 0u;
    m->contend_count = 0u;
}

int wt_mutex_acquire(wt_mutex_t *m)
{
    /* The bootstrap must not block, and a recursive acquire would deadlock. */
    wt_co_t *self = wt_co_current();
    int ret = -1;

    if (self != NULL && m->holder != self) {
        ret = wt_mutex_acquire_queued(m, self);
    }
    if (ret == 1) {
        /* A latched wake can end the block early; release hands the mutex
         * over before waking, so wait until this coroutine holds it. */
        do {
            wt_co_block();
        } while (m->holder != self);
        m->acquire_count++;
        ret = 0;
    }
    return ret;
}

int wt_mutex_release(wt_mutex_t *m)
{
    wt_co_t *next;

    if (m->holder != wt_co_current())
        return -1;

    if (m->wait_head == NULL) {
        /* No waiters: simply release. */
        m->holder = NULL;
        return 0;
    }

    /* Pop the head of the wait queue and transfer ownership before waking,
     * so the woken coroutine observes itself as holder the instant it
     * resumes. */
    next            = m->wait_head;
    m->wait_head    = next->next_wait;
    if (m->wait_head == NULL)
        m->wait_tail = NULL;
    next->next_wait = NULL;

    m->holder = next;
    wt_co_wake(next);

    return 0;
}

bool wt_mutex_try_acquire(wt_mutex_t *m)
{
    if (m->holder != NULL)
        return false;

    m->holder = wt_co_current();
    m->acquire_count++;
    return true;
}

struct wt_co *wt_mutex_holder(const wt_mutex_t *m)
{
    return m->holder;
}

int wt_mutex_acquire_queued(wt_mutex_t *m, struct wt_co *self)
{
    wt_co_t *waiter;

    if (m == NULL || self == NULL) {
        return -1;
    }
    if (m->holder == NULL) {
        m->holder = self;
        m->acquire_count++;
        return 0;
    }
    /* Includes the gated re-issue after release handed the mutex over. */
    if (m->holder == self) {
        return 0;
    }
    for (waiter = m->wait_head; waiter != NULL;
            waiter = waiter->next_wait) {
        if (waiter == self) {
            return 1;
        }
    }

    m->contend_count++;
    self->next_wait = NULL;
    if (m->wait_head == NULL) {
        m->wait_head = self;
        m->wait_tail = self;
    } else {
        m->wait_tail->next_wait = self;
        m->wait_tail = self;
    }
    return 1;
}

void wt_mutex_remove_waiter(wt_mutex_t *m, struct wt_co *co)
{
    wt_co_t *prev;
    wt_co_t *cur;

    if (m == NULL || co == NULL) {
        return;
    }

    /* Unlink co from the wait queue if parked there. A coroutine that faults
     * while blocked as a waiter would otherwise be handed the mutex on the
     * next release (m->holder = dead co, wt_co_wake a no-op for FAULTED) and
     * every later acquirer would block forever behind the dead holder. */
    prev = NULL;
    cur = m->wait_head;
    while (cur != NULL) {
        if (cur == co) {
            if (prev == NULL) {
                m->wait_head = cur->next_wait;
            } else {
                prev->next_wait = cur->next_wait;
            }
            if (m->wait_tail == cur) {
                m->wait_tail = prev;
            }
            cur->next_wait = NULL;
            return;
        }
        prev = cur;
        cur = cur->next_wait;
    }
}

void wt_mutex_release_if_holder(wt_mutex_t *m, struct wt_co *co)
{
    wt_co_t *next;

    if (m == NULL || co == NULL || m->holder != co) {
        return;
    }

    if (m->wait_head == NULL) {
        m->holder = NULL;
        return;
    }

    /* Hand the mutex to the next waiter, identical to wt_mutex_release
     * but without the "holder == current" check that fails from handler
     * mode (wt_co_current() returns the faulted coroutine which is no
     * longer running). */
    next            = m->wait_head;
    m->wait_head    = next->next_wait;
    if (m->wait_head == NULL)
        m->wait_tail = NULL;
    next->next_wait = NULL;

    m->holder = next;
    wt_co_wake(next);
}
