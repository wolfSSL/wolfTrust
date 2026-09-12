/* coroutine_aarch64.c
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* Coroutine architecture hooks at S-EL1. The switch itself lands with the
 * SVC gate; until then every entry fails closed so a partial runtime can
 * never run a partition unconfined. */

#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/platform.h"

#include <stddef.h>
#include <stdint.h>

void wt_co_arch_init_stack(struct wt_co *co, wt_co_entry_fn entry, void *arg)
{
    uintptr_t sp = (uintptr_t)co->stack_base + co->stack_size;

    co->sp = sp & ~(uintptr_t)15u;
    co->entry = entry;
    co->arg = arg;
}

void wt_co_arch_enter(struct wt_co *to)
{
    (void)to;
    wt_platform_panic();
}

void wt_co_arch_leave(void)
{
    wt_platform_panic();
}

void wt_co_arch_request_preempt(void)
{
    wt_platform_panic();
}
