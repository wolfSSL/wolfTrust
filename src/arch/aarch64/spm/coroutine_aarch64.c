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

/* Coroutine architecture hooks at Secure EL1. Privileged tasklets run at
 * S-EL1 through a synchronous save/restore switch. Unprivileged Secure
 * Partitions run at S-EL0 through an ERET wrapper that lands with the SVC
 * gate; until then a domain-bearing coroutine fails closed. */

#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/arch.h"
#include "wolftrust/platform.h"

#include <stddef.h>
#include <stdint.h>

void wt_co_arch_switch(uintptr_t* save_from_sp, uintptr_t to_sp);
void wt_co_trampoline(void);

/* Frame the first switch-in restores: x19..x30 at 8-byte slots 0..11. */
#define WT_CO_FRAME_WORDS 12u
#define WT_CO_SLOT_X19 0u
#define WT_CO_SLOT_X20 1u
#define WT_CO_SLOT_X30 11u

void wt_co_arch_init_stack(struct wt_co *co, wt_co_entry_fn entry, void *arg)
{
    uintptr_t top = ((uintptr_t)co->stack_base + co->stack_size) &
                    ~(uintptr_t)15u;
    uint64_t* frame = (uint64_t*)(top - WT_CO_FRAME_WORDS * sizeof(uint64_t));
    unsigned int i;

    for (i = 0u; i < WT_CO_FRAME_WORDS; i++) {
        frame[i] = 0u;
    }
    frame[WT_CO_SLOT_X19] = (uint64_t)(uintptr_t)entry;
    frame[WT_CO_SLOT_X20] = (uint64_t)(uintptr_t)arg;
    frame[WT_CO_SLOT_X30] = (uint64_t)(uintptr_t)&wt_co_trampoline;
    co->sp = (uintptr_t)frame;
}

void wt_co_arch_enter(struct wt_co *to)
{
    const struct wt_secure_domain *domain = to->domain;

    /* S-EL0 partitions need the ERET path (next slice); refuse to run an
     * unprivileged partition at S-EL1 rather than run it unconfined. */
    if (to->unprivileged != 0u) {
        wt_platform_panic();
    }
    if (domain != NULL) {
        wt_arch_program_sp_thread_domain(domain->regions, domain->region_count);
    }
    wt_co_arch_switch(&g_wt_co_bootstrap.sp, to->sp);
    /* Back on the bootstrap stack: `to` blocked or faulted. */
    g_wt_co_current = &g_wt_co_bootstrap;
    if (domain != NULL) {
        wt_arch_restore_spm_domain();
    }
}

void wt_co_arch_leave(void)
{
    wt_co_arch_switch(&g_wt_co_current->sp, g_wt_co_bootstrap.sp);
}

/* Cooperative on AArch64: the tick FIQ requests a switch through the
 * scheduler, so no asynchronous trigger is needed here. */
void wt_co_arch_request_preempt(void)
{
}
