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
 * Partitions run at S-EL0: entering one ERETs into its saved register
 * state under its own translation table, and it comes back when its SVC
 * or fault handler unwinds to the bootstrap through wt_sp_el0_leave. */

#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/arch.h"
#include "wolftrust/platform.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

void wt_co_arch_switch(uintptr_t* save_from_sp, uintptr_t to_sp);
void wt_co_trampoline(void);

/* Frame the first switch-in restores: x19..x30 at 8-byte slots 0..11. */
#define WT_CO_FRAME_WORDS 12u
#define WT_CO_SLOT_X19 0u
#define WT_CO_SLOT_X20 1u
#define WT_CO_SLOT_X30 11u
/* EL0t with D, A, I masked; FIQ stays open so the tick can reach S-EL1. */
#define WT_SP_SPSR_EL0T 0x1C0u

static wt_sp_arch_t g_sp_arch[WT_CO_MAX];

static wt_sp_arch_t* sp_arch(const struct wt_co *co)
{
    if (co->id == 0u || co->id > WT_CO_MAX) {
        wt_platform_panic();
    }
    return &g_sp_arch[co->id - 1u];
}

static void write_tpidrro(uint64_t value)
{
    __asm__ volatile("msr TPIDRRO_EL0, %0\n\tisb" : : "r"(value));
}

void wt_co_arch_init_stack(struct wt_co *co, wt_co_entry_fn entry, void *arg)
{
    uintptr_t top = ((uintptr_t)co->stack_base + co->stack_size) &
                    ~(uintptr_t)15u;
    uint64_t* frame = (uint64_t*)(top - WT_CO_FRAME_WORDS * sizeof(uint64_t));
    wt_sp_arch_t* a = sp_arch(co);
    unsigned int i;

    for (i = 0u; i < WT_CO_FRAME_WORDS; i++) {
        frame[i] = 0u;
    }
    frame[WT_CO_SLOT_X19] = (uint64_t)(uintptr_t)entry;
    frame[WT_CO_SLOT_X20] = (uint64_t)(uintptr_t)arg;
    frame[WT_CO_SLOT_X30] = (uint64_t)(uintptr_t)&wt_co_trampoline;
    co->sp = (uintptr_t)frame;

    /* The S-EL0 form of the same start: the domain flag arrives later. */
    (void)memset(&a->frame, 0, sizeof(a->frame));
    a->frame.x[0] = (uint64_t)(uintptr_t)arg;
    a->frame.elr = (uint64_t)(uintptr_t)entry;
    a->frame.sp_el0 = (uint64_t)top;
    a->frame.spsr = WT_SP_SPSR_EL0T;
}

void wt_co_arch_enter(struct wt_co *to)
{
    const struct wt_secure_domain *domain = to->domain;

    if (domain != NULL) {
        wt_arch_program_sp_thread_domain(domain->regions, domain->region_count);
    }
    if (to->unprivileged != 0u) {
        write_tpidrro((uint64_t)to->id);
        wt_sp_el0_enter(&sp_arch(to)->frame);
        write_tpidrro(0u);
    }
    else {
        wt_co_arch_switch(&g_wt_co_bootstrap.sp, to->sp);
    }
    /* Back on the bootstrap stack: `to` blocked or faulted. */
    g_wt_co_current = &g_wt_co_bootstrap;
    if (domain != NULL) {
        wt_arch_restore_spm_domain();
    }
}

void wt_co_arch_leave(void)
{
    struct wt_co *current = g_wt_co_current;

    if (current->unprivileged != 0u) {
        if (g_wt_spm_live_frame == NULL) {
            wt_platform_panic();
        }
        sp_arch(current)->frame = *g_wt_spm_live_frame;
        g_wt_spm_live_frame = NULL;
        g_wt_spm_handler_depth = 0u;
        wt_sp_el0_leave();
    }
    wt_co_arch_switch(&current->sp, g_wt_co_bootstrap.sp);
}

/* Cooperative on AArch64: the tick FIQ requests a switch through the
 * scheduler, so no asynchronous trigger is needed here. */
void wt_co_arch_request_preempt(void)
{
}
