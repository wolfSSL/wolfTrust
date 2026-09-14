/* spm_svc.h
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

/* Secure virtual instance (SVC) conventions between S-EL0 partitions and
 * the S-EL1 SPMC. FF-A function ids ride x0 as at any instance; the
 * wolfTrust partition-message hypercall (DEV-05) uses the OEM range. */

#ifndef WOLFTRUST_ARCH_AARCH64_SPM_SVC_H
#define WOLFTRUST_ARCH_AARCH64_SPM_SVC_H

#include "wolftrust/arch/aarch64/context.h"

#include <stdint.h>

/* x0 = this id, x1 = wt_spm_call_t*, x8 = call->op; x0 = gate status out. */
#define WT_SPM_SVC_FID_CALL  0xC3800100u
/* Scheduler yield from a partition; x1 carries a token the SPMC records. */
#define WT_SPM_SVC_FID_YIELD 0xC3800101u

/* Saved S-EL0 register state of one partition, indexed by coroutine id. */
typedef struct wt_sp_arch {
    wt_trap_frame_t frame;
} wt_sp_arch_t;

/* Set while an S-EL1 exception handler runs on a partition's behalf. */
extern volatile uint32_t g_wt_spm_handler_depth;
extern volatile uint64_t g_wt_spm_trap_spsr;
/* The frame of the exception being handled (valid while depth != 0). */
extern wt_trap_frame_t* volatile g_wt_spm_live_frame;

void wt_spm_sp_panic_trap(void);
void wt_spm_idle(void) __attribute__((noreturn));

/* Load frame into the S-EL0 state and ERET; returns when the partition's
 * exception handler unwinds back through wt_sp_el0_leave. */
void wt_sp_el0_enter(wt_trap_frame_t* frame);
void wt_sp_el0_leave(void) __attribute__((noreturn));
void wt_spm_lower_sync(wt_trap_frame_t* frame);
uint64_t wt_spm_yield_token(void);

/* Set once the core owns the partitions: the first block of each S-EL0
 * coroutine then counts as that partition's initialization. */
extern volatile uint32_t g_wt_spm_partitions_live;
uint32_t wt_spm_sp_init_count(void);
void wt_spm_init_partitions(void);

#endif /* WOLFTRUST_ARCH_AARCH64_SPM_SVC_H */
