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

#include <stdint.h>

/* x0 = this id, x1 = wt_spm_call_t*, x8 = call->op; x0 = gate status out. */
#define WT_SPM_SVC_FID_CALL 0xC3800100u

/* Set while an S-EL1 exception handler runs on a partition's behalf. */
extern volatile uint32_t g_wt_spm_handler_depth;
extern volatile uint64_t g_wt_spm_trap_spsr;

void wt_spm_sp_panic_trap(void);
void wt_spm_idle(void) __attribute__((noreturn));

#endif /* WOLFTRUST_ARCH_AARCH64_SPM_SVC_H */
