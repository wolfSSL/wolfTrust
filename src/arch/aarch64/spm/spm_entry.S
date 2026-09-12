/* spm_entry.S
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

/* Secure EL1 entry the monitor drops into with x0 = FF-A boot information
 * blob: point VBAR_EL1 at a table that reports every exception to EL3, take
 * the SPM stack, call wt_spm_main(blob). */

#define WT_MON_FID_PANIC 0xC3800002
#define WT_SPM_PANIC_EXCEPTION 0xEE

    .macro WT_SPM_VECTOR
    .balign 0x80
    ldr     x0, =WT_MON_FID_PANIC
    mov     x1, #WT_SPM_PANIC_EXCEPTION
    smc     #0
1:  wfi
    b       1b
    .endm

    .section .text.wt_spm_entry, "ax"
    .globl wt_spm_entry
wt_spm_entry:
    ldr     x9, =wt_spm_vectors
    msr     VBAR_EL1, x9
    ldr     x9, =__spm_stack_top
    mov     sp, x9
    msr     TPIDRRO_EL0, xzr
    isb
    bl      wt_spm_main
2:  wfi
    b       2b

    .section .text.wt_spm_vectors, "ax"
    .balign 0x800
    .globl wt_spm_vectors
wt_spm_vectors:
    .rept 16
    WT_SPM_VECTOR
    .endr
