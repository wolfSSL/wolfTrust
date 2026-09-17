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

/* Panic code 0xE0 + slot names the vector that fired. */
    .macro WT_SPM_VECTOR_PANIC slot
    .balign 0x80
    ldr     x0, =WT_MON_FID_PANIC
    mov     x1, #(0xE0 + \slot)
    smc     #0
1:  wfi
    b       1b
    .endm

    .macro WT_SPM_VECTOR_BRANCH target
    .balign 0x80
    b       \target
    .endm

/* Copy [x10, x11) from x9 and zero [x12, x13), 16 bytes at a time; the
 * linker script aligns every band edge to 16. */
    .macro WT_SPM_INIT_BAND lma, start, end, bss_start, bss_end
    ldr     x9, =\lma
    ldr     x10, =\start
    ldr     x11, =\end
1:  cmp     x10, x11
    b.hs    2f
    ldp     x14, x15, [x9], #16
    stp     x14, x15, [x10], #16
    b       1b
2:  ldr     x12, =\bss_start
    ldr     x13, =\bss_end
3:  cmp     x12, x13
    b.hs    4f
    stp     xzr, xzr, [x12], #16
    b       3b
4:
    .endm

    .section .text.wt_spm_entry, "ax"
    .globl wt_spm_entry
wt_spm_entry:
    mov     x19, x0
    ldr     x9, =wt_spm_vectors
    msr     VBAR_EL1, x9
    ldr     x9, =__spm_stack_top
    mov     sp, x9
    msr     TPIDRRO_EL0, xzr
    isb
    WT_SPM_INIT_BAND __data_lma, __data_start, __data_end, __bss_start, __bss_end
    WT_SPM_INIT_BAND _si_keystore, _s_keystore, _e_keystore_data, _s_keystore_bss, _e_keystore
    WT_SPM_INIT_BAND _si_conf_data, _s_conf_data, _e_conf_data_data, _s_conf_bss, _e_conf_bss
    mov     x0, x19
    bl      wt_spm_main
2:  wfi
    b       2b

/* Current-EL SPx FIQ (slot 6): Group 0 interrupts reach the SPMC while the
 * Secure world runs; save the caller-saved state and run wt_spm_fiq. */
    .section .text.wt_spm_fiq_entry, "ax"
wt_spm_fiq_entry:
    sub     sp, sp, #192
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x29, [sp, #144]
    mrs     x0, ELR_EL1
    mrs     x1, SPSR_EL1
    stp     x30, x0, [sp, #160]
    str     x1, [sp, #176]
    bl      wt_spm_fiq
    ldr     x1, [sp, #176]
    ldp     x30, x0, [sp, #160]
    msr     ELR_EL1, x0
    msr     SPSR_EL1, x1
    ldp     x18, x29, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #192
    eret

    .section .text.wt_spm_vectors, "ax"
    .balign 0x800
    .globl wt_spm_vectors
wt_spm_vectors:
    WT_SPM_VECTOR_PANIC 0
    WT_SPM_VECTOR_PANIC 1
    WT_SPM_VECTOR_PANIC 2
    WT_SPM_VECTOR_PANIC 3
    WT_SPM_VECTOR_PANIC 4
    WT_SPM_VECTOR_PANIC 5
    WT_SPM_VECTOR_BRANCH wt_spm_fiq_entry
    WT_SPM_VECTOR_PANIC 7
    WT_SPM_VECTOR_BRANCH wt_sp_lower_sync_entry
    WT_SPM_VECTOR_PANIC 9
    WT_SPM_VECTOR_BRANCH wt_sp_lower_fiq_entry
    WT_SPM_VECTOR_PANIC 11
    WT_SPM_VECTOR_PANIC 12
    WT_SPM_VECTOR_PANIC 13
    WT_SPM_VECTOR_PANIC 14
    WT_SPM_VECTOR_PANIC 15
