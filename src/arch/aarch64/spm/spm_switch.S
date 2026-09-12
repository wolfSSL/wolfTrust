/* spm_switch.S
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

/* Cooperative S-EL1 coroutine switch: save the callee-saved state of the
 * running context, hand its stack pointer back through *x0, load the
 * target's, and resume it. The AAPCS64 caller-saved registers are already
 * dead across a call, so only x19-x30 and SP need preserving. */

    .section .text.wt_co_arch_switch, "ax"
    .globl wt_co_arch_switch
/* void wt_co_arch_switch(uintptr_t* save_from_sp, uintptr_t to_sp) */
wt_co_arch_switch:
    sub     sp, sp, #96
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    mov     x2, sp
    str     x2, [x0]
    mov     sp, x1
    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    add     sp, sp, #96
    ret

/* First switch-in lands here with x19 = entry, x20 = arg (see
 * wt_co_arch_init_stack). A coroutine entry must never return. */
    .section .text.wt_co_trampoline, "ax"
    .globl wt_co_trampoline
wt_co_trampoline:
    mov     x0, x20
    blr     x19
    brk     #0x52
1:  b       1b
