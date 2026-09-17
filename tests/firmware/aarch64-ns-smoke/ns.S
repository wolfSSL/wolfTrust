/* ns.S
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

/* Normal-world payload entry: the SPMD ERETs here at NS-EL1. Set the stack,
 * copy .data from its pristine load image, clear .bss, run ns_main, then exit
 * through semihosting so QEMU reports the run's status. */

    .section .text.entry, "ax"
    .globl _start
_start:
    ldr     x0, =__stack_top
    mov     sp, x0
    ldr     x0, =__data_load
    ldr     x1, =__data_start
    ldr     x2, =__data_end
5:  cmp     x1, x2
    b.hs    6f
    ldr     x3, [x0], #8
    str     x3, [x1], #8
    b       5b
6:  ldr     x0, =__bss_start
    ldr     x1, =__bss_end
1:  cmp     x0, x1
    b.hs    2f
    str     xzr, [x0], #8
    b       1b
2:  bl      ns_main
    mov     x0, #0
    b       ns_exit

/* Semihosting SYS_EXIT: x0 = exit code, reported through QEMU's exit status. */
    .globl ns_exit
ns_exit:
    ldr     x1, =g_exit_block
    ldr     x2, =0x20026
    str     x2, [x1]
    str     x0, [x1, #8]
    mov     x0, #0x18
    hlt     #0xf000
3:  wfi
    b       3b

#if defined(WT_NS_GUEST_SECRAM) || defined(WT_NS_GUEST_CONF)
/* Normal-world EL1 exception vectors: a Secure-RAM read (secramneg) or one of
 * the conformance suite's by-design client aborts lands here, so the guest
 * catches its own abort and answers it instead of hanging on an unset vector.
 * Every entry funnels to one handler. */
    .section .text
    .balign 0x800
    .globl _ns_vectbl
_ns_vectbl:
    .rept 16
    .balign 0x80
    b       _ns_abort
    .endr
_ns_abort:
    mrs     x0, esr_el1
    bl      ns_abort_report
4:  wfi
    b       4b
#endif

    .bss
    .balign 16
g_exit_block:
    .skip   16
