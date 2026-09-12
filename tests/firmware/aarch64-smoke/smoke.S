/* smoke.S
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

/* EL3 entry of the QEMU AArch64 smoke: refuse anything but EL3, park every
 * core whose MPIDR affinity is not zero, and hand core 0 to smoke_main. */

    .section .text.entry, "ax"
    .globl _start
_start:
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #3
    b.ne    wrong_el
    mrs     x0, MPIDR_EL1
    and     x1, x0, #0xffffff
    cbz     x1, primary
    and     x1, x0, #3
    ldr     x2, =g_parked
    mov     w3, #1
    strb    w3, [x2, x1]
    dsb     sy
    sev
1:  wfe
    b       1b

primary:
    ldr     x0, =__stack_top
    mov     sp, x0
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
2:  cmp     x0, x1
    b.hs    3f
    str     xzr, [x0], #8
    b       2b
3:  bl      smoke_main
    mov     x0, #0
    b       smoke_exit

wrong_el:
    mov     x0, #2
    b       smoke_exit

/* Semihosting SYS_EXIT: x0 = exit code, reported through QEMU's exit status. */
    .text
    .globl smoke_exit
smoke_exit:
    ldr     x1, =g_exit_block
    ldr     x2, =0x20026
    str     x2, [x1]
    str     x0, [x1, #8]
    mov     x0, #0x18
    hlt     #0xf000
4:  wfi
    b       4b

    .bss
    .balign 16
g_exit_block:
    .skip   16
