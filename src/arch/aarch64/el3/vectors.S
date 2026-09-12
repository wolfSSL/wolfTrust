/* vectors.S
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

/* EL3 vector table: every slot saves the caller-visible registers and hands
 * its slot index to wt_el3_exception; the return value becomes x0. */

    .macro WT_VECTOR index
    .balign 0x80
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
    mrs     x0, ELR_EL3
    mrs     x1, SPSR_EL3
    stp     x30, x0, [sp, #160]
    str     x1, [sp, #176]
    mov     x0, #\index
    b       wt_el3_vector_common
    .endm

    .section .el3.vectors, "ax"
    .balign 0x800
    .globl wt_el3_vectors
wt_el3_vectors:
    WT_VECTOR 0
    WT_VECTOR 1
    WT_VECTOR 2
    WT_VECTOR 3
    WT_VECTOR 4
    WT_VECTOR 5
    WT_VECTOR 6
    WT_VECTOR 7
    WT_VECTOR 8
    WT_VECTOR 9
    WT_VECTOR 10
    WT_VECTOR 11
    WT_VECTOR 12
    WT_VECTOR 13
    WT_VECTOR 14
    WT_VECTOR 15

    .section .el3.text, "ax"
wt_el3_vector_common:
    ldp     x1, x2, [sp, #0]
    bl      wt_el3_exception
    str     x0, [sp, #0]
    ldr     x1, [sp, #176]
    ldp     x30, x0, [sp, #160]
    msr     ELR_EL3, x0
    msr     SPSR_EL3, x1
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
