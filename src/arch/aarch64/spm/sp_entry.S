/* sp_entry.S
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

/* S-EL0 partition entry and exit. wt_sp_el0_enter parks the S-EL1 caller's
 * callee-saved state, loads a wt_trap_frame into the EL0 register state and
 * ERETs; a lower-EL synchronous exception lands in wt_sp_lower_sync_entry,
 * which builds the frame for wt_spm_lower_sync and either ERETs back into
 * the partition or, when the handler unwinds through wt_sp_el0_leave,
 * resumes the parked S-EL1 caller. Frame layout: include/wolftrust/arch/
 * aarch64/context.h (x0..x30, SP_EL0, ELR, SPSR, ESR, FAR; 288 bytes). */

#define FRAME_SP_EL0 248
#define FRAME_ELR    256
#define FRAME_SPSR   264
#define FRAME_ESR    272
#define FRAME_FAR    280
#define FRAME_SIZE   288

    .section .bss.g_wt_sp_kernel_ctx, "aw", %nobits
    .balign 16
g_wt_sp_kernel_ctx:
    .skip   112

    .section .text.wt_sp_el0_enter, "ax"
    .globl wt_sp_el0_enter
wt_sp_el0_enter:
    adrp    x1, g_wt_sp_kernel_ctx
    add     x1, x1, :lo12:g_wt_sp_kernel_ctx
    stp     x19, x20, [x1, #0]
    stp     x21, x22, [x1, #16]
    stp     x23, x24, [x1, #32]
    stp     x25, x26, [x1, #48]
    stp     x27, x28, [x1, #64]
    stp     x29, x30, [x1, #80]
    mov     x2, sp
    str     x2, [x1, #96]
    ldr     x1, [x0, #FRAME_SP_EL0]
    msr     SP_EL0, x1
    ldr     x1, [x0, #FRAME_ELR]
    msr     ELR_EL1, x1
    ldr     x1, [x0, #FRAME_SPSR]
    msr     SPSR_EL1, x1
    ldp     x2, x3, [x0, #16]
    ldp     x4, x5, [x0, #32]
    ldp     x6, x7, [x0, #48]
    ldp     x8, x9, [x0, #64]
    ldp     x10, x11, [x0, #80]
    ldp     x12, x13, [x0, #96]
    ldp     x14, x15, [x0, #112]
    ldp     x16, x17, [x0, #128]
    ldp     x18, x19, [x0, #144]
    ldp     x20, x21, [x0, #160]
    ldp     x22, x23, [x0, #176]
    ldp     x24, x25, [x0, #192]
    ldp     x26, x27, [x0, #208]
    ldp     x28, x29, [x0, #224]
    ldr     x30, [x0, #240]
    ldp     x0, x1, [x0, #0]
    eret

    .section .text.wt_sp_el0_leave, "ax"
    .globl wt_sp_el0_leave
wt_sp_el0_leave:
    adrp    x1, g_wt_sp_kernel_ctx
    add     x1, x1, :lo12:g_wt_sp_kernel_ctx
    ldp     x19, x20, [x1, #0]
    ldp     x21, x22, [x1, #16]
    ldp     x23, x24, [x1, #32]
    ldp     x25, x26, [x1, #48]
    ldp     x27, x28, [x1, #64]
    ldp     x29, x30, [x1, #80]
    ldr     x2, [x1, #96]
    mov     sp, x2
    ret

    .section .text.wt_sp_lower_sync_entry, "ax"
    .globl wt_sp_lower_sync_entry
wt_sp_lower_sync_entry:
    sub     sp, sp, #FRAME_SIZE
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]
    mrs     x0, SP_EL0
    str     x0, [sp, #FRAME_SP_EL0]
    mrs     x0, ELR_EL1
    str     x0, [sp, #FRAME_ELR]
    mrs     x0, SPSR_EL1
    str     x0, [sp, #FRAME_SPSR]
    mrs     x0, ESR_EL1
    str     x0, [sp, #FRAME_ESR]
    mrs     x0, FAR_EL1
    str     x0, [sp, #FRAME_FAR]
    mov     x0, sp
    bl      wt_spm_lower_sync
    ldr     x0, [sp, #FRAME_SPSR]
    msr     SPSR_EL1, x0
    ldr     x0, [sp, #FRAME_ELR]
    msr     ELR_EL1, x0
    ldr     x0, [sp, #FRAME_SP_EL0]
    msr     SP_EL0, x0
    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #FRAME_SIZE
    eret

/* Lower-EL FIQ (a Group 0 interrupt while an S-EL0 partition runs): build the
 * same frame the sync path does and call wt_spm_lower_fiq. It returns here to
 * resume the partition when nothing preempts it; when the tick preempts, it
 * unwinds through wt_sp_el0_leave to the scheduler and never comes back. */
    .section .text.wt_sp_lower_fiq_entry, "ax"
    .globl wt_sp_lower_fiq_entry
wt_sp_lower_fiq_entry:
    sub     sp, sp, #FRAME_SIZE
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]
    mrs     x0, SP_EL0
    str     x0, [sp, #FRAME_SP_EL0]
    mrs     x0, ELR_EL1
    str     x0, [sp, #FRAME_ELR]
    mrs     x0, SPSR_EL1
    str     x0, [sp, #FRAME_SPSR]
    mrs     x0, ESR_EL1
    str     x0, [sp, #FRAME_ESR]
    mrs     x0, FAR_EL1
    str     x0, [sp, #FRAME_FAR]
    mov     x0, sp
    bl      wt_spm_lower_fiq
    ldr     x0, [sp, #FRAME_SPSR]
    msr     SPSR_EL1, x0
    ldr     x0, [sp, #FRAME_ELR]
    msr     ELR_EL1, x0
    ldr     x0, [sp, #FRAME_SP_EL0]
    msr     SP_EL0, x0
    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #FRAME_SIZE
    eret

/* S-EL0 spinner for the preemption self-test: loops until a tick preempts it. */
    .section .text.wt_sp_spin, "ax"
    .globl wt_sp_spin
wt_sp_spin:
1:  b       1b

/* S-EL0 probe for the boot self-test: yield twice with distinct tokens. */
    .section .text.wt_sp_el0_probe, "ax"
    .globl wt_sp_el0_probe
wt_sp_el0_probe:
    mov     w0, #0x0101
    movk    w0, #0xC380, lsl #16
    mov     x1, #0x5A
    svc     #0
    mov     w0, #0x0101
    movk    w0, #0xC380, lsl #16
    mov     x1, #0xA5
    svc     #0
1:  b       1b

/* S-EL0 FF-A echo partition: FFA_MSG_WAIT to signal init and wait, then for
 * each delivered direct request (x0=REQ fid, x1=sender/receiver ids, x3=first
 * payload word) reply with FFA_MSG_SEND_DIRECT_RESP32, swapping the ids and
 * complementing the payload word. A delivered FFA_INTERRUPT (x0) is a Secure
 * interrupt: acknowledge it by returning to waiting. The response SVC also
 * waits for the next request, so control resumes at label 1 with it. */
    .section .text.wt_sp_ffa_echo, "ax"
    .globl wt_sp_ffa_echo
wt_sp_ffa_echo:
0:  movz    w0, #0x006B                 /* FFA_MSG_WAIT (0x8400006B) */
    movk    w0, #0x8400, lsl #16
    svc     #0
1:  movz    w4, #0x0062                 /* FFA_INTERRUPT (0x84000062) */
    movk    w4, #0x8400, lsl #16
    cmp     w0, w4
    b.eq    0b                          /* interrupt: acknowledge and re-wait */
    lsr     x2, x1, #16                 /* original sender */
    ubfx    x1, x1, #0, #16             /* original receiver = our id */
    orr     x1, x2, x1, lsl #16         /* reply w1 = our_id<<16 | sender */
    mvn     x3, x3                      /* echo ~payload */
    mov     x2, #0                      /* w2 SBZ */
    movz    w0, #0x0070                 /* FFA_MSG_SEND_DIRECT_RESP32 (0x84000070) */
    movk    w0, #0x8400, lsl #16
    svc     #0
    b       1b
