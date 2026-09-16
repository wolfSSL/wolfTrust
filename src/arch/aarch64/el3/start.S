/* start.S
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

/* EL3 reset entry: park every core but the boot core, set up EL3 with the
 * MMU and caches off, initialize the image, and call wt_el3_main. */

#define SCTLR_EL3_INIT  (0x30C50830 | (1 << 12) | (1 << 3))
#define CNTHCTL_EL2_INIT 0x3
/* RW | ST | EA | FIQ: Group 0 interrupts come to EL3 until the Secure world
 * runs (an FIQ whose target EL is below the current EL stays pending). */
#define SCR_EL3_INIT    0xC0C

    .section .el3.text.entry, "ax"
    .globl wt_el3_start
wt_el3_start:
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #3
    b.ne    wrong_el
    mrs     x0, MPIDR_EL1
    and     x1, x0, #0xffffff
    cbz     x1, primary

    /* Secondary: report only after the boot core has cleared .bss. */
    ldr     x2, =g_wt_el3_ready
7:  ldr     w3, [x2]
    cbnz    w3, 8f
    wfe
    b       7b
8:  and     x1, x0, #3
    ldr     x2, =g_wt_el3_parked
    mov     w3, #1
    strb    w3, [x2, x1]
    dsb     sy
    sev
9:  wfe
    b       9b

primary:
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x5, #0
    mov     x6, #0
    mov     x7, #0
    mov     x8, #0
    mov     x9, #0
    mov     x10, #0
    mov     x11, #0
    mov     x12, #0
    mov     x13, #0
    mov     x14, #0
    mov     x15, #0
    mov     x16, #0
    mov     x17, #0
    mov     x18, #0
    mov     x19, #0
    mov     x20, #0
    mov     x21, #0
    mov     x22, #0
    mov     x23, #0
    mov     x24, #0
    mov     x25, #0
    mov     x26, #0
    mov     x27, #0
    mov     x28, #0
    mov     x29, #0
    mov     x30, #0

    msr     DAIFSet, #0xf
    ldr     x0, =wt_el3_vectors
    msr     VBAR_EL3, x0
    mov     x0, #SCR_EL3_INIT
    msr     SCR_EL3, x0
    msr     SPSel, #1
    ldr     x0, =__el3_stack_top
    mov     sp, x0

    msr     CPTR_EL3, xzr
    tlbi    alle3
    ic      iallu
    dsb     sy
    isb
    ldr     x0, =SCTLR_EL3_INIT
    msr     SCTLR_EL3, x0
    dsb     sy
    isb

#if !defined(WT_PORT_CNTFRQ_KEEP) || (WT_PORT_CNTFRQ_KEEP == 0)
    ldr     x0, =WT_PORT_CNTFRQ_HZ
    msr     CNTFRQ_EL0, x0
#endif
    msr     CNTVOFF_EL2, xzr
    mov     x0, #CNTHCTL_EL2_INIT
    msr     CNTHCTL_EL2, x0

    ldr     x0, =__data_lma
    ldr     x1, =__data_start
    ldr     x2, =__data_end
1:  cmp     x1, x2
    b.hs    2f
    ldr     x3, [x0], #8
    str     x3, [x1], #8
    b       1b
2:  ldr     x0, =__bss_start
    ldr     x1, =__bss_end
3:  cmp     x0, x1
    b.hs    4f
    str     xzr, [x0], #8
    b       3b
4:  ldr     x0, =g_wt_el3_ready
    mov     w1, #1
    str     w1, [x0]
    dsb     sy
    sev
    bl      wt_el3_main
    b       halt

wrong_el:
    mov     x0, #2
    b       wt_el3_semihost_exit

halt:
    wfi
    b       halt

/* void wt_el3_semihost_exit(uint64_t code): SYS_EXIT through hlt #0xf000. */
    .section .el3.text, "ax"
    .globl wt_el3_semihost_exit
wt_el3_semihost_exit:
    ldr     x1, =g_wt_el3_exit_block
    ldr     x2, =0x20026
    str     x2, [x1]
    str     x0, [x1, #8]
    mov     x0, #0x18
    hlt     #0xf000
    b       halt

/* void wt_el3_enter_secure_el1(void (*entry)(void), uintptr_t stack_top,
 *                              uint64_t x0_arg): x0_arg reaches S-EL1 in x0. */
    .globl wt_el3_enter_secure_el1
wt_el3_enter_secure_el1:
    msr     SP_EL1, x1
    msr     ELR_EL3, x0
    mov     x3, #0x3c5
    msr     SPSR_EL3, x3
    mov     x3, #0xc08
    msr     SCR_EL3, x3
    mov     x0, x2
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    isb
    eret

/* void wt_el3_enter_ns(void (*entry)(void), uintptr_t sp, uint64_t x0_arg):
 * drop to NS-EL1. SCR_EL3 = NS|FIQ|EA|RW|ST (0xc0d): a Secure interrupt taken
 * while the Normal world runs traps to the SPMD, so it can preempt NS (Ch.9).
 * EL2 is implemented on these machines, so HCR_EL2.RW selects the EL1 register
 * width; set it for AArch64 or the ERET is an illegal state change. */
    .globl wt_el3_enter_ns
wt_el3_enter_ns:
    mrs     x4, HCR_EL2
    mov     x5, #1
    lsl     x5, x5, #31
    orr     x4, x4, x5
    msr     HCR_EL2, x4
    msr     SP_EL1, x1
    msr     ELR_EL3, x0
    mov     x3, #0x3c5
    msr     SPSR_EL3, x3
    mov     x3, #0xc0d
    msr     SCR_EL3, x3
    mov     x0, x2
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    isb
    eret

/* void wt_el3_world_eret(const wt_el3_frame_t* frame, uint64_t scr_el3):
 * enter a saved world. Program SCR_EL3 (and HCR_EL2.RW for a Normal-world
 * return so EL1 is AArch64), reset the EL3 stack (this never returns, so the
 * handler's stack is abandoned), load the full saved register file plus ELR and
 * SPSR, then ERET. The ISB before the ERET matches wt_el3_enter_ns. */
    .globl wt_el3_world_eret
wt_el3_world_eret:
    tbz     x1, #0, 1f
    mrs     x2, HCR_EL2
    mov     x3, #1
    lsl     x3, x3, #31
    orr     x2, x2, x3
    msr     HCR_EL2, x2
1:  msr     SCR_EL3, x1
    ldr     x2, [x0, #248]
    msr     ELR_EL3, x2
    ldr     x2, [x0, #256]
    msr     SPSR_EL3, x2
    ldr     x2, =__el3_stack_top
    mov     sp, x2
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
    ldr     x1, [x0, #8]
    ldr     x0, [x0, #0]
    isb
    eret

    .bss
    .balign 16
g_wt_el3_exit_block:
    .skip   16
