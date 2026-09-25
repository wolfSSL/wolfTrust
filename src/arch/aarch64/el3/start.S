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
#define HCR_EL2_RW      0x80000000
/* No EL2 traps: bits 13, 9 and 7:0 are RES1 (TZ/TSM too without SVE/SME). */
#define CPTR_EL2_INIT   0x22FF
/* RW | ST | EA | FIQ: Group 0 interrupts come to EL3 until the Secure world
 * runs (an FIQ whose target EL is below the current EL stays pending). */
#define SCR_EL3_INIT    0xC0C
/* SDD | SPD32 = disabled: Secure self-hosted debug off in both states. */
#define MDCR_EL3_INIT   0x18000
/* SPME | STE | NSPB = NSTB = enabled in Secure | TPM | TDA | TDOSA */
#define MDCR_EL3_DIRTY  0x3063640

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
    /* A warm reset re-clears .bss and then signals: report again on every
     * wake so the re-entered boot core counts this core too. */
9:  wfe
    strb    w3, [x2, x1]
    dsb     sy
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
#if defined(WT_EL3_EL2_DIRTY_PROBE) && (WT_EL3_EL2_DIRTY_PROBE == 1)
    /* Test only: stand in for a stage that left Secure counting, tracing,
     * profiling, and self-hosted debug open and PMU accesses trapped. */
    ldr     x0, =MDCR_EL3_DIRTY
    msr     MDCR_EL3, x0
#endif
    /* MDCR_EL3: no Secure-state PMU counting, tracing, or profiling, no
     * Secure self-hosted debug, no traps; the fields a missing PMU, SPE, or
     * TRBE leaves RES0 stay clear (wt_el3_mdcr_expected mirrors this). */
    mov     x0, #MDCR_EL3_INIT
    mrs     x1, ID_AA64DFR0_EL1
    ubfx    x2, x1, #8, #4
    cmp     x2, #6
    b.lo    3f
    cmp     x2, #0xf
    b.eq    3f
    orr     x0, x0, #(1 << 23)
3:  ubfx    x2, x1, #32, #4
    cbz     x2, 4f
    orr     x0, x0, #(2 << 12)
4:  ubfx    x2, x1, #44, #4
    cbz     x2, 5f
    orr     x0, x0, #(2 << 24)
5:  msr     MDCR_EL3, x0
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

    /* EL2 is unused but, when implemented, still applies to NS-EL1: give its
     * controls known values instead of whatever an earlier stage left. */
    mrs     x1, ID_AA64PFR0_EL1
    ubfx    x1, x1, #8, #4
    cbz     x1, 15f
#if defined(WT_EL3_EL2_DIRTY_PROBE) && (WT_EL3_EL2_DIRTY_PROBE == 1)
    /* Test only: stand in for a stage that left SMC trapped, a foreign
     * virtual MPIDR, and the EL2 GIC system-register interface off behind. */
    mov     x0, #HCR_EL2_RW
    orr     x0, x0, #(1 << 19)
    msr     HCR_EL2, x0
    mrs     x0, MPIDR_EL1
    eor     x0, x0, #0x100
    msr     VMPIDR_EL2, x0
#if defined(WT_GIC_VERSION) && (WT_GIC_VERSION == 3)
    msr     ICC_SRE_EL2, xzr
#endif
#endif
    mov     x0, #HCR_EL2_RW
    msr     HCR_EL2, x0
    msr     HSTR_EL2, xzr
    msr     VTTBR_EL2, xzr
    mrs     x0, MIDR_EL1
    msr     VPIDR_EL2, x0
    mrs     x0, MPIDR_EL1
    msr     VMPIDR_EL2, x0
    mov     x0, #CPTR_EL2_INIT
    mrs     x1, ID_AA64PFR0_EL1
    ubfx    x1, x1, #32, #4
    cbnz    x1, 10f
    orr     x0, x0, #(1 << 8)
10: mrs     x1, ID_AA64PFR1_EL1
    ubfx    x1, x1, #24, #4
    cbnz    x1, 11f
    orr     x0, x0, #(1 << 12)
11: msr     CPTR_EL2, x0
    /* MDCR_EL2: no traps; EL1 owns every PMU counter and any SPE/TRBE. */
    mov     x0, #0
    mrs     x1, ID_AA64DFR0_EL1
    ubfx    x2, x1, #8, #4
    cbz     x2, 12f
    cmp     x2, #0xf
    b.eq    12f
    mrs     x2, PMCR_EL0
    ubfx    x0, x2, #11, #5
12: ubfx    x2, x1, #32, #4
    cbz     x2, 13f
    orr     x0, x0, #(3 << 12)
13: ubfx    x2, x1, #44, #4
    cbz     x2, 14f
    orr     x0, x0, #(3 << 24)
14: msr     MDCR_EL2, x0
15:
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
    mov     x4, #HCR_EL2_RW
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
 * enter a saved world. Program SCR_EL3 (and HCR_EL2 = RW for a Normal world at
 * EL1; an EL2 world, SCR_EL3.HCE, owns HCR_EL2 and may run its EL1 in
 * AArch32), reset the EL3 stack (this never returns, so the handler's stack is
 * abandoned), load the full saved register file plus ELR and SPSR, then ERET.
 * The ISB before the ERET matches wt_el3_enter_ns. */
    .globl wt_el3_world_eret
wt_el3_world_eret:
    tbz     x1, #0, 1f
    tbnz    x1, #8, 1f
    mov     x2, #HCR_EL2_RW
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

#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
/* void wt_el3_a32_enter(uint64_t scr_el3, uintptr_t entry, const uint64_t* r):
 * ERET to AArch32 Secure EL1 SVC mode at entry with r[0..7] in R0-R7, until
 * wt_el3_a32_leave, run from the handler of one of its SMCs, returns here. */
    .globl wt_el3_a32_enter
wt_el3_a32_enter:
    ldr     x9, =g_wt_el3_a32_ctx
    stp     x19, x20, [x9, #0]
    stp     x21, x22, [x9, #16]
    stp     x23, x24, [x9, #32]
    stp     x25, x26, [x9, #48]
    stp     x27, x28, [x9, #64]
    stp     x29, x30, [x9, #80]
    mov     x10, sp
    mrs     x11, SCR_EL3
    stp     x10, x11, [x9, #96]
    msr     SCR_EL3, x0
    msr     ELR_EL3, x1
    mov     x3, #0x1d3
    msr     SPSR_EL3, x3
    mov     x9, x2
    ldp     x0, x1, [x9, #0]
    ldp     x2, x3, [x9, #16]
    ldp     x4, x5, [x9, #32]
    ldp     x6, x7, [x9, #48]
    isb
    eret

/* void wt_el3_a32_leave(void): abandon the handler's stack and return from
 * wt_el3_a32_enter with its SCR_EL3 and callee-saved registers back. */
    .globl wt_el3_a32_leave
wt_el3_a32_leave:
    ldr     x9, =g_wt_el3_a32_ctx
    ldp     x10, x11, [x9, #96]
    msr     SCR_EL3, x11
    isb
    mov     sp, x10
    ldp     x19, x20, [x9, #0]
    ldp     x21, x22, [x9, #16]
    ldp     x23, x24, [x9, #32]
    ldp     x25, x26, [x9, #48]
    ldp     x27, x28, [x9, #64]
    ldp     x29, x30, [x9, #80]
    ret

/* A32: SMC with the ids in R0, R4, R5 (results kept in R8-R10), then the
 * done id in R6. */
    .balign 4
    .globl wt_el3_a32_stub
wt_el3_a32_stub:
    .word   0xe1600070              /* smc #0 */
    .word   0xe1a08000              /* mov r8, r0 */
    .word   0xe1a00004              /* mov r0, r4 */
    .word   0xe1600070              /* smc #0 */
    .word   0xe1a09000              /* mov r9, r0 */
    .word   0xe1a00005              /* mov r0, r5 */
    .word   0xe1600070              /* smc #0 */
    .word   0xe1a0a000              /* mov r10, r0 */
    .word   0xe1a00006              /* mov r0, r6 */
    .word   0xe1600070              /* smc #0 */
    .word   0xeafffffe              /* b . */
#endif

    .bss
    .balign 16
g_wt_el3_exit_block:
    .skip   16
#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
    .balign 16
g_wt_el3_a32_ctx:
    .skip   112
#endif
