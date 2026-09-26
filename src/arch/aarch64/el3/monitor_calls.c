/* monitor_calls.c
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

/* EL3 vector dispatch: the SMCCC Arm Architecture Calls are answered for
 * either world, FF-A calls from the Secure world go to the SPMD handlers, the
 * OEM-range test calls to the monitor calls, the secure timer FIQ to the tick
 * handler; everything else is a fault. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/psci.h"
#include "wolftrust/arch/aarch64/sysreg.h"

volatile uint32_t g_wt_el3_tick_intid;

#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
#if defined(WT_GIC_VERSION) && (WT_GIC_VERSION == 3)
WT_SYSREG_READ(icc_igrpen1_el3, "ICC_IGRPEN1_EL3")
WT_SYSREG_WRITE(icc_igrpen1_el3, "ICC_IGRPEN1_EL3")
#define WT_ICC_IGRPEN1_EL3_GRP1NS 1u

static void test_ns_group(uint64_t on)
{
    uint64_t value = wt_read_icc_igrpen1_el3();

    value = (on != 0u) ? (value | WT_ICC_IGRPEN1_EL3_GRP1NS)
                       : (value & ~(uint64_t)WT_ICC_IGRPEN1_EL3_GRP1NS);
    wt_write_icc_igrpen1_el3(value);
    wt_isb();
}
#else
/* The GICv2 CPU interface already signals Group 1 to the Secure world. */
static void test_ns_group(uint64_t on)
{
    (void)on;
}
#endif

WT_SYSREG_READ(id_aa64pfr0_el1, "ID_AA64PFR0_EL1")
#define WT_EL3_A32_PROBE_DONE 0x830000FFu

void wt_el3_a32_enter(uint64_t scr_el3, uintptr_t entry, const uint64_t* r);
void wt_el3_a32_leave(void) __attribute__((noreturn));
extern const uint32_t wt_el3_a32_stub[];
static uint32_t g_a32_result[3];
static uint32_t g_a32_active;

/* The stub's first three SMCs left their results in R8-R10. */
static void a32_probe_done(const wt_el3_frame_t* frame)
{
    g_a32_active = 0u;
    g_a32_result[0] = (uint32_t)frame->x[8];
    g_a32_result[1] = (uint32_t)frame->x[9];
    g_a32_result[2] = (uint32_t)frame->x[10];
    wt_el3_a32_leave();
}

/* Drop to an AArch32 Secure EL1 stub, SCR_EL3.RW clear and its stage 1 off,
 * so its SMCs take the lower-AArch32 vector, and report their answers. */
static void a32_probe(void)
{
    uint64_t r[8];
    uint64_t sctlr;
    unsigned int i;

    if (((wt_read_id_aa64pfr0_el1() >> 4) & 0xFu) != 2u) {
        wt_el3_puts("[EL3] a32 vector probe: no AArch32 EL1\r\n");
        return;
    }
    for (i = 0u; i < 8u; i++) {
        r[i] = 0u;
    }
    r[0] = WT_SMCCC_VERSION;
    r[4] = WT_PSCI_AFFINITY_INFO64;
    r[5] = WT_PSCI_VERSION;
    r[6] = WT_EL3_A32_PROBE_DONE;
    sctlr = wt_read_sctlr_el1();
    wt_write_sctlr_el1(sctlr & ~(uint64_t)1u);
    wt_isb();
    g_a32_active = 1u;
    wt_el3_a32_enter((uint64_t)(WT_SCR_EL3_SECURE & ~WT_SCR_RW),
                     (uintptr_t)wt_el3_a32_stub, r);
    wt_write_sctlr_el1(sctlr);
    wt_isb();
    wt_el3_puts("[EL3] a32 vector smc version=0x");
    wt_el3_puthex(g_a32_result[0], 8u);
    wt_el3_puts(" smc64=0x");
    wt_el3_puthex(g_a32_result[1], 8u);
    wt_el3_puts(" psci=0x");
    wt_el3_puthex(g_a32_result[2], 8u);
    wt_el3_puts("\r\n");
}
#endif

uint64_t wt_el3_monitor_call(uint32_t fid, uint64_t arg)
{
    uint64_t result = WT_MON_NOT_SUPPORTED;

    switch (fid) {
        case WT_MON_FID_EXIT:
#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
            a32_probe();
#endif
            wt_el3_puts("[BKPT] imm=0x");
            wt_el3_puthex(arg & 0xFFu, 2u);
            wt_el3_puts("\r\n");
            if ((arg & 0xFFu) == WT_MON_EXIT_SUCCESS) {
                wt_el3_puts("[EXPECT BKPT] Success\r\n");
            }
            wt_platform_console_flush();
            wt_el3_semihost_exit(((arg & 0xFFu) == WT_MON_EXIT_SUCCESS)
                                     ? 0u : (arg & 0xFFu));
            break;
        case WT_MON_FID_PANIC:
            wt_el3_puts("[EL3] panic code=0x");
            wt_el3_puthex(arg, 8u);
            wt_el3_puts("\r\n");
            wt_platform_console_flush();
            wt_el3_semihost_exit(WT_MON_EXIT_PANIC);
            break;
        case WT_MON_FID_SYSTEM_RESET:
            wt_el3_system_reset("mon");
            break;
#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
        case WT_MON_FID_TEST_NS_GROUP:
            test_ns_group(arg);
            result = 0u;
            break;
#endif
        default:
            break;
    }
    return result;
}

static void wt_el3_fiq(void)
{
    uint32_t intid = wt_gic->ack_group0();

    if (intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_el3_timer_disable();
    }
    if (intid != WT_GIC_INTID_SPURIOUS) {
        g_wt_el3_tick_intid = intid;
        wt_gic->eoi_group0(intid);
    }
}

/* A Secure interrupt taken while the Normal world runs (SCR_EL3.FIQ routes it to
 * EL3 as a lower-EL FIQ) stays pending in the GIC: the SPMC, which alone
 * services the GIC, acknowledges it after FFA_INTERRUPT (9.1, 12.4.1 item 3)
 * and yields the Normal world back afterwards. */
static void ns_fiq(wt_el3_frame_t* frame)
{
    wt_el3_puts("[EL3] ns preempted\r\n");
    wt_platform_console_flush();
    wt_el3_world_preempt_to_secure(frame);
}

/* SMCCC_VERSION and SMCCC_ARCH_FEATURES (DEN0028 7.2, 7.3), mandatory from
 * SMCCC 1.1 whichever world calls; x4-x17 are preserved. */
static int arch_call(wt_el3_frame_t* frame)
{
    uint32_t fid = (uint32_t)frame->x[0];
    uint32_t query = (uint32_t)frame->x[1];

    if (fid == WT_SMCCC_VERSION) {
        frame->x[0] = WT_SMCCC_VERSION_1_2;
    }
    else if (fid == WT_SMCCC_ARCH_FEATURES) {
        /* No Arm Architecture Service call beyond these two is offered. */
        frame->x[0] = ((query == WT_SMCCC_VERSION) ||
                       (query == WT_SMCCC_ARCH_FEATURES)) ?
                          0u : (uint64_t)(uint32_t)WT_SMCCC_NOT_SUPPORTED;
    }
    else {
        return 0;
    }
    frame->x[1] = 0u;
    frame->x[2] = 0u;
    frame->x[3] = 0u;
    return 1;
}

/* Only an AArch32 EL directly below EL3 takes this vector, which SCR_EL3.RW=1
 * rules out. Its SMC is still answered: the Arm Architecture Calls, and every
 * other id unknown, as the PSCI and FF-A world switches assume AArch64. */
static void lower32_smc(wt_el3_frame_t* frame)
{
    wt_ffa_regs_normalize(frame->x);
    if (arch_call(frame) == 0) {
        frame->x[0] = WT_MON_NOT_SUPPORTED;
    }
}

/* A Normal-world SMC: relayed to the SPMC, or PSCI/FF-A served here. */
static void ns_smc(wt_el3_frame_t* frame)
{
    wt_ffa_regs_t regs;
    uint32_t fid = (uint32_t)frame->x[0];
    unsigned int i;

    wt_ffa_spmd_ns_note(fid);
    /* Discovery and guest-to-SP messaging need the SPMC (the SPMD has no
     * manifest): forward the call and run the Secure world. */
    if (wt_ffa_spmd_ns_forwards(fid)) {
        if (wt_ffa_spmd_ns_forward(frame->x) != 0) {
            wt_el3_world_forward_to_secure(frame);
        }
        return;
    }
    /* PSCI power management is served by the SPMD directly (WT-FFM-0067). */
    if (wt_psci_fid_in_range(fid)) {
        for (i = 0u; i < 8u; i++) {
            regs.x[i] = frame->x[i];
        }
        wt_psci_ns_call(&regs);
        for (i = 0u; i < 8u; i++) {
            frame->x[i] = regs.x[i];
        }
        return;
    }
    if (wt_ffa_fid_in_range(fid)) {
        for (i = 0u; i < 8u; i++) {
            regs.x[i] = frame->x[i];
        }
        wt_ffa_spmd_ns_call(&regs);
        for (i = 0u; i < 8u; i++) {
            frame->x[i] = regs.x[i];
        }
        wt_ffa_reply_clear_ext(fid, frame->x);
        return;
    }
    frame->x[0] = WT_MON_NOT_SUPPORTED;
}

static void secure_smc(wt_el3_frame_t* frame)
{
    wt_ffa_regs_t regs;
    uint32_t fid = (uint32_t)frame->x[0];
    unsigned int pending;
    unsigned int i;

    wt_ffa_spmd_secure_note(fid);
    /* The SPMC's answer to a paused Normal world: its reply to a forwarded call
     * (deliver x0-x7) or its yield after handling a preemption (resume as-is). */
    pending = wt_el3_world_ns_pending();
    if ((pending == WT_NS_PENDING_REPLY) && (wt_ffa_spmd_is_ns_reply(fid) != 0)) {
        wt_ffa_spmd_ns_reply(frame->x);
        wt_el3_world_return_to_ns(frame);
        return;
    }
    if ((pending == WT_NS_PENDING_RESUME) && (wt_ffa_spmd_is_ns_resume(fid) != 0)) {
        wt_el3_world_resume_ns(frame);
        return;
    }
    if (fid == WT_FFA_CONSOLE_LOG64) {
        /* Characters span x2-x17: use the saved frame, not the 8-register copy. */
        wt_ffa_spmd_console_call(frame->x, 1u);
        return;
    }
    if (wt_ffa_fid_in_range(fid)) {
        for (i = 0u; i < 8u; i++) {
            regs.x[i] = frame->x[i];
        }
        if (wt_ffa_spmd_secure_call(&regs) == WT_SPMD_ACTION_LAUNCH) {
            /* SPMC init complete: turn on the Normal world (or exit). */
            wt_el3_world_launch_ns(frame);
            return;
        }
        for (i = 0u; i < 8u; i++) {
            frame->x[i] = regs.x[i];
        }
        /* 11.2: the SPMC's hypcall completes over ERET, x8-x17 MBZ. */
        for (i = 8u; i < WT_FFA_MSG_REGS_EXT; i++) {
            frame->x[i] = 0u;
        }
        return;
    }
    frame->x[0] = wt_el3_monitor_call(fid, frame->x[1]);
}

void wt_el3_exception(uint64_t kind, wt_el3_frame_t* frame)
{
    uint64_t esr;
    uint32_t ec;

    if (kind == WT_EL3_VEC_CUR_SPX_FIQ) {
        wt_el3_fiq();
        return;
    }
    /* A Secure interrupt taken while the Normal world runs preempts it (Ch.9). */
    if (kind == WT_EL3_VEC_LOWER64_FIQ) {
        ns_fiq(frame);
        return;
    }
    esr = wt_read_esr_el3();
    ec = WT_ESR_EC(esr);
    if ((kind == WT_EL3_VEC_LOWER32_SYNC) && (ec == WT_ESR_EC_SMC32)) {
#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
        if ((g_a32_active != 0u) &&
            ((uint32_t)frame->x[0] == WT_EL3_A32_PROBE_DONE)) {
            a32_probe_done(frame);
        }
#endif
        lower32_smc(frame);
        return;
    }
    /* EC SMC32 is an SMC from AArch32, an EL1 beneath an NS-EL2 payload; it
     * still takes the lower-AArch64 vector, which follows EL2's state. */
    if ((kind == WT_EL3_VEC_LOWER64_SYNC) &&
        ((ec == WT_ESR_EC_SMC64) || (ec == WT_ESR_EC_SMC32))) {
        /* SMCCC 2.7, 5.2: an SMC64 id from AArch32 is unknown. */
        if ((ec == WT_ESR_EC_SMC32) &&
            (((uint32_t)frame->x[0] & 0x40000000u) != 0u)) {
            frame->x[0] = WT_MON_NOT_SUPPORTED;
            return;
        }
        /* An SMC32 call carries W1-W7 only (SMCCC 3.1): no handler, and no
         * world a call is relayed to, sees the caller's upper halves. */
        wt_ffa_regs_normalize(frame->x);
        if (arch_call(frame) != 0) {
            return;
        }
        if ((wt_read_scr_el3() & WT_SCR_NS) != 0u) {
            ns_smc(frame);
            return;
        }
        secure_smc(frame);
        return;
    }
    wt_el3_fault(kind, esr, wt_read_far_el3(), wt_read_elr_el3());
}
