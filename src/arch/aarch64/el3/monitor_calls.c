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

/* EL3 vector dispatch: FF-A calls from the Secure world go to the SPMD
 * handlers, the OEM-range test calls to the monitor calls, the secure timer
 * FIQ to the tick handler; everything else is a fault. */

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
#endif

uint64_t wt_el3_monitor_call(uint32_t fid, uint64_t arg)
{
    uint64_t result = WT_MON_NOT_SUPPORTED;

    switch (fid) {
        case WT_MON_FID_EXIT:
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

/* A Normal-world SMC: relayed to the SPMC, or PSCI/SMCCC/FF-A served here. */
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
    /* PSCI power management is served by the SPMD directly (WT-FFM-0067),
     * with the SMCCC version and feature queries. */
    if (wt_psci_fid_in_range(fid) || (fid == WT_SMCCC_VERSION) ||
        (fid == WT_SMCCC_ARCH_FEATURES)) {
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
        wt_ffa_reply_clear_ext(fid, frame->x);
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
    if ((kind == WT_EL3_VEC_LOWER64_SYNC) &&
        ((ec == WT_ESR_EC_SMC64) || (ec == WT_ESR_EC_SMC32))) {
        /* An SMC32 call carries W1-W7 only (SMCCC 3.1): no handler, and no
         * world a call is relayed to, sees the caller's upper halves. */
        wt_ffa_regs_normalize(frame->x);
        if ((wt_read_scr_el3() & WT_SCR_NS) != 0u) {
            ns_smc(frame);
            return;
        }
        secure_smc(frame);
        return;
    }
    wt_el3_fault(kind, esr, wt_read_far_el3(), wt_read_elr_el3());
}
