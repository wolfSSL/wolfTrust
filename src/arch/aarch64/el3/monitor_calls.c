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
#include "wolftrust/arch/aarch64/sysreg.h"

volatile uint32_t g_wt_el3_tick_intid;

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

/* An SMC taken at the NS physical instance (SCR_EL3.NS was set): FF-A calls go
 * to the SPMD NS dispatch, everything else is an SMCCC unknown function for
 * now (PSCI lands in a later B3 slice). */
static void ns_smc(wt_el3_frame_t* frame)
{
    wt_ffa_regs_t regs;
    uint32_t fid = (uint32_t)frame->x[0];
    unsigned int i;

    if (wt_ffa_fid_in_range(fid)) {
        for (i = 0u; i < 8u; i++) {
            regs.x[i] = frame->x[i];
        }
        wt_ffa_spmd_ns_call(&regs);
        for (i = 0u; i < 8u; i++) {
            frame->x[i] = regs.x[i];
        }
        return;
    }
    frame->x[0] = WT_MON_NOT_SUPPORTED;
}

static void secure_smc(wt_el3_frame_t* frame)
{
    wt_ffa_regs_t regs;
    uint32_t fid = (uint32_t)frame->x[0];
    unsigned int i;

    if (fid == WT_FFA_CONSOLE_LOG64) {
        /* Characters span x2-x17: use the saved frame, not the 8-register copy. */
        wt_ffa_spmd_console_call(frame->x, 1u);
        return;
    }
    if (wt_ffa_fid_in_range(fid)) {
        for (i = 0u; i < 8u; i++) {
            regs.x[i] = frame->x[i];
        }
        wt_ffa_spmd_secure_call(&regs);
        for (i = 0u; i < 8u; i++) {
            frame->x[i] = regs.x[i];
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
    esr = wt_read_esr_el3();
    ec = WT_ESR_EC(esr);
    if ((kind == WT_EL3_VEC_LOWER64_SYNC) &&
        ((ec == WT_ESR_EC_SMC64) || (ec == WT_ESR_EC_SMC32))) {
        if ((wt_read_scr_el3() & WT_SCR_NS) != 0u) {
            ns_smc(frame);
            return;
        }
        secure_smc(frame);
        return;
    }
    wt_el3_fault(kind, esr, wt_read_far_el3(), wt_read_elr_el3());
}
