/* spm_svc_glue.c
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

/* Lower-EL synchronous exceptions at the SPMC: the Secure virtual instance
 * (SVC from an S-EL0 partition) and partition faults. Runs on the
 * bootstrap stack underneath the wt_co_arch_enter that started the
 * partition; blocking unwinds to it through wt_co_arch_leave. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/esr.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch.h"
#include "wolftrust/platform.h"
#include "wolftrust/sched/coroutine.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"

#include <stddef.h>
#include <stdint.h>

#define WT_ESR_EC_SVC64 0x15u

wt_trap_frame_t* volatile g_wt_spm_live_frame;
static uint64_t g_yield_token;

uint64_t wt_spm_yield_token(void)
{
    return g_yield_token;
}

static void report_partition_fault(const wt_trap_frame_t* frame)
{
    char line[80];

    (void)wt_esr_format(line, sizeof(line), 0u, frame->esr, frame->far);
    wt_el3_puts(line);
    wt_el3_puts("\r\n");
}

static void ffa_not_supported(wt_trap_frame_t* frame)
{
    frame->x[0] = WT_FFA_ERROR;
    frame->x[1] = 0u;
    frame->x[2] = (uint64_t)(uint32_t)WT_FFA_NOT_SUPPORTED;
}

void wt_spm_lower_sync(wt_trap_frame_t* frame)
{
    uint32_t ec = (uint32_t)(frame->esr >> 26) & 0x3Fu;
    uint32_t fid = (uint32_t)frame->x[0];
    wt_co_t* co = wt_co_current();

    g_wt_spm_live_frame = frame;
    g_wt_spm_trap_spsr = frame->spsr;
    g_wt_spm_handler_depth++;

    if (ec != WT_ESR_EC_SVC64) {
        report_partition_fault(frame);
        /* Route a partition fault through the core's restart policy; if it is
         * not a scheduled SP (e.g. the boot self-test) quarantine it here. */
        if (wt_spm_sp_fault(co) != WT_FFM_SUCCESS) {
            wt_co_mark_faulted(co);
        }
        g_wt_spm_live_frame = NULL;
        g_wt_spm_handler_depth = 0u;
        wt_sp_el0_leave();
    }

    if (fid == WT_SPM_SVC_FID_CALL) {
        wt_spm_call_t* call = (wt_spm_call_t*)(uintptr_t)frame->x[1];

        frame->x[0] = (uint64_t)(int64_t)wt_spm_dispatch_call(call, frame);
    }
    else if (fid == WT_SPM_SVC_FID_YIELD) {
        g_yield_token = frame->x[1];
        frame->x[0] = 0u;
        wt_co_block();
    }
    else {
        ffa_not_supported(frame);
    }

    g_wt_spm_handler_depth--;
    g_wt_spm_live_frame = NULL;
}
