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
#include "wolftrust/arch/aarch64/ffa_manifest.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/ffa_partinfo.h"
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
uint64_t g_wt_ffa_direct_resp[8];
volatile uint32_t g_wt_ffa_direct_resp_ready;

uint64_t wt_spm_yield_token(void)
{
    return g_yield_token;
}

static void ffa_error(wt_trap_frame_t* frame, int32_t code)
{
    frame->x[0] = WT_FFA_ERROR;
    frame->x[1] = 0u;
    frame->x[2] = (uint64_t)(uint32_t)code;
}

/* A partition's direct response: validate it at the Secure virtual instance,
 * keep it for the deliverer, and park the partition back in waiting. A
 * malformed response is returned to the partition as an error instead. */
static void ffa_direct_resp(wt_trap_frame_t* frame)
{
    unsigned int i;
    int ret = wt_ffa_direct_resp_check(frame->x, WT_FFA_INSTANCE_SECURE_VIRTUAL);

    if (ret != 0) {
        ffa_error(frame, (int32_t)ret);
        return;
    }
    for (i = 0u; i < 8u; i++) {
        g_wt_ffa_direct_resp[i] = frame->x[i];
    }
    g_wt_ffa_direct_resp_ready = 1u;
    wt_co_block();
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

static void ffa_success(wt_trap_frame_t* frame, uint64_t w2, uint64_t w3)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        frame->x[i] = 0u;
    }
    frame->x[0] = WT_FFA_SUCCESS32;
    frame->x[2] = w2;
    frame->x[3] = w3;
}

/* The configured partitions as FFA_PARTITION_INFO_GET source records: the FF-A
 * id follows creation order (0x8002 up), matching the ids the SPMC assigns. */
static wt_ffa_partinfo_entry_t g_partinfo[16];

/* FFA_PARTITION_INFO_GET (6.1): write a Table 6.1 descriptor for every
 * configured partition matching the UUID in w1-w4 into the RX buffer, and
 * return the match count in w2 and the descriptor size in w3. A Nil UUID lists
 * every partition (WT-FFA-0003). */
static void ffa_partition_info_get(wt_trap_frame_t* frame)
{
    const wt_ffa_partition_manifest_t* parts;
    size_t n;
    size_t i;
    unsigned int j;
    uint8_t uuid[16];
    uint32_t word;
    uint32_t count = 0u;
    uint32_t size = 0u;
    int ret;

    parts = wt_generated_ffa_partitions_get(&n);
    if ((parts == NULL) || (n > (sizeof(g_partinfo) / sizeof(g_partinfo[0])))) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    for (i = 0u; i < n; i++) {
        g_partinfo[i].id = (uint16_t)(WT_FFA_ID_SP_FIRST + i);
        g_partinfo[i].exec_contexts = (uint16_t)parts[i].execution_contexts;
        g_partinfo[i].properties = wt_ffa_partinfo_props(parts[i].messaging);
        for (j = 0u; j < 16u; j++) {
            g_partinfo[i].uuid[j] = (parts[i].uuid_count > 0u) ?
                                    parts[i].uuids[0].bytes[j] : 0u;
        }
    }
    for (i = 0u; i < 4u; i++) {
        word = (uint32_t)frame->x[1u + i];
        uuid[4u * i + 0u] = (uint8_t)(word & 0xFFu);
        uuid[4u * i + 1u] = (uint8_t)((word >> 8) & 0xFFu);
        uuid[4u * i + 2u] = (uint8_t)((word >> 16) & 0xFFu);
        uuid[4u * i + 3u] = (uint8_t)((word >> 24) & 0xFFu);
    }
    ret = wt_ffa_partinfo_write((uint8_t*)(uintptr_t)WT_SPM_RXTX_PA,
                                (size_t)WT_SPM_RXTX_SIZE, WT_FFA_VERSION_1_2,
                                g_partinfo, n, uuid, (uint32_t)frame->x[5],
                                &count, &size);
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, count, size);
}

/* FFA_RX_RELEASE (7.2.2.4): ownership of the RX buffer returns to the SPMC. */
static void ffa_rx_release(wt_trap_frame_t* frame)
{
    ffa_success(frame, 0u, 0u);
}

void wt_spm_lower_sync(wt_trap_frame_t* frame)
{
    uint32_t ec = (uint32_t)(frame->esr >> 26) & 0x3Fu;
    uint32_t fid = (uint32_t)frame->x[0];
    wt_co_t* co = wt_co_current();
    uint32_t sint;
    unsigned int i;

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
    else if (fid == WT_FFA_MSG_WAIT) {
        /* 8.2/8.5: the partition enters the waiting state; the next direct
         * request is delivered as this call's return registers. A Secure
         * interrupt queued while it ran (Table 9.1) is delivered here as
         * FFA_INTERRUPT instead of blocking. */
        sint = wt_spm_sint_take_pending(co);
        if (sint != 0u) {
            for (i = 0u; i < 8u; i++) {
                frame->x[i] = 0u;
            }
            frame->x[0] = WT_FFA_INTERRUPT;
            frame->x[1] = (uint64_t)sint;
        }
        else {
            wt_co_block();
        }
    }
    else if ((fid == WT_FFA_MSG_SEND_DIRECT_RESP32) ||
             (fid == WT_FFA_MSG_SEND_DIRECT_RESP64)) {
        ffa_direct_resp(frame);
    }
    else if (fid == WT_FFA_PARTITION_INFO_GET) {
        ffa_partition_info_get(frame);
    }
    else if (fid == WT_FFA_RX_RELEASE) {
        ffa_rx_release(frame);
    }
    else {
        ffa_not_supported(frame);
    }

    g_wt_spm_handler_depth--;
    g_wt_spm_live_frame = NULL;
}
