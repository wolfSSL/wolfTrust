/* ffa_spmd.c
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

/* SPMD: FF-A calls arriving at the Secure physical instance (from the SPMC).
 * Every reply zeroes the unused result registers (11.2). */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"

static unsigned int g_spmc_ready;
static wt_ffa_version_state_t g_ns_version;
static wt_ffa_version_state_t g_spmc_version;
/* The FFA_VERSION input forwarded to the SPMC, awaiting its Table 13.8 answer. */
static uint32_t g_ns_version_asked;
static uint8_t g_ns_version_forwarded;

static void reply_error(wt_ffa_regs_t* r, int32_t code)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_ERROR;
    r->x[2] = (uint64_t)(uint32_t)code;
}

static void reply_success(wt_ffa_regs_t* r, uint64_t w2, uint64_t w3)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_SUCCESS32;
    r->x[2] = w2;
    r->x[3] = w3;
}

static int spmd_implements(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_ERROR:
        case WT_FFA_SUCCESS32:
        case WT_FFA_SUCCESS64:
        case WT_FFA_VERSION:
        case WT_FFA_FEATURES:
        case WT_FFA_ID_GET:
        case WT_FFA_SPM_ID_GET:
        case WT_FFA_MSG_WAIT:
        case WT_FFA_NORMAL_WORLD_RESUME:
        case WT_FFA_CONSOLE_LOG32:
        case WT_FFA_CONSOLE_LOG64:
            return 1;
        default:
            return 0;
    }
}

unsigned int wt_ffa_spmd_spmc_ready(void)
{
    return g_spmc_ready;
}

/* 13.12: w1 = count (bits 31:8 SBZ), characters tightly packed from w2/x2
 * upward; 1..24 characters over w2-w7, 1..128 over x2-x17. */
void wt_ffa_spmd_console_call(uint64_t* x, unsigned int is64)
{
    uint32_t count = wt_ffa_console_count(x[1], is64);
    unsigned int per_reg = (is64 != 0u) ? 8u : 4u;
    unsigned int i;
    uint64_t reg;

    if (count == 0u) {
        reply_error((wt_ffa_regs_t*)x, WT_FFA_INVALID_PARAMETERS);
    }
    else {
        for (i = 0u; i < count; i++) {
            reg = x[2u + (i / per_reg)];
            wt_platform_console_putc(
                (char)((reg >> (8u * (i % per_reg))) & 0xFFu));
        }
        reply_success((wt_ffa_regs_t*)x, 0u, 0u);
    }
    if (is64 != 0u) {
        wt_ffa_reply_clear_ext(WT_FFA_CONSOLE_LOG64, x);
    }
}

#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
/* The monitor exit call lives in the host-untranslatable monitor ABI, so the
 * driver alone includes it. */
#include "wolftrust/arch/aarch64/monitor_abi.h"

/* Normal-world stand-in for the ffa-direct proof (never in a production
 * image): the SPMC's first post-init wait is answered with one direct request
 * to the echo partition, and the relayed response ends the run. */
static int test_driver_request(wt_ffa_regs_t* r)
{
    static const uint32_t payload[WT_FFA_DIRECT_PAYLOAD_WORDS] = {
        WT_FFA_TEST_PAYLOAD, 0u, 0u, 0u, 0u
    };

    wt_el3_puts("[EL3] spmc ready\r\n[EL3] direct req to=0x");
    wt_el3_puthex(WT_FFA_ID_ECHO, 4u);
    wt_el3_puts("\r\n");
    wt_ffa_direct_build(r->x, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_ECHO, payload);
    return 1;
}

static int test_driver_response(wt_ffa_regs_t* r)
{
    int ok = (wt_ffa_direct_resp_check(r->x, WT_FFA_INSTANCE_NS_PHYSICAL) == 0) &&
             (wt_ffa_direct_sender(r->x[1]) == WT_FFA_ID_ECHO) &&
             (wt_ffa_direct_receiver(r->x[1]) == WT_FFA_ID_NS_PRIMARY) &&
             ((uint32_t)r->x[3] == (uint32_t)~WT_FFA_TEST_PAYLOAD);

    wt_el3_puts(ok ? "[EL3] direct resp ok from=0x" : "[EL3] direct resp BAD from=0x");
    wt_el3_puthex(wt_ffa_direct_sender(r->x[1]), 4u);
    wt_el3_puts(" x3=0x");
    wt_el3_puthex((uint32_t)r->x[3], 8u);
    wt_el3_puts("\r\n");
    wt_platform_console_flush();
    (void)wt_el3_monitor_call(WT_MON_FID_EXIT,
                              ok ? WT_MON_EXIT_SUCCESS : WT_MON_EXIT_PANIC);
    return 1;
}
#else
static int test_driver_request(wt_ffa_regs_t* r)
{
    (void)r;
    return 0;
}

static int test_driver_response(wt_ffa_regs_t* r)
{
    (void)r;
    return 0;
}
#endif

static int ns_implements(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_ERROR:
        case WT_FFA_SUCCESS32:
        case WT_FFA_SUCCESS64:
        case WT_FFA_INTERRUPT:
        case WT_FFA_VERSION:
        case WT_FFA_FEATURES:
        case WT_FFA_ID_GET:
        case WT_FFA_SPM_ID_GET:
        case WT_FFA_PARTITION_INFO_GET:
        case WT_FFA_PARTITION_INFO_GET_REGS:
        case WT_FFA_RXTX_MAP32:
        case WT_FFA_RXTX_MAP64:
        case WT_FFA_RXTX_UNMAP:
        case WT_FFA_RX_RELEASE:
        case WT_FFA_MSG_WAIT:
        case WT_FFA_RUN:
        case WT_FFA_MSG_SEND_DIRECT_REQ32:
        case WT_FFA_MSG_SEND_DIRECT_REQ64:
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
        case WT_FFA_MSG_SEND_DIRECT_RESP64:
        case WT_FFA_MSG_SEND_DIRECT_REQ2:
        case WT_FFA_MSG_SEND_DIRECT_RESP2:
        case WT_FFA_MEM_SHARE32:
        case WT_FFA_MEM_SHARE64:
        case WT_FFA_MEM_LEND32:
        case WT_FFA_MEM_LEND64:
        case WT_FFA_MEM_DONATE32:
        case WT_FFA_MEM_DONATE64:
        case WT_FFA_MEM_RETRIEVE_REQ32:
        case WT_FFA_MEM_RETRIEVE_REQ64:
        case WT_FFA_MEM_RETRIEVE_RESP:
        case WT_FFA_MEM_RELINQUISH:
        case WT_FFA_MEM_RECLAIM:
        case WT_FFA_MEM_FRAG_RX:
        case WT_FFA_MEM_FRAG_TX:
        case WT_FFA_NOTIFICATION_BITMAP_CREATE:
        case WT_FFA_NOTIFICATION_BITMAP_DESTROY:
        case WT_FFA_NOTIFICATION_BIND:
        case WT_FFA_NOTIFICATION_UNBIND:
        case WT_FFA_NOTIFICATION_SET:
        case WT_FFA_NOTIFICATION_GET:
        case WT_FFA_NOTIFICATION_INFO_GET32:
        case WT_FFA_NOTIFICATION_INFO_GET64:
        case WT_FFA_MSG_SEND2:
            return 1;
        default:
            return 0;
    }
}

/* Any NS call but FFA_VERSION settles the version the guest negotiated. */
void wt_ffa_spmd_ns_note(uint32_t fid)
{
    if (wt_ffa_fid_in_range(fid) && (fid != WT_FFA_VERSION)) {
        wt_ffa_version_lock(&g_ns_version, WT_FFA_VERSION_1_2);
    }
}

/* Any SPMC call but FFA_VERSION settles the version it negotiated (13.2). */
void wt_ffa_spmd_secure_note(uint32_t fid)
{
    if (wt_ffa_fid_in_range(fid) && (fid != WT_FFA_VERSION)) {
        wt_ffa_version_lock(&g_spmc_version, WT_FFA_VERSION_1_2);
    }
}

/* NS-instance FIDs the SPMD cannot answer alone (it has no manifest and owns
 * no mailbox): they are forwarded to the SPMC. */
int wt_ffa_spmd_ns_forwards(uint32_t fid)
{
    if (!wt_ffa_fid_available(
            fid, wt_ffa_version_of(&g_ns_version, WT_FFA_VERSION_1_2))) {
        return 0;
    }
    switch (fid) {
        case WT_FFA_VERSION:
            /* 13.2.3.2: the SPMC chooses what the Normal world negotiates; once
             * that is locked the SPMD answers a repeat itself. */
            return (g_ns_version.locked == 0u) ? 1 : 0;
        case WT_FFA_RXTX_MAP32:
        case WT_FFA_RXTX_MAP64:
        case WT_FFA_RXTX_UNMAP:
        case WT_FFA_RX_RELEASE:
        case WT_FFA_RUN:
        case WT_FFA_PARTITION_INFO_GET:
        case WT_FFA_PARTITION_INFO_GET_REGS:
        case WT_FFA_MSG_SEND_DIRECT_REQ32:
        case WT_FFA_MSG_SEND_DIRECT_REQ64:
        case WT_FFA_MSG_SEND_DIRECT_REQ2:
        case WT_FFA_MEM_SHARE32:
        case WT_FFA_MEM_SHARE64:
        case WT_FFA_MEM_LEND32:
        case WT_FFA_MEM_LEND64:
        case WT_FFA_MEM_DONATE32:
        case WT_FFA_MEM_DONATE64:
        case WT_FFA_MEM_RETRIEVE_REQ32:
        case WT_FFA_MEM_RETRIEVE_REQ64:
        case WT_FFA_MEM_RELINQUISH:
        case WT_FFA_MEM_RECLAIM:
        case WT_FFA_MEM_FRAG_RX:
        case WT_FFA_MEM_FRAG_TX:
        case WT_FFA_NOTIFICATION_BITMAP_CREATE:
        case WT_FFA_NOTIFICATION_BITMAP_DESTROY:
        case WT_FFA_NOTIFICATION_BIND:
        case WT_FFA_NOTIFICATION_UNBIND:
        case WT_FFA_NOTIFICATION_SET:
        case WT_FFA_NOTIFICATION_GET:
        case WT_FFA_NOTIFICATION_INFO_GET32:
        case WT_FFA_NOTIFICATION_INFO_GET64:
        case WT_FFA_MSG_SEND2:
#if defined(WT_FFA_ACS) && (WT_FFA_ACS == 1)
        case WT_SPM_SVC_FID_TIMER_ARM:
        case WT_SPM_SVC_FID_TIMER_STOP:
#endif
            return 1;
        default:
            return 0;
    }
}

/* FFA_VERSION reaches the SPMC as the Table 13.7 framework message. 7.4.2:
 * the SPMD relays a direct request only from the Normal world to a Secure
 * endpoint, so nothing it forwards carries a Secure sender id. */
int wt_ffa_spmd_ns_forward(uint64_t* x)
{
    uint32_t fid = (uint32_t)x[0];

    if (fid == WT_FFA_VERSION) {
        g_ns_version_asked = (uint32_t)x[1];
        g_ns_version_forwarded = 1u;
        wt_ffa_fwk_version_req(x, g_ns_version_asked);
        return 1;
    }
    if (((fid == WT_FFA_MSG_SEND_DIRECT_REQ32) ||
         (fid == WT_FFA_MSG_SEND_DIRECT_REQ64) ||
         (fid == WT_FFA_MSG_SEND_DIRECT_REQ2)) &&
        (wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) != 0)) {
        reply_error((wt_ffa_regs_t*)x, WT_FFA_INVALID_PARAMETERS);
        wt_ffa_reply_clear_ext(fid, x);
        return 0;
    }
    /* Only x0-x7 travel, and an 8-register reply leaves x8-x17 as here. */
    if (wt_ffa_fid_in_range(fid) &&
        (wt_ffa_msg_reg_count(fid) == WT_FFA_MSG_REGS)) {
        wt_ffa_reply_clear_ext(fid, x);
    }
    return 1;
}

void wt_ffa_spmd_ns_reply(uint64_t* x)
{
    int32_t result;
    unsigned int i;

    if (g_ns_version_forwarded == 0u) {
        return;
    }
    g_ns_version_forwarded = 0u;
    result = wt_ffa_fwk_version_result(x);
    if (result >= 0) {
        g_ns_version.version = wt_ffa_version_settle(g_ns_version_asked,
                                                     (uint32_t)result);
    }
    for (i = 0u; i < 8u; i++) {
        x[i] = 0u;
    }
    x[0] = (uint64_t)(uint32_t)result;
}

/* An SMC from the SPMC that is the reply to a call the SPMD forwarded from the
 * Normal world; it is routed back to the waiting Normal world. */
int wt_ffa_spmd_is_ns_reply(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_SUCCESS32:
        case WT_FFA_SUCCESS64:
        case WT_FFA_ERROR:
        case WT_FFA_INTERRUPT:
        case WT_FFA_MEM_FRAG_RX:
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
        case WT_FFA_MSG_SEND_DIRECT_RESP64:
        case WT_FFA_MSG_SEND_DIRECT_RESP2:
        case WT_FFA_YIELD:
        case WT_FFA_MSG_WAIT:
            return 1;
        default:
            return 0;
    }
}

/* An SMC from the SPMC yielding the CPU back to a preempted Normal world:
 * only FFA_NORMAL_WORLD_RESUME does (14.4). */
int wt_ffa_spmd_is_ns_resume(uint32_t fid)
{
    return (fid == WT_FFA_NORMAL_WORLD_RESUME) ? 1 : 0;
}

/* NS physical instance (13.x): FF-A calls arriving from the Normal world once
 * the SPMD has launched it. B3.2 serves version negotiation and discovery
 * (FEATURES, ID_GET, SPM_ID_GET); direct messaging and the interrupt loop
 * follow in later B3 slices. */
void wt_ffa_spmd_ns_call(wt_ffa_regs_t* r)
{
    uint32_t fid = (uint32_t)r->x[0];
    uint32_t w1 = (uint32_t)r->x[1];
    uint32_t version = wt_ffa_version_of(&g_ns_version, WT_FFA_VERSION_1_2);
    unsigned int i;

    if (!wt_ffa_fid_available(fid, version)) {
        reply_error(r, WT_FFA_NOT_SUPPORTED);
        return;
    }
    switch (fid) {
        case WT_FFA_VERSION:
            for (i = 1u; i < 8u; i++) {
                r->x[i] = 0u;
            }
            r->x[0] = (uint64_t)(uint32_t)wt_ffa_version_negotiate(
                &g_ns_version, w1, WT_FFA_VERSION_1_2);
            break;
        case WT_FFA_FEATURES:
            /* Table 13.11: w2 is MBZ for a feature id query. */
            if ((w1 == WT_FFA_FEATURE_SRI) && ((uint32_t)r->x[2] == 0u)) {
                reply_success(r, WT_FFA_SRI_INTID, 0u);
            }
            else if ((w1 == WT_FFA_MEM_RETRIEVE_REQ32) ||
                     (w1 == WT_FFA_MEM_RETRIEVE_REQ64)) {
                /* The NS-bit request is an SP rule (DEN0140 1.10.4.1.1). */
                reply_success(r, WT_FFA_FEATURES_RETRIEVE_NS_BIT, 0u);
            }
            else if (WT_FFA_FEATURES_IS_FID(w1) && ns_implements(w1) &&
                     wt_ffa_fid_available(w1, version)) {
                /* w3[5:0] caps RXTX_MAP at 63 pages: no limit (Tbl 13.25). */
                reply_success(r, 0u, 0u);
            }
            else {
                reply_error(r, WT_FFA_NOT_SUPPORTED);
            }
            break;
        case WT_FFA_ID_GET:
            /* The caller's own id: the primary Normal-world endpoint is 0
             * (DEV-01: the SPMD plays the Hypervisor id-allocation role). */
            reply_success(r, WT_FFA_ID_NS_PRIMARY, 0u);
            break;
        case WT_FFA_SPM_ID_GET:
            /* The SPM the Normal world talks to is the SPMC. */
            reply_success(r, WT_FFA_ID_SPMC, 0u);
            break;
        case WT_FFA_MSG_WAIT:
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
        case WT_FFA_MSG_SEND_DIRECT_RESP64:
        case WT_FFA_MSG_SEND_DIRECT_RESP2:
            /* The primary Normal-world endpoint is never a message receiver. */
            reply_error(r, WT_FFA_DENIED);
            break;
        default:
            reply_error(r, WT_FFA_NOT_SUPPORTED);
            break;
    }
}

int wt_ffa_spmd_secure_call(wt_ffa_regs_t* r)
{
    uint32_t fid = (uint32_t)r->x[0];
    uint32_t w1 = (uint32_t)r->x[1];
    uint32_t version = wt_ffa_version_of(&g_spmc_version, WT_FFA_VERSION_1_2);
    unsigned int i;

    if (!wt_ffa_fid_available(fid, version)) {
        reply_error(r, WT_FFA_NOT_SUPPORTED);
        return WT_SPMD_ACTION_REPLY;
    }
    switch (fid) {
        case WT_FFA_VERSION:
            for (i = 1u; i < 8u; i++) {
                r->x[i] = 0u;
            }
            r->x[0] = (uint64_t)(uint32_t)wt_ffa_version_negotiate(
                &g_spmc_version, w1, WT_FFA_VERSION_1_2);
            break;
        case WT_FFA_FEATURES:
            if (WT_FFA_FEATURES_IS_FID(w1) && spmd_implements(w1) &&
                wt_ffa_fid_available(w1, version)) {
                reply_success(r, 0u, 0u);
            }
            else {
                reply_error(r, WT_FFA_NOT_SUPPORTED);
            }
            break;
        case WT_FFA_ID_GET:
            reply_success(r, WT_FFA_ID_SPMC, 0u);
            break;
        case WT_FFA_SPM_ID_GET:
            reply_success(r, WT_FFA_ID_SPMD, 0u);
            break;
        case WT_FFA_CONSOLE_LOG32:
            wt_ffa_spmd_console_call(r->x, 0u);
            break;
        case WT_FFA_MSG_WAIT:
            /* 5.5: the first MSG_WAIT from the SPMC ends its initialization; the
             * SPMD then turns on the Normal world. */
            if (g_spmc_ready == 0u) {
                g_spmc_ready = 1u;
                if (test_driver_request(r) != 0) {
                    break;
                }
                return WT_SPMD_ACTION_LAUNCH;
            }
            reply_error(r, WT_FFA_DENIED);
            break;
        case WT_FFA_NORMAL_WORLD_RESUME:
            /* 14.4.1: the monitor resumes a preempted Normal world before this
             * dispatch, so reaching it means none was preempted. */
            reply_error(r, WT_FFA_DENIED);
            break;
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
            if (test_driver_response(r) == 0) {
                reply_error(r, WT_FFA_NOT_SUPPORTED);
            }
            break;
        default:
            reply_error(r, WT_FFA_NOT_SUPPORTED);
            break;
    }
    return WT_SPMD_ACTION_REPLY;
}
