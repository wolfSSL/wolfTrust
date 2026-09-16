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
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"

static unsigned int g_spmc_ready;

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
    uint32_t count = (uint32_t)x[1];
    unsigned int per_reg = (is64 != 0u) ? 8u : 4u;
    unsigned int max = (is64 != 0u) ? 128u : 24u;
    unsigned int i;
    uint64_t reg;

    if (((count & 0xFFFFFF00u) != 0u) || (count < 1u) || (count > max)) {
        reply_error((wt_ffa_regs_t*)x, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    for (i = 0u; i < count; i++) {
        reg = x[2u + (i / per_reg)];
        wt_platform_console_putc((char)((reg >> (8u * (i % per_reg))) & 0xFFu));
    }
    reply_success((wt_ffa_regs_t*)x, 0u, 0u);
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
        case WT_FFA_VERSION:
        case WT_FFA_FEATURES:
        case WT_FFA_ID_GET:
        case WT_FFA_SPM_ID_GET:
        case WT_FFA_PARTITION_INFO_GET:
            return 1;
        default:
            return 0;
    }
}

/* NS-instance FIDs the SPMD cannot answer alone (it has no manifest): they are
 * forwarded to the SPMC. Partition discovery today; guest-to-SP direct
 * messaging joins it next. */
int wt_ffa_spmd_ns_forwards(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_PARTITION_INFO_GET:
            return 1;
        default:
            return 0;
    }
}

/* An SMC from the SPMC that is the reply to a call the SPMD forwarded from the
 * Normal world; it is routed back to the waiting Normal world. */
int wt_ffa_spmd_is_ns_reply(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_SUCCESS32:
        case WT_FFA_SUCCESS64:
        case WT_FFA_ERROR:
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
        case WT_FFA_MSG_SEND_DIRECT_RESP64:
            return 1;
        default:
            return 0;
    }
}

/* NS physical instance (13.x): FF-A calls arriving from the Normal world once
 * the SPMD has launched it. B3.2 serves version negotiation and discovery
 * (FEATURES, ID_GET, SPM_ID_GET); direct messaging and the interrupt loop
 * follow in later B3 slices. */
void wt_ffa_spmd_ns_call(wt_ffa_regs_t* r)
{
    uint32_t fid = (uint32_t)r->x[0];
    uint32_t w1 = (uint32_t)r->x[1];
    unsigned int i;

    switch (fid) {
        case WT_FFA_VERSION:
            for (i = 1u; i < 8u; i++) {
                r->x[i] = 0u;
            }
            r->x[0] = (uint64_t)(uint32_t)wt_ffa_version_reply(w1,
                                                               WT_FFA_VERSION_1_2);
            break;
        case WT_FFA_FEATURES:
            if (WT_FFA_FEATURES_IS_FID(w1) && ns_implements(w1)) {
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
        default:
            reply_error(r, WT_FFA_NOT_SUPPORTED);
            break;
    }
}

int wt_ffa_spmd_secure_call(wt_ffa_regs_t* r)
{
    uint32_t fid = (uint32_t)r->x[0];
    uint32_t w1 = (uint32_t)r->x[1];
    unsigned int i;

    switch (fid) {
        case WT_FFA_VERSION:
            for (i = 1u; i < 8u; i++) {
                r->x[i] = 0u;
            }
            r->x[0] = (uint64_t)(uint32_t)wt_ffa_version_reply(w1,
                                                               WT_FFA_VERSION_1_2);
            break;
        case WT_FFA_FEATURES:
            if (WT_FFA_FEATURES_IS_FID(w1) && spmd_implements(w1)) {
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
