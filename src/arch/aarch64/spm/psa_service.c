/* psa_service.c
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

/* Register-only PSA framework endpoint at the NS physical instance: the SPMC
 * answers a Normal-world client's FrameworkVersion/ServiceVersion/Connect/Close
 * with no payload copy. A connection is a slot in a fixed table (no
 * allocation); a data-carrying psa_call to the owning partition arrives with
 * memory sharing (B4). */

#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/psa_ffa.h"

#include "psa/client.h"

static struct wt_psa_conn {
    uint32_t sid;
    uint8_t used;
} g_conn[WT_PSA_FFA_MAX_CONN];

static int32_t service_version(uint32_t sid)
{
    if (sid == WT_PSA_FFA_SID_TEST) {
        return (int32_t)WT_PSA_FFA_SID_TEST_VERSION;
    }
    return (int32_t)PSA_VERSION_NONE;
}

static int32_t do_connect(uint32_t sid, uint32_t version)
{
    unsigned int i;

    if (service_version(sid) == (int32_t)PSA_VERSION_NONE) {
        return (int32_t)PSA_ERROR_CONNECTION_REFUSED;
    }
    if ((version != 0u) && (version > WT_PSA_FFA_SID_TEST_VERSION)) {
        return (int32_t)PSA_ERROR_CONNECTION_REFUSED;
    }
    for (i = 0u; i < WT_PSA_FFA_MAX_CONN; i++) {
        if (g_conn[i].used == 0u) {
            g_conn[i].used = 1u;
            g_conn[i].sid = sid;
            return (int32_t)(i + 1u);
        }
    }
    return (int32_t)PSA_ERROR_CONNECTION_BUSY;
}

static int32_t do_close(uint32_t handle)
{
    if ((handle >= 1u) && (handle <= WT_PSA_FFA_MAX_CONN) &&
        (g_conn[handle - 1u].used != 0u)) {
        g_conn[handle - 1u].used = 0u;
        g_conn[handle - 1u].sid = 0u;
        return (int32_t)PSA_SUCCESS;
    }
    return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
}

static uint64_t g_ns_lo;
static uint64_t g_ns_hi;

void wt_spm_psa_init(uint64_t ns_lo, uint64_t ns_hi)
{
    g_ns_lo = ns_lo;
    g_ns_hi = ns_hi;
}

static int conn_live(uint32_t handle)
{
    return (handle >= 1u) && (handle <= WT_PSA_FFA_MAX_CONN) &&
           (g_conn[handle - 1u].used != 0u);
}

/* A non-empty span must lie entirely inside the Non-secure window: this is the
 * whole security check - a Secure or out-of-range pointer is refused, so the
 * service never reads or writes anything but the caller's own memory. */
static int range_ok(uint64_t base, uint64_t len, uint64_t lo, uint64_t hi)
{
    if (len == 0u) {
        return 1;
    }
    return (base >= lo) && (base <= hi) && (len <= (hi - base));
}

/* The register-only test service: copy the first in-vec into a private scratch
 * buffer complementing each byte, then copy that into the first out-vec and
 * report the written length. The service only ever touches the scratch copy,
 * never the caller's live memory (SPM-mediated copy, TF-M model). */
static int32_t call_service(const wt_psa_ffa_call_t* desc, const psa_invec* iv,
                            psa_outvec* ov)
{
    static uint8_t scratch[WT_PSA_FFA_CALL_MAX];
    uint32_t n = 0u;
    uint32_t cap;
    uint32_t i;

    if (desc->in_len >= 1u) {
        n = (uint32_t)iv[0].len;
        if (n > WT_PSA_FFA_CALL_MAX) {
            n = WT_PSA_FFA_CALL_MAX;
        }
        for (i = 0u; i < n; i++) {
            scratch[i] = (uint8_t)(((const uint8_t*)iv[0].base)[i] ^ 0xFFu);
        }
    }
    if (desc->out_len >= 1u) {
        cap = (uint32_t)ov[0].len;
        if (cap > n) {
            cap = n;
        }
        for (i = 0u; i < cap; i++) {
            ((uint8_t*)ov[0].base)[i] = scratch[i];
        }
        ov[0].len = cap;
    }
    return (int32_t)PSA_SUCCESS;
}

int32_t wt_psa_call_run(uint64_t desc_addr, uint64_t ns_lo, uint64_t ns_hi)
{
    const wt_psa_ffa_call_t* desc;
    const psa_invec* iv;
    psa_outvec* ov;
    uint32_t i;

    if (!range_ok(desc_addr, (uint64_t)sizeof(wt_psa_ffa_call_t), ns_lo, ns_hi)) {
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    desc = (const wt_psa_ffa_call_t*)(uintptr_t)desc_addr;
    if ((desc->in_len > PSA_MAX_IOVEC) || (desc->out_len > PSA_MAX_IOVEC)) {
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (!conn_live(desc->handle)) {
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    if ((desc->in_len != 0u) &&
        !range_ok(desc->in_vec,
                  (uint64_t)desc->in_len * (uint64_t)sizeof(psa_invec),
                  ns_lo, ns_hi)) {
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    if ((desc->out_len != 0u) &&
        !range_ok(desc->out_vec,
                  (uint64_t)desc->out_len * (uint64_t)sizeof(psa_outvec),
                  ns_lo, ns_hi)) {
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    iv = (const psa_invec*)(uintptr_t)desc->in_vec;
    ov = (psa_outvec*)(uintptr_t)desc->out_vec;
    for (i = 0u; i < desc->in_len; i++) {
        if (!range_ok((uint64_t)(uintptr_t)iv[i].base, (uint64_t)iv[i].len,
                      ns_lo, ns_hi)) {
            return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
        }
    }
    for (i = 0u; i < desc->out_len; i++) {
        if (!range_ok((uint64_t)(uintptr_t)ov[i].base, (uint64_t)ov[i].len,
                      ns_lo, ns_hi)) {
            return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
        }
    }
    return call_service(desc, iv, ov);
}

int wt_spm_psa_framework(wt_ffa_regs_t* r)
{
    uint32_t op = (uint32_t)r->x[3];
    uint32_t a0 = (uint32_t)r->x[4];
    uint32_t a1 = (uint32_t)r->x[5];
    uint16_t sender = wt_ffa_direct_sender(r->x[1]);
    int32_t result;
    unsigned int i;

    switch (op) {
        case WT_PSA_FFA_OP_FRAMEWORK_VERSION:
            result = (int32_t)PSA_FRAMEWORK_VERSION;
            break;
        case WT_PSA_FFA_OP_SERVICE_VERSION:
            result = service_version(a0);
            break;
        case WT_PSA_FFA_OP_CONNECT:
            result = do_connect(a0, a1);
            break;
        case WT_PSA_FFA_OP_CLOSE:
            result = do_close(a0);
            break;
        case WT_PSA_FFA_OP_CALL:
            /* The parameter block address is the full 64-bit w4, not a0. */
            result = wt_psa_call_run(r->x[4], g_ns_lo, g_ns_hi);
            break;
        default:
            for (i = 0u; i < 8u; i++) {
                r->x[i] = 0u;
            }
            r->x[0] = WT_FFA_ERROR;
            r->x[2] = (uint64_t)(uint32_t)WT_FFA_INVALID_PARAMETERS;
            return -1;
    }
    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_MSG_SEND_DIRECT_RESP32;
    r->x[1] = ((uint64_t)WT_FFA_ID_PSA << 16) | sender;
    r->x[3] = (uint64_t)(uint32_t)result;
    return 0;
}
