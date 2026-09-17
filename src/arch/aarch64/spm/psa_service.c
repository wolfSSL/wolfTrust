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

/* The PSA framework endpoint at the NS physical instance: the AArch64 twin of
 * the Armv8-M CMSE veneers. Each Normal-world FrameworkVersion/ServiceVersion/
 * Connect/Close/Call is handed to the neutral FF-M gateway, which owns caller
 * identity, handles, versions, and misuse detection; a Call's vectors stay in
 * the guest's memory and the core copies them itself (psa_read/psa_write)
 * through the Non-secure window the SPMC maps EL1-only. */

#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/psa_ffa.h"
#include "wolftrust/ffm_gateway.h"
#include "wolftrust/ffm_veneer.h"

#include "psa/client.h"

static uint64_t g_ns_lo;
static uint64_t g_ns_hi;

void wt_spm_psa_init(uint64_t ns_lo, uint64_t ns_hi)
{
    g_ns_lo = ns_lo;
    g_ns_hi = ns_hi;
}

/* A non-empty span must lie entirely inside the Non-secure window: this is the
 * whole security check - a Secure or out-of-range pointer is refused, so the
 * core never reads or writes anything but the caller's own memory. */
int wt_spm_ns_window_ok(uintptr_t base, size_t len)
{
    uint64_t b = (uint64_t)base;
    uint64_t n = (uint64_t)len;

    if (n == 0u) {
        return 1;
    }
    return (b >= g_ns_lo) && (b <= g_ns_hi) && (n <= (g_ns_hi - b));
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
            result = (int32_t)wt_ffm_gateway_framework_version();
            break;
        case WT_PSA_FFA_OP_SERVICE_VERSION:
            result = (int32_t)wt_ffm_gateway_service_version(a0);
            break;
        case WT_PSA_FFA_OP_CONNECT:
            result = wt_ffm_gateway_connect(a0, a1);
            break;
        case WT_PSA_FFA_OP_CLOSE:
            wt_ffm_gateway_close((int32_t)a0);
            result = (int32_t)PSA_SUCCESS;
            break;
        case WT_PSA_FFA_OP_CALL:
            /* x4 = the Non-secure address of the client's vector block (the
             * gateway checks it against the window before reading it), x5 =
             * handle in bits 31:0 and type in bits 63:32. */
            result = wt_ffm_gateway_call((int32_t)(uint32_t)r->x[5],
                                         (int32_t)(uint32_t)(r->x[5] >> 32),
                                         (wt_ffm_veneer_iovec_t*)(uintptr_t)r->x[4]);
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
