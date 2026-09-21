/* crypto_native_client.c
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

/* OS-neutral Non-secure client for the native crypto wire: one mediated
 * psa_call to SERVICE_HSM per request, no shared-RAM window, no raw veneer.
 * A Secure Partition restart invalidates the cached handle; every call
 * reconnects on demand so the client heals across recovery windows. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "psa/client.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/crypto_native_client.h"

/* SERVICE_HSM SID from the platform manifest, same door the wolfHSM client
 * glue connects to in the hsm engine. */
#ifndef WT_CRYPTO_NATIVE_SID
#define WT_CRYPTO_NATIVE_SID 4102u
#endif
#ifndef WT_CRYPTO_NATIVE_SID_VERSION
#define WT_CRYPTO_NATIVE_SID_VERSION 1u
#endif

/* A Secure Partition restart window (WT-SYS-0008 graceful recovery) makes
 * the door refuse connects and calls for a short while; every consumer of
 * this client — including a wc_InitRng seed fetch mid-keygen — must ride it
 * out, so the round trip below retries with bounded patience, mirroring the
 * wolfHSM client glue's heal-on-demand. */
#ifndef WT_CRYPTO_NATIVE_RETRIES
#define WT_CRYPTO_NATIVE_RETRIES 64
#endif

static psa_handle_t g_native_handle;

static int wt_crypto_native_ensure_connected(void)
{
    if (g_native_handle > 0) {
        return 0;
    }
    g_native_handle = psa_connect(WT_CRYPTO_NATIVE_SID,
                                  WT_CRYPTO_NATIVE_SID_VERSION);
    return (g_native_handle > 0) ? 0 : -1;
}

psa_status_t wt_crypto_native_call(const wt_crypto_wire_req_t* hdr,
                                   const uint8_t* payload,
                                   size_t payload_len, uint8_t* out,
                                   size_t out_cap, size_t* out_len)
{
    uint8_t req[WT_HSM_RELAY_MSG_MAX];
    uint8_t resp[WT_HSM_RELAY_MSG_MAX];
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t status;
    int32_t wire_status;
    size_t got;
    int attempt;

    /* Subtraction, not sizeof(*hdr) + payload_len, so a payload_len near
     * SIZE_MAX cannot wrap the bound and let the memcpy overrun req. The
     * header always fits, so sizeof(req) - sizeof(*hdr) never underflows. */
    if (hdr == NULL || (payload == NULL && payload_len != 0U) ||
            payload_len > sizeof(req) - sizeof(*hdr)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memcpy(req, hdr, sizeof(*hdr));
    if (payload_len != 0U) {
        (void)memcpy(req + sizeof(*hdr), payload, payload_len);
    }

    status = PSA_ERROR_CONNECTION_REFUSED;
    for (attempt = 0; attempt < WT_CRYPTO_NATIVE_RETRIES; attempt++) {
        if (wt_crypto_native_ensure_connected() != 0) {
            continue;
        }
        in_vec.base = req;
        in_vec.len = sizeof(*hdr) + payload_len;
        out_vec.base = resp;
        out_vec.len = sizeof(resp);
        status = psa_call(g_native_handle, PSA_IPC_CALL, &in_vec, 1U,
                          &out_vec, 1U);
        if (status == PSA_SUCCESS) {
            break;
        }
        psa_close(g_native_handle);
        g_native_handle = 0;
        /* A call that failed after reaching the door is ambiguous: a mutating
         * op may have committed to NVM before its reply was lost, so replaying
         * it would corrupt the store or misreport the result. Surface the
         * failure; only connect setup and idempotent ops are safe to retry. */
        if (hdr->op == WT_CRYPTO_OP_KEY_GENERATE ||
                hdr->op == WT_CRYPTO_OP_KEY_IMPORT ||
                hdr->op == WT_CRYPTO_OP_KEY_DESTROY) {
            return status;
        }
    }
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (out_vec.len < sizeof(wire_status)) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    (void)memcpy(&wire_status, resp, sizeof(wire_status));
    got = out_vec.len - sizeof(wire_status);
    if (out != NULL && got != 0U) {
        if (got > out_cap) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        (void)memcpy(out, resp + sizeof(wire_status), got);
    }
    if (out_len != NULL) {
        *out_len = got;
    }
    return (psa_status_t)wire_status;
}

psa_status_t wt_crypto_native_random(uint8_t* out, size_t len)
{
    wt_crypto_wire_req_t hdr;
    size_t done = 0U;
    size_t chunk;
    size_t got = 0U;
    psa_status_t status = PSA_SUCCESS;

    if (out == NULL || len == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    while (done < len) {
        chunk = len - done;
        if (chunk > WT_CRYPTO_RANDOM_MAX) {
            chunk = WT_CRYPTO_RANDOM_MAX;
        }
        (void)memset(&hdr, 0, sizeof(hdr));
        hdr.op = WT_CRYPTO_OP_RANDOM;
        hdr.usage = (uint32_t)chunk;
        status = wt_crypto_native_call(&hdr, NULL, 0U, out + done, chunk,
                                       &got);
        if (status != PSA_SUCCESS) {
            break;
        }
        if (got != chunk) {
            status = PSA_ERROR_COMMUNICATION_FAILURE;
            break;
        }
        done += chunk;
    }
    return status;
}

int wolftrust_guest_rng_stub(unsigned char* output, unsigned int sz)
{
    return (wt_crypto_native_random(output, (size_t)sz) == PSA_SUCCESS) ?
           0 : -1;
}
