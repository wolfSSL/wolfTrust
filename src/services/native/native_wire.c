/* native_wire.c
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

/*
 * Native crypto wire: SERVICE_HSM's submit backend for WT_ENGINE=native.
 * Port-free by design (no flash, boot, or attestation dependencies) so the
 * packet parser and every operation are host-testable against a RAM-backed
 * NVM store.
 */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolftrust/services/hsm.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/crypto_native.h"

#include <string.h>
#include <stdint.h>

/* =========================================================================
 * wt_native_submit — SERVICE_HSM's native wire backend.
 *
 * One request packet ([wt_crypto_wire_req_t][payload]) in, one response
 * packet ([int32_t psa_status][payload]) out, both bounded by the relay's
 * copied buffers. Key ops execute in the key backend with the SPM-stamped
 * client as delegated sub_owner, so a client only reaches its own keys.
 * ====================================================================== */
static psa_status_t wt_native_hash(const uint8_t* input, size_t input_len,
                                   uint8_t* out, size_t out_cap,
                                   size_t* out_len)
{
    wc_Sha256 sha;
    int rc;

    if (out_cap < WC_SHA256_DIGEST_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    rc = wc_InitSha256_ex(&sha, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_Sha256Update(&sha, input, (word32)input_len);
    }
    if (rc == 0) {
        rc = wc_Sha256Final(&sha, out);
    }
    if (rc != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    *out_len = WC_SHA256_DIGEST_SIZE;
    return PSA_SUCCESS;
}

int wt_native_submit(void* submit_ctx, int32_t client_id, const uint8_t* req,
                     size_t req_len, uint8_t* resp, size_t resp_cap,
                     size_t* resp_len)
{
    wt_crypto_wire_req_t hdr;
    int32_t owner = (int32_t)(intptr_t)submit_ctx;
    const uint8_t* payload;
    uint8_t* out;
    size_t payload_len;
    size_t out_cap;
    size_t out_len = 0U;
    size_t rand_len;
    int32_t wire_status;
    psa_status_t status;

    if (req == NULL || resp == NULL || resp_len == NULL ||
            req_len < sizeof(hdr) || resp_cap < sizeof(wire_status)) {
        return -1;
    }
    (void)memcpy(&hdr, req, sizeof(hdr));
    payload = req + sizeof(hdr);
    payload_len = req_len - sizeof(hdr);
    out = resp + sizeof(wire_status);
    out_cap = resp_cap - sizeof(wire_status);

    /* Strict parser: reserved must be zero so a future op cannot repurpose
     * it as a flag a current client left set. Clients are told to zero it. */
    if (hdr.reserved != 0U) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    else switch (hdr.op) {
    case WT_CRYPTO_OP_KEY_GENERATE:
        status = wt_hsm_key_backend.generate(owner, client_id, hdr.uid,
                                             hdr.key_type, hdr.usage);
        break;
    case WT_CRYPTO_OP_KEY_IMPORT:
        status = wt_hsm_key_backend.import(owner, client_id, hdr.uid,
                                           hdr.key_type, hdr.usage, payload,
                                           payload_len);
        break;
    case WT_CRYPTO_OP_KEY_EXPORT_PUBLIC:
        status = wt_hsm_key_backend.export_public(owner, client_id, hdr.uid,
                                                  out, out_cap, &out_len);
        break;
    case WT_CRYPTO_OP_KEY_SIGN:
        status = wt_hsm_key_backend.sign(owner, client_id, hdr.uid, payload,
                                         payload_len, out, out_cap,
                                         &out_len);
        break;
    case WT_CRYPTO_OP_KEY_VERIFY:
        /* payload = [digest 32][signature 64]. */
        if (payload_len != WT_VAULT_KEY_DIGEST_LEN + WT_VAULT_KEY_SIG_LEN) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            status = wt_hsm_key_backend.verify(owner, client_id, hdr.uid,
                                               payload,
                                               WT_VAULT_KEY_DIGEST_LEN,
                                               payload +
                                                   WT_VAULT_KEY_DIGEST_LEN,
                                               WT_VAULT_KEY_SIG_LEN);
        }
        break;
    case WT_CRYPTO_OP_KEY_ENCRYPT:
        status = wt_hsm_key_backend.encrypt(owner, client_id, hdr.uid,
                                            payload, payload_len, out,
                                            out_cap, &out_len);
        break;
    case WT_CRYPTO_OP_KEY_DECRYPT:
        status = wt_hsm_key_backend.decrypt(owner, client_id, hdr.uid,
                                            payload, payload_len, out,
                                            out_cap, &out_len);
        break;
    case WT_CRYPTO_OP_KEY_DESTROY:
        status = wt_hsm_keyvault_destroy(owner, client_id, hdr.uid);
        break;
    case WT_CRYPTO_OP_RANDOM:
        rand_len = hdr.usage;
        if (rand_len == 0U || rand_len > WT_CRYPTO_RANDOM_MAX ||
                rand_len > out_cap) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            status = wt_hsm_keyvault_random(out, rand_len);
            if (status == PSA_SUCCESS) {
                out_len = rand_len;
            }
        }
        break;
    case WT_CRYPTO_OP_HASH:
        status = wt_native_hash(payload, payload_len, out, out_cap,
                                &out_len);
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }

    wire_status = (int32_t)status;
    (void)memcpy(resp, &wire_status, sizeof(wire_status));
    *resp_len = sizeof(wire_status) + out_len;
    return 0;
}
