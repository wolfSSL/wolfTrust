/* wt_hsm_seal.c
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

/* wolfCrypt AES-256-GCM vault sealer (WT-FFM-0048). The device-unique key is
 * generated on first boot, stored at WT_HSM_SEAL_KEY_ID as NONEXPORTABLE and
 * immutable, and cached in the shared keystore trust band granted only to the
 * confined keystore partitions. The GCM nonce is the caller-supplied
 * monotonic rollback counter, unique per sealed write by construction, so a
 * rolled-back ciphertext fails tag authentication on unseal. */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_nvm.h"

#include "wolftrust/services/hsm.h"

#include <string.h>

#define WT_HSM_SEAL_KEY_LEN   32U
#define WT_HSM_SEAL_NONCE_LEN 12U

#define WT_HSM_SEAL_LABEL_MAGIC 0x4B535457UL /* "WTSK" little-endian */

static uint8_t g_seal_key[WT_HSM_SEAL_KEY_LEN];
static int g_seal_ready;

static void wt_hsm_seal_zeroize(uint8_t* buf, size_t len)
{
    volatile uint8_t* p = buf;
    size_t i;

    for (i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

static void wt_hsm_seal_nonce(uint8_t* nonce, uint64_t counter)
{
    (void)memset(nonce, 0, WT_HSM_SEAL_NONCE_LEN);
    (void)memcpy(nonce, &counter, sizeof(counter));
    nonce[8] = (uint8_t)'W';
    nonce[9] = (uint8_t)'T';
    nonce[10] = (uint8_t)'P';
    nonce[11] = (uint8_t)'S';
}

int wt_hsm_seal_init(whNvmContext* nvm)
{
    whNvmMetadata meta;
    WC_RNG rng;
    uint32_t magic = WT_HSM_SEAL_LABEL_MAGIC;
    int rc;

    if (nvm == NULL) {
        return -1;
    }
    /* Fail closed across a re-init: drop readiness until the key is proven
     * present again, so a partial reinit can never seal with a stale key. */
    g_seal_ready = 0;
    rc = wh_Nvm_GetMetadata(nvm, WT_HSM_SEAL_KEY_ID, &meta);
    if (rc == WH_ERROR_OK) {
        if (meta.len != WT_HSM_SEAL_KEY_LEN) {
            wt_hsm_seal_zeroize(g_seal_key, sizeof(g_seal_key));
            return -1;
        }
        rc = wh_Nvm_Read(nvm, WT_HSM_SEAL_KEY_ID, 0U, WT_HSM_SEAL_KEY_LEN,
                         g_seal_key);
        if (rc != WH_ERROR_OK) {
            wt_hsm_seal_zeroize(g_seal_key, sizeof(g_seal_key));
            return -1;
        }
    }
    else if (rc == WH_ERROR_NOTFOUND) {
        rc = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
        if (rc != 0) {
            return -1;
        }
        rc = wc_RNG_GenerateBlock(&rng, g_seal_key, WT_HSM_SEAL_KEY_LEN);
        (void)wc_FreeRng(&rng);
        if (rc != 0) {
            wt_hsm_seal_zeroize(g_seal_key, sizeof(g_seal_key));
            return -1;
        }
        (void)memset(&meta, 0, sizeof(meta));
        meta.id = WT_HSM_SEAL_KEY_ID;
        meta.access = WH_NVM_ACCESS_ANY;
        meta.flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE |
                     WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE;
        meta.len = WT_HSM_SEAL_KEY_LEN;
        (void)memcpy(meta.label, &magic, sizeof(magic));
        rc = wh_Nvm_AddObject(nvm, &meta, WT_HSM_SEAL_KEY_LEN, g_seal_key);
        if (rc != WH_ERROR_OK) {
            wt_hsm_seal_zeroize(g_seal_key, sizeof(g_seal_key));
            return -1;
        }
    }
    else {
        wt_hsm_seal_zeroize(g_seal_key, sizeof(g_seal_key));
        return -1;
    }
    g_seal_ready = 1;
    return 0;
}

static psa_status_t wt_hsm_seal_seal(const uint8_t* aad, size_t aad_len,
                                     uint64_t counter, const uint8_t* pt,
                                     size_t pt_len, uint8_t* ct)
{
    Aes aes;
    uint8_t nonce[WT_HSM_SEAL_NONCE_LEN];
    int rc;

    if (g_seal_ready == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    wt_hsm_seal_nonce(nonce, counter);
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_AesGcmSetKey(&aes, g_seal_key, WT_HSM_SEAL_KEY_LEN);
    }
    if (rc == 0) {
        rc = wc_AesGcmEncrypt(&aes, ct, pt, (word32)pt_len, nonce,
                              WT_HSM_SEAL_NONCE_LEN, ct + pt_len,
                              WT_VAULT_SEAL_TAG_LEN, aad, (word32)aad_len);
    }
    wc_AesFree(&aes);
    return (rc == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

static psa_status_t wt_hsm_seal_unseal(const uint8_t* aad, size_t aad_len,
                                       uint64_t counter, const uint8_t* ct,
                                       size_t ct_len, uint8_t* pt)
{
    Aes aes;
    uint8_t nonce[WT_HSM_SEAL_NONCE_LEN];
    size_t pt_len;
    int rc;

    if (g_seal_ready == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (ct_len < WT_VAULT_SEAL_TAG_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    pt_len = ct_len - WT_VAULT_SEAL_TAG_LEN;
    wt_hsm_seal_nonce(nonce, counter);
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_AesGcmSetKey(&aes, g_seal_key, WT_HSM_SEAL_KEY_LEN);
    }
    if (rc == 0) {
        rc = wc_AesGcmDecrypt(&aes, pt, ct, (word32)pt_len, nonce,
                              WT_HSM_SEAL_NONCE_LEN, ct + pt_len,
                              WT_VAULT_SEAL_TAG_LEN, aad, (word32)aad_len);
    }
    wc_AesFree(&aes);
    if (rc == AES_GCM_AUTH_E) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    return (rc == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

const wt_vault_sealer_t wt_hsm_sealer = {
    wt_hsm_seal_seal,
    wt_hsm_seal_unseal
};
