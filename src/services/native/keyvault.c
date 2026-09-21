/* keyvault.c
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

/* wolfCrypt key-op backend (WT-FFM-0046): every private-key computation runs
 * inside the privileged vault domain against material that never leaves it.
 * Keys are vault NVM objects (shared (owner, sub_owner, uid) directory)
 * stored SENSITIVE + NONEXPORTABLE, so no *Checked NVM path can return the
 * bytes, the storage face refuses key-flagged objects, and no wire op
 * exports private material — three independent layers between a compromised
 * Secure Partition and raw key bytes, which is the property TF-M's
 * Crypto-partition-RAM key storage does not have. P-256 objects store
 * [d 32][X9.63 public 65] with the public point derived once at creation;
 * AES-256 objects store the raw 32-byte key. */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_nvm.h"

#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/crypto_native.h"

#include <string.h>

#define WT_HSM_KEY_P256_OBJ_LEN \
    (WT_VAULT_KEY_MATERIAL_LEN + WT_VAULT_KEY_PUB_LEN)
#define WT_HSM_KEY_AES_OBJ_LEN WT_VAULT_KEY_MATERIAL_LEN

#define WT_HSM_KEY_DER_SIG_MAX 80U

#define WT_HSM_KEY_LABEL(usage, type) \
    (WT_VAULT_FLAG_KEY | ((usage) & WT_VAULT_KEY_USAGE_MASK) | \
     (((uint32_t)(type) & 0xFFU) << 24))
#define WT_HSM_KEY_TYPE_OF(flags) (((flags) >> 24) & 0xFFU)

static whNvmContext* g_kv_nvm;
static WC_RNG g_kv_rng;
static int g_kv_rng_ready;

int wt_hsm_keyvault_init(whNvmContext* nvm)
{
    if (nvm == NULL) {
        return -1;
    }
    g_kv_nvm = nvm;
    return 0;
}

/* Fault-recovery hook (WT-SYS-0008): the vault DRBG is the only mutable crypto
 * state that outlives a torn native request. Invalidate it so the restarted
 * service re-seeds on next use; a re-seed failure then fails the op closed
 * rather than drawing from a half-updated generator. */
void wt_hsm_keyvault_reset(void)
{
    if (g_kv_rng_ready != 0) {
        (void)wc_FreeRng(&g_kv_rng);
        g_kv_rng_ready = 0;
    }
}

static void wt_hsm_kv_zeroize(uint8_t* buf, size_t len)
{
    volatile uint8_t* p = buf;
    size_t i;

    for (i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

static psa_status_t wt_hsm_kv_rng(WC_RNG** out)
{
    if (g_kv_rng_ready == 0) {
        if (wc_InitRng_ex(&g_kv_rng, NULL, INVALID_DEVID) != 0) {
            return PSA_ERROR_GENERIC_ERROR;
        }
        g_kv_rng_ready = 1;
    }
    *out = &g_kv_rng;
    return PSA_SUCCESS;
}

/* Vault-domain randomness (WT-FFM-0054): serves the vault RANDOM face and
 * the native wire so non-secure DRBG seeds come from the same vault RNG
 * that generates key material. */
psa_status_t wt_hsm_keyvault_random(uint8_t* out, size_t len)
{
    WC_RNG* rng;
    psa_status_t status;

    if (out == NULL || len == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_hsm_kv_rng(&rng);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (wc_RNG_GenerateBlock(rng, out, (word32)len) != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

/* Store new key material at a free directory slot; refuses any existing
 * object (storage or key) at the same (owner, sub, uid) with ALREADY_EXISTS,
 * matching psa_import_key/psa_generate_key on an occupied persistent id. */
static psa_status_t wt_hsm_kv_store(int32_t owner, int32_t sub, uint64_t uid,
                                    uint32_t type, uint32_t usage,
                                    const uint8_t* obj, size_t obj_len)
{
    whNvmMetadata meta;
    whNvmId free_id = WH_NVM_ID_INVALID;
    psa_status_t status;
    int rc;

    status = wt_hsm_vault_lookup(owner, sub, uid, NULL, NULL, &free_id);
    if (status == PSA_SUCCESS) {
        return PSA_ERROR_ALREADY_EXISTS;
    }
    if (status != PSA_ERROR_DOES_NOT_EXIST) {
        return status;
    }
    if (free_id == WH_NVM_ID_INVALID) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    /* Reserve and reclaim before the add, exactly like wt_hsm_vault_set: key
     * generate/destroy churn over the native wire must not fill the shared log
     * or eat the headroom the seal-counter table and rollback floor need. */
    status = wt_hsm_vault_reserve_object((whNvmSize)obj_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = free_id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE;
    meta.len = (whNvmSize)obj_len;
    wt_hsm_vault_make_label(meta.label, owner, sub, uid,
                            WT_HSM_KEY_LABEL(usage, type));
    rc = wh_Nvm_AddObject(g_kv_nvm, &meta, (whNvmSize)obj_len, obj);
    return (rc == WH_ERROR_OK) ? PSA_SUCCESS : PSA_ERROR_STORAGE_FAILURE;
}

/* Load key material for one operation: the object must be a key of the
 * expected type carrying the required usage bit. The plain (non-Checked)
 * read is the privileged domain's internal path — NONEXPORTABLE blocks
 * every Checked consumer. Caller zeroizes obj after use. */
static psa_status_t wt_hsm_kv_load(int32_t owner, int32_t sub, uint64_t uid,
                                   uint32_t type, uint32_t usage_needed,
                                   uint8_t* obj, size_t obj_len)
{
    whNvmMetadata meta;
    whNvmId id = WH_NVM_ID_INVALID;
    uint32_t flags;
    psa_status_t status;

    if (g_kv_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = wt_hsm_vault_lookup(owner, sub, uid, &id, &meta, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    flags = wt_hsm_vault_flags_of(meta.label);
    if ((flags & WT_VAULT_FLAG_KEY) == 0U) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (WT_HSM_KEY_TYPE_OF(flags) != type ||
            (flags & usage_needed) != usage_needed) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (meta.len != obj_len) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    if (wh_Nvm_Read(g_kv_nvm, id, 0U, (whNvmSize)obj_len, obj) !=
            WH_ERROR_OK) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    return PSA_SUCCESS;
}

/* Derive [d][X9.63 public] from a P-256 private scalar. */
static psa_status_t wt_hsm_kv_p256_object(const uint8_t* d, uint8_t* obj)
{
    ecc_key key;
    word32 len;
    int rc;

    rc = wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
    if (rc != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    rc = wc_ecc_import_private_key_ex(d, WT_VAULT_KEY_MATERIAL_LEN, NULL, 0U,
                                      &key, ECC_SECP256R1);
    if (rc == 0) {
        rc = wc_ecc_make_pub(&key, NULL);
    }
    if (rc == 0) {
        (void)memcpy(obj, d, WT_VAULT_KEY_MATERIAL_LEN);
        len = WT_VAULT_KEY_PUB_LEN;
        rc = wc_ecc_export_x963(&key, obj + WT_VAULT_KEY_MATERIAL_LEN, &len);
        if (rc == 0 && len != WT_VAULT_KEY_PUB_LEN) {
            rc = -1;
        }
    }
    wc_ecc_free(&key);
    return (rc == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

static psa_status_t wt_hsm_kv_generate(int32_t owner, int32_t sub,
                                       uint64_t uid, uint32_t type,
                                       uint32_t usage)
{
    uint8_t obj[WT_HSM_KEY_P256_OBJ_LEN];
    uint8_t d[WT_VAULT_KEY_MATERIAL_LEN];
    ecc_key key;
    WC_RNG* rng;
    word32 len;
    psa_status_t status;
    int rc;

    if (g_kv_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((usage & ~WT_VAULT_KEY_USAGE_MASK) != 0U || usage == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_hsm_kv_rng(&rng);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (type == WT_VAULT_KEY_P256) {
        rc = wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
        if (rc != 0) {
            return PSA_ERROR_GENERIC_ERROR;
        }
        rc = wc_ecc_make_key_ex(rng, 32, &key, ECC_SECP256R1);
        if (rc == 0) {
            len = WT_VAULT_KEY_MATERIAL_LEN;
            rc = wc_ecc_export_private_only(&key, obj, &len);
        }
        if (rc == 0) {
            len = WT_VAULT_KEY_PUB_LEN;
            rc = wc_ecc_export_x963(&key, obj + WT_VAULT_KEY_MATERIAL_LEN,
                                    &len);
        }
        wc_ecc_free(&key);
        if (rc != 0) {
            wt_hsm_kv_zeroize(obj, sizeof(obj));
            return PSA_ERROR_GENERIC_ERROR;
        }
        status = wt_hsm_kv_store(owner, sub, uid, type, usage, obj,
                                 WT_HSM_KEY_P256_OBJ_LEN);
        wt_hsm_kv_zeroize(obj, sizeof(obj));
        return status;
    }
    if (type == WT_VAULT_KEY_AES256) {
        if (wc_RNG_GenerateBlock(rng, d, WT_VAULT_KEY_MATERIAL_LEN) != 0) {
            return PSA_ERROR_GENERIC_ERROR;
        }
        status = wt_hsm_kv_store(owner, sub, uid, type, usage, d,
                                 WT_HSM_KEY_AES_OBJ_LEN);
        wt_hsm_kv_zeroize(d, sizeof(d));
        return status;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_hsm_kv_import(int32_t owner, int32_t sub, uint64_t uid,
                                     uint32_t type, uint32_t usage,
                                     const uint8_t* data, size_t len)
{
    uint8_t obj[WT_HSM_KEY_P256_OBJ_LEN];
    psa_status_t status;

    if (g_kv_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((usage & ~WT_VAULT_KEY_USAGE_MASK) != 0U || usage == 0U ||
            len != WT_VAULT_KEY_MATERIAL_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (type == WT_VAULT_KEY_P256) {
        status = wt_hsm_kv_p256_object(data, obj);
        if (status == PSA_SUCCESS) {
            status = wt_hsm_kv_store(owner, sub, uid, type, usage, obj,
                                     WT_HSM_KEY_P256_OBJ_LEN);
        }
        wt_hsm_kv_zeroize(obj, sizeof(obj));
        return status;
    }
    if (type == WT_VAULT_KEY_AES256) {
        return wt_hsm_kv_store(owner, sub, uid, type, usage, data,
                               WT_HSM_KEY_AES_OBJ_LEN);
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

/* Public halves are exportable by design; usage bits do not gate this. */
static psa_status_t wt_hsm_kv_export_public(int32_t owner, int32_t sub,
                                            uint64_t uid, uint8_t* out,
                                            size_t cap, size_t* out_len)
{
    uint8_t obj[WT_HSM_KEY_P256_OBJ_LEN];
    psa_status_t status;

    if (cap < WT_VAULT_KEY_PUB_LEN) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    status = wt_hsm_kv_load(owner, sub, uid, WT_VAULT_KEY_P256, 0U, obj,
                            WT_HSM_KEY_P256_OBJ_LEN);
    if (status != PSA_SUCCESS) {
        return status;
    }
    (void)memcpy(out, obj + WT_VAULT_KEY_MATERIAL_LEN, WT_VAULT_KEY_PUB_LEN);
    wt_hsm_kv_zeroize(obj, sizeof(obj));
    *out_len = WT_VAULT_KEY_PUB_LEN;
    return PSA_SUCCESS;
}

static psa_status_t wt_hsm_kv_sign(int32_t owner, int32_t sub, uint64_t uid,
                                   const uint8_t* digest, size_t digest_len,
                                   uint8_t* sig, size_t cap, size_t* out_len)
{
    uint8_t obj[WT_HSM_KEY_P256_OBJ_LEN];
    uint8_t der[WT_HSM_KEY_DER_SIG_MAX];
    uint8_t r[WT_VAULT_KEY_MATERIAL_LEN];
    uint8_t s[WT_VAULT_KEY_MATERIAL_LEN];
    ecc_key key;
    WC_RNG* rng;
    word32 der_len = sizeof(der);
    word32 r_len = sizeof(r);
    word32 s_len = sizeof(s);
    psa_status_t status;
    int rc;

    if (digest_len != WT_VAULT_KEY_DIGEST_LEN ||
            cap < WT_VAULT_KEY_SIG_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_hsm_kv_load(owner, sub, uid, WT_VAULT_KEY_P256,
                            WT_VAULT_KEY_USAGE_SIGN, obj,
                            WT_HSM_KEY_P256_OBJ_LEN);
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* Capture the vault DRBG only after the NVM lock is dropped: a
     * fault-recovery reset during the lock wait must not free the RNG out
     * from under this in-flight signature. */
    status = wt_hsm_kv_rng(&rng);
    if (status != PSA_SUCCESS) {
        wt_hsm_kv_zeroize(obj, sizeof(obj));
        return status;
    }
    rc = wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_ecc_import_private_key_ex(obj, WT_VAULT_KEY_MATERIAL_LEN,
                                          NULL, 0U, &key, ECC_SECP256R1);
        if (rc == 0) {
            rc = wc_ecc_sign_hash(digest, (word32)digest_len, der, &der_len,
                                  rng, &key);
        }
        wc_ecc_free(&key);
    }
    wt_hsm_kv_zeroize(obj, sizeof(obj));
    if (rc == 0) {
        rc = wc_ecc_sig_to_rs(der, der_len, r, &r_len, s, &s_len);
    }
    if (rc != 0 || r_len > 32U || s_len > 32U) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    /* Fixed-width raw r||s, left-padded with zeros. */
    (void)memset(sig, 0, WT_VAULT_KEY_SIG_LEN);
    (void)memcpy(sig + (32U - r_len), r, r_len);
    (void)memcpy(sig + 32U + (32U - s_len), s, s_len);
    *out_len = WT_VAULT_KEY_SIG_LEN;
    return PSA_SUCCESS;
}

static psa_status_t wt_hsm_kv_verify(int32_t owner, int32_t sub, uint64_t uid,
                                     const uint8_t* digest, size_t digest_len,
                                     const uint8_t* sig, size_t sig_len)
{
    uint8_t obj[WT_HSM_KEY_P256_OBJ_LEN];
    uint8_t der[WT_HSM_KEY_DER_SIG_MAX];
    ecc_key key;
    word32 der_len = sizeof(der);
    int res = 0;
    psa_status_t status;
    int rc;

    if (digest_len != WT_VAULT_KEY_DIGEST_LEN ||
            sig_len != WT_VAULT_KEY_SIG_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_hsm_kv_load(owner, sub, uid, WT_VAULT_KEY_P256,
                            WT_VAULT_KEY_USAGE_VERIFY, obj,
                            WT_HSM_KEY_P256_OBJ_LEN);
    if (status != PSA_SUCCESS) {
        return status;
    }
    rc = wc_ecc_rs_raw_to_sig(sig, 32U, sig + 32U, 32U, der, &der_len);
    if (rc == 0) {
        rc = wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
    }
    if (rc == 0) {
        rc = wc_ecc_import_x963_ex(obj + WT_VAULT_KEY_MATERIAL_LEN,
                                   WT_VAULT_KEY_PUB_LEN, &key, ECC_SECP256R1);
        if (rc == 0) {
            rc = wc_ecc_verify_hash(der, der_len, digest, (word32)digest_len,
                                    &res, &key);
        }
        wc_ecc_free(&key);
    }
    wt_hsm_kv_zeroize(obj, sizeof(obj));
    if (rc != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return (res == 1) ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}

static psa_status_t wt_hsm_kv_encrypt(int32_t owner, int32_t sub,
                                      uint64_t uid, const uint8_t* input,
                                      size_t input_len, uint8_t* out,
                                      size_t cap, size_t* out_len)
{
    uint8_t obj[WT_HSM_KEY_AES_OBJ_LEN];
    Aes aes;
    WC_RNG* rng;
    psa_status_t status;
    int rc;

    if (cap < input_len + WT_VAULT_KEY_NONCE_LEN + WT_VAULT_KEY_TAG_LEN) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    status = wt_hsm_kv_load(owner, sub, uid, WT_VAULT_KEY_AES256,
                            WT_VAULT_KEY_USAGE_ENCRYPT, obj,
                            WT_HSM_KEY_AES_OBJ_LEN);
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* Capture the vault DRBG only after the NVM lock is dropped (see the
     * sign path): a fault-recovery reset during the lock wait must not free
     * the RNG mid-encrypt. */
    status = wt_hsm_kv_rng(&rng);
    if (status != PSA_SUCCESS) {
        wt_hsm_kv_zeroize(obj, sizeof(obj));
        return status;
    }
    rc = wc_RNG_GenerateBlock(rng, out, WT_VAULT_KEY_NONCE_LEN);
    if (rc == 0) {
        rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            rc = wc_AesGcmSetKey(&aes, obj, WT_VAULT_KEY_MATERIAL_LEN);
            if (rc == 0) {
                rc = wc_AesGcmEncrypt(&aes, out + WT_VAULT_KEY_NONCE_LEN,
                                      input, (word32)input_len, out,
                                      WT_VAULT_KEY_NONCE_LEN,
                                      out + WT_VAULT_KEY_NONCE_LEN +
                                          input_len,
                                      WT_VAULT_KEY_TAG_LEN, NULL, 0U);
            }
            wc_AesFree(&aes);
        }
    }
    wt_hsm_kv_zeroize(obj, sizeof(obj));
    if (rc != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    *out_len = input_len + WT_VAULT_KEY_NONCE_LEN + WT_VAULT_KEY_TAG_LEN;
    return PSA_SUCCESS;
}

static psa_status_t wt_hsm_kv_decrypt(int32_t owner, int32_t sub,
                                      uint64_t uid, const uint8_t* input,
                                      size_t input_len, uint8_t* out,
                                      size_t cap, size_t* out_len)
{
    uint8_t obj[WT_HSM_KEY_AES_OBJ_LEN];
    Aes aes;
    size_t pt_len;
    psa_status_t status;
    int rc;

    if (input_len < WT_VAULT_KEY_NONCE_LEN + WT_VAULT_KEY_TAG_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    pt_len = input_len - WT_VAULT_KEY_NONCE_LEN - WT_VAULT_KEY_TAG_LEN;
    if (cap < pt_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    status = wt_hsm_kv_load(owner, sub, uid, WT_VAULT_KEY_AES256,
                            WT_VAULT_KEY_USAGE_DECRYPT, obj,
                            WT_HSM_KEY_AES_OBJ_LEN);
    if (status != PSA_SUCCESS) {
        return status;
    }
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_AesGcmSetKey(&aes, obj, WT_VAULT_KEY_MATERIAL_LEN);
        if (rc == 0) {
            rc = wc_AesGcmDecrypt(&aes, out,
                                  input + WT_VAULT_KEY_NONCE_LEN,
                                  (word32)pt_len, input,
                                  WT_VAULT_KEY_NONCE_LEN,
                                  input + input_len - WT_VAULT_KEY_TAG_LEN,
                                  WT_VAULT_KEY_TAG_LEN, NULL, 0U);
        }
        wc_AesFree(&aes);
    }
    wt_hsm_kv_zeroize(obj, sizeof(obj));
    if (rc != 0) {
        /* wolfSSL leaves out[] undefined after a non-zero AES-GCM decrypt;
         * clear the plaintext region so no unauthenticated bytes survive in
         * the shared response band. */
        wt_hsm_kv_zeroize(out, pt_len);
        return (rc == AES_GCM_AUTH_E) ? PSA_ERROR_INVALID_SIGNATURE :
                                        PSA_ERROR_GENERIC_ERROR;
    }
    *out_len = pt_len;
    return PSA_SUCCESS;
}

/* Key destruction is key-typed on purpose: the storage-face remove applies
 * PSA storage semantics to the label's low bits, where a key object keeps its
 * usage mask, so it would read a signing key's usage bit as WRITE_ONCE. */
psa_status_t wt_hsm_keyvault_destroy(int32_t owner, int32_t sub, uint64_t uid)
{
    whNvmMetadata meta;
    whNvmId id = WH_NVM_ID_INVALID;
    psa_status_t status;

    if (g_kv_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = wt_hsm_vault_lookup(owner, sub, uid, &id, &meta, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if ((wt_hsm_vault_flags_of(meta.label) & WT_VAULT_FLAG_KEY) == 0U) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (wh_Nvm_DestroyObjectsChecked(g_kv_nvm, 1U, &id) != WH_ERROR_OK) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    return PSA_SUCCESS;
}

const wt_vault_key_backend_t wt_hsm_key_backend = {
    wt_hsm_kv_generate,
    wt_hsm_kv_import,
    wt_hsm_kv_export_public,
    wt_hsm_kv_sign,
    wt_hsm_kv_verify,
    wt_hsm_kv_encrypt,
    wt_hsm_kv_decrypt
};
