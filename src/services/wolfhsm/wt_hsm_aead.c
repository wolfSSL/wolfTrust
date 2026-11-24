/* wt_hsm_aead.c
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

/* AES-256 AEAD for the vault sealer and native vault key encryption: GCM,
 * or CCM under WT_AEAD_CCM. Callers own the key and a unique nonce. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolftrust/services/hsm.h"
#include "wolftrust/zeroize.h"

#if defined(WT_AEAD_CCM) && !defined(HAVE_AESCCM)
#error "WT_AEAD_CCM needs HAVE_AESCCM"
#endif
#if !defined(WT_AEAD_CCM) && !defined(HAVE_AESGCM)
#error "the vault AEAD needs HAVE_AESGCM, or WT_AEAD_CCM"
#endif
/* With wolfPSA in the image, the AEAD runs on its streaming code, so
 * wolfCrypt's one-shot GCM or CCM is not linked twice over. */
#if defined(WT_SECURE_PSA) && defined(WT_AEAD_CCM)
#define WT_AEAD_WOLFPSA
#include "wolfpsa/psa_ccm.h"
#define WT_AEAD_SEAL wolfPSA_AesCcmEncrypt
#define WT_AEAD_OPEN wolfPSA_AesCcmDecrypt
#define WT_AEAD_AUTH_E AES_CCM_AUTH_E
#elif defined(WT_SECURE_PSA) && defined(WOLFPSA_GCM_ONESHOT_STREAM)
#define WT_AEAD_WOLFPSA
#include "wolfpsa/psa_gcm.h"
#define WT_AEAD_SEAL wolfPSA_AesGcmEncrypt
#define WT_AEAD_OPEN wolfPSA_AesGcmDecrypt
#define WT_AEAD_AUTH_E AES_GCM_AUTH_E
#endif

#ifdef WT_AEAD_WOLFPSA
psa_status_t wt_hsm_aead_encrypt(const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* aad, size_t aad_len,
                                 const uint8_t* in, size_t len, uint8_t* out,
                                 uint8_t* tag)
{
    int rc;

    rc = WT_AEAD_SEAL(key, WT_HSM_AEAD_KEY_LEN, nonce, WT_HSM_AEAD_NONCE_LEN,
                      aad, (word32)aad_len, in, (word32)len, out, tag,
                      WT_HSM_AEAD_TAG_LEN);
    return (rc == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t wt_hsm_aead_decrypt(const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* aad, size_t aad_len,
                                 const uint8_t* in, size_t len,
                                 const uint8_t* tag, uint8_t* out)
{
    int rc;

    rc = WT_AEAD_OPEN(key, WT_HSM_AEAD_KEY_LEN, nonce, WT_HSM_AEAD_NONCE_LEN,
                      aad, (word32)aad_len, in, (word32)len, tag,
                      WT_HSM_AEAD_TAG_LEN, out);
    if (rc == 0) {
        return PSA_SUCCESS;
    }
    /* No unauthenticated plaintext may survive a failed decrypt */
    wt_forceZero(out, len);
    return (rc == WT_AEAD_AUTH_E) ? PSA_ERROR_INVALID_SIGNATURE :
        PSA_ERROR_GENERIC_ERROR;
}
#else

psa_status_t wt_hsm_aead_encrypt(const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* aad, size_t aad_len,
                                 const uint8_t* in, size_t len, uint8_t* out,
                                 uint8_t* tag)
{
    Aes aes;
    int rc;

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
#ifdef WT_AEAD_CCM
        rc = wc_AesCcmSetKey(&aes, key, WT_HSM_AEAD_KEY_LEN);
        if (rc == 0) {
            rc = wc_AesCcmEncrypt(&aes, out, in, (word32)len, nonce,
                                  WT_HSM_AEAD_NONCE_LEN, tag,
                                  WT_HSM_AEAD_TAG_LEN, aad, (word32)aad_len);
        }
#else
        rc = wc_AesGcmSetKey(&aes, key, WT_HSM_AEAD_KEY_LEN);
        if (rc == 0) {
            rc = wc_AesGcmEncrypt(&aes, out, in, (word32)len, nonce,
                                  WT_HSM_AEAD_NONCE_LEN, tag,
                                  WT_HSM_AEAD_TAG_LEN, aad, (word32)aad_len);
        }
#endif
        wc_AesFree(&aes);
    }
    return (rc == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t wt_hsm_aead_decrypt(const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* aad, size_t aad_len,
                                 const uint8_t* in, size_t len,
                                 const uint8_t* tag, uint8_t* out)
{
    Aes aes;
    psa_status_t status = PSA_SUCCESS;
    int rc;

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
#ifdef WT_AEAD_CCM
        rc = wc_AesCcmSetKey(&aes, key, WT_HSM_AEAD_KEY_LEN);
        if (rc == 0) {
            rc = wc_AesCcmDecrypt(&aes, out, in, (word32)len, nonce,
                                  WT_HSM_AEAD_NONCE_LEN, tag,
                                  WT_HSM_AEAD_TAG_LEN, aad, (word32)aad_len);
        }
        if (rc == AES_CCM_AUTH_E) {
            status = PSA_ERROR_INVALID_SIGNATURE;
        }
#else
        rc = wc_AesGcmSetKey(&aes, key, WT_HSM_AEAD_KEY_LEN);
        if (rc == 0) {
            rc = wc_AesGcmDecrypt(&aes, out, in, (word32)len, nonce,
                                  WT_HSM_AEAD_NONCE_LEN, tag,
                                  WT_HSM_AEAD_TAG_LEN, aad, (word32)aad_len);
        }
        if (rc == AES_GCM_AUTH_E) {
            status = PSA_ERROR_INVALID_SIGNATURE;
        }
#endif
        wc_AesFree(&aes);
    }
    if (rc != 0) {
        /* No unauthenticated plaintext may survive a failed decrypt */
        wt_forceZero(out, len);
        if (status == PSA_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
    }
    return status;
}
#endif /* WT_AEAD_WOLFPSA */
