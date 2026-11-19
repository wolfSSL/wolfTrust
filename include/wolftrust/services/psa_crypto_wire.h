/* psa_crypto_wire.h
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

#ifndef WOLFTRUST_SERVICES_PSA_CRYPTO_WIRE_H
#define WOLFTRUST_SERVICES_PSA_CRYPTO_WIRE_H

#include <stdint.h>

#include "wolftrust/services/crypto_native.h"

/* Secure PSA Crypto (WT_SECURE_PSA=1) rides the native wire: hdr.op is
 * WT_CRYPTO_OP_PSA, hdr.usage the function id, hdr.key_type the version, and
 * the payload is [wt_psa_wire_args_t][input bytes]. The response
 * payload after the status is [wt_psa_wire_ret_t][output bytes]. */
#define WT_PSA_WIRE_VERSION   1U
#define WT_PSA_WIRE_VER_SHIFT 16U

#define WT_PSA_WIRE_IN_MAX  3U
#define WT_PSA_WIRE_OUT_MAX 2U

typedef struct wt_psa_wire_args {
    uint32_t a[4];
    uint32_t in_len[WT_PSA_WIRE_IN_MAX];
    uint32_t out_cap[WT_PSA_WIRE_OUT_MAX];
} wt_psa_wire_args_t;

/* op: the operation token after the call (0 once released); val: a key id
 * or a derivation capacity. */
typedef struct wt_psa_wire_ret {
    uint32_t op;
    uint32_t val;
    uint32_t out_len[WT_PSA_WIRE_OUT_MAX];
} wt_psa_wire_ret_t;

/* Serialized psa_key_attributes_t: type, bits, lifetime, usage, alg, alg2,
 * id as little-endian u16, u16, u32 x 5. */
#define WT_PSA_WIRE_ATTR_LEN 24U

enum wt_psa_fn {
    WT_PSA_FN_CRYPTO_INIT = 1,
    WT_PSA_FN_GENERATE_RANDOM,
    WT_PSA_FN_GET_KEY_ATTRIBUTES,
    WT_PSA_FN_IMPORT_KEY,
    WT_PSA_FN_EXPORT_KEY,
    WT_PSA_FN_EXPORT_PUBLIC_KEY,
    WT_PSA_FN_DESTROY_KEY,
    WT_PSA_FN_PURGE_KEY,
    WT_PSA_FN_COPY_KEY,
    WT_PSA_FN_GENERATE_KEY,
    WT_PSA_FN_HASH_COMPUTE,
    WT_PSA_FN_HASH_COMPARE,
    WT_PSA_FN_HASH_SETUP,
    WT_PSA_FN_HASH_UPDATE,
    WT_PSA_FN_HASH_FINISH,
    WT_PSA_FN_HASH_VERIFY,
    WT_PSA_FN_HASH_ABORT,
    WT_PSA_FN_HASH_CLONE,
    WT_PSA_FN_MAC_COMPUTE,
    WT_PSA_FN_MAC_VERIFY,
    WT_PSA_FN_MAC_SIGN_SETUP,
    WT_PSA_FN_MAC_VERIFY_SETUP,
    WT_PSA_FN_MAC_UPDATE,
    WT_PSA_FN_MAC_SIGN_FINISH,
    WT_PSA_FN_MAC_VERIFY_FINISH,
    WT_PSA_FN_MAC_ABORT,
    WT_PSA_FN_CIPHER_ENCRYPT,
    WT_PSA_FN_CIPHER_DECRYPT,
    WT_PSA_FN_CIPHER_ENCRYPT_SETUP,
    WT_PSA_FN_CIPHER_DECRYPT_SETUP,
    WT_PSA_FN_CIPHER_GENERATE_IV,
    WT_PSA_FN_CIPHER_SET_IV,
    WT_PSA_FN_CIPHER_UPDATE,
    WT_PSA_FN_CIPHER_FINISH,
    WT_PSA_FN_CIPHER_ABORT,
    WT_PSA_FN_AEAD_ENCRYPT,
    WT_PSA_FN_AEAD_DECRYPT,
    WT_PSA_FN_AEAD_ENCRYPT_SETUP,
    WT_PSA_FN_AEAD_DECRYPT_SETUP,
    WT_PSA_FN_AEAD_GENERATE_NONCE,
    WT_PSA_FN_AEAD_SET_NONCE,
    WT_PSA_FN_AEAD_SET_LENGTHS,
    WT_PSA_FN_AEAD_UPDATE_AD,
    WT_PSA_FN_AEAD_UPDATE,
    WT_PSA_FN_AEAD_FINISH,
    WT_PSA_FN_AEAD_VERIFY,
    WT_PSA_FN_AEAD_ABORT,
    WT_PSA_FN_KDF_SETUP,
    WT_PSA_FN_KDF_GET_CAPACITY,
    WT_PSA_FN_KDF_SET_CAPACITY,
    WT_PSA_FN_KDF_INPUT_BYTES,
    WT_PSA_FN_KDF_INPUT_KEY,
    WT_PSA_FN_KDF_KEY_AGREEMENT,
    WT_PSA_FN_KDF_OUTPUT_BYTES,
    WT_PSA_FN_KDF_OUTPUT_KEY,
    WT_PSA_FN_KDF_INPUT_INTEGER,
    WT_PSA_FN_KDF_VERIFY_BYTES,
    WT_PSA_FN_KDF_VERIFY_KEY,
    WT_PSA_FN_KDF_ABORT,
    WT_PSA_FN_SIGN_HASH,
    WT_PSA_FN_VERIFY_HASH,
    WT_PSA_FN_SIGN_MESSAGE,
    WT_PSA_FN_VERIFY_MESSAGE,
    WT_PSA_FN_RAW_KEY_AGREEMENT,
    WT_PSA_FN_KEY_AGREEMENT,
    WT_PSA_FN_ASYMMETRIC_ENCRYPT,
    WT_PSA_FN_ASYMMETRIC_DECRYPT,
    WT_PSA_FN_COUNT
};

#endif /* WOLFTRUST_SERVICES_PSA_CRYPTO_WIRE_H */
