/* main.c
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

/* Secure PSA Crypto end to end: the Non-secure client library against the
 * service in its own process, with the SPM-stamped client id under test
 * control. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "psa/crypto.h"

#include "wolftrust/crypto_native_client.h"
#include "wolftrust/services/crypto_native.h"
#include "wolftrust/services/psa_crypto_wire.h"
#include "transport.h"

#define GUEST0 (-1)
#define GUEST1 (-2)
#define BIG    1500U
/* Past what the old 2,048-byte staging buffer could carry. */
#define HUGE   5000U

/* lean and symmetric offer one AEAD, CCM unless built with WT_AEAD=gcm */
#ifdef PSA_WANT_ALG_GCM
#define WT_TEST_AEAD PSA_ALG_GCM
#else
#define WT_TEST_AEAD PSA_ALG_CCM
#endif

static int g_failures;

static void check(int ok, const char* what)
{
    (void)printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

static psa_key_id_t aes_key(psa_key_id_t id, uint8_t fill, psa_status_t* st)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    uint8_t key[16];
    psa_key_id_t out = PSA_KEY_ID_NULL;

    (void)memset(key, fill, sizeof(key));
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, WT_TEST_AEAD);
    if (id != PSA_KEY_ID_NULL) {
        psa_set_key_id(&attr, id);
    }
    *st = psa_import_key(&attr, key, sizeof(key), &out);
    return out;
}

static psa_key_id_t ecc_key(psa_status_t* st)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t out = PSA_KEY_ID_NULL;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    *st = psa_generate_key(&attr, &out);
    return out;
}

/* Imports a 128-bit AES key for alg and runs one 16-byte one-shot with it. */
static psa_status_t aes_oneshot(psa_algorithm_t alg, int decrypt)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    uint8_t key[16];
    uint8_t in[32];
    uint8_t out[64];
    uint8_t nonce[12];
    psa_key_id_t k = PSA_KEY_ID_NULL;
    psa_status_t st;
    size_t len = 0U;

    (void)memset(key, 0x5C, sizeof(key));
    (void)memset(in, 0x3A, sizeof(in));
    (void)memset(nonce, 0x01, sizeof(nonce));
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, alg);
    st = psa_import_key(&attr, key, sizeof(key), &k);
    if (st == PSA_SUCCESS && PSA_ALG_IS_AEAD(alg)) {
        st = psa_aead_encrypt(k, alg, nonce, sizeof(nonce), NULL, 0U, in, 16U,
                              out, sizeof(out), &len);
    }
    else if (st == PSA_SUCCESS && decrypt) {
        st = psa_cipher_decrypt(k, alg, in, 16U, out, sizeof(out), &len);
    }
    else if (st == PSA_SUCCESS) {
        st = psa_cipher_encrypt(k, alg, in, 16U, out, sizeof(out), &len);
    }
    if (k != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(k);
    }
    return st;
}

static psa_status_t pbkdf2_setup(void)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st;

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    (void)psa_key_derivation_abort(&op);
    return st;
}

/* What each WT_SECURE_PSA_PROFILE keeps and what it compiles out. */
static void test_profile(void)
{
    psa_status_t ecc = PSA_SUCCESS;
    psa_key_id_t k;

    check(psa_generate_random(NULL, 1U) == PSA_ERROR_INVALID_ARGUMENT,
          "generate_random refuses a NULL buffer");
#if defined(WT_SECURE_PSA_lean) || defined(WT_SECURE_PSA_symmetric)
#ifdef PSA_WANT_ALG_GCM
    check(aes_oneshot(PSA_ALG_GCM, 0) == PSA_SUCCESS &&
          aes_oneshot(PSA_ALG_CCM, 0) == PSA_ERROR_NOT_SUPPORTED,
          "WT_AEAD=gcm offers GCM and not CCM");
#else
    check(aes_oneshot(PSA_ALG_CCM, 0) == PSA_SUCCESS &&
          aes_oneshot(PSA_ALG_GCM, 0) == PSA_ERROR_NOT_SUPPORTED,
          "the one-AEAD profiles offer CCM and not GCM");
#endif
#else
    check(aes_oneshot(PSA_ALG_GCM, 0) == PSA_SUCCESS &&
          aes_oneshot(PSA_ALG_CCM, 0) == PSA_SUCCESS,
          "compat and standard offer GCM and CCM");
#endif
    k = ecc_key(&ecc);
    if (k != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(k);
    }
#if defined(WT_SECURE_PSA_compat)
    check(aes_oneshot(PSA_ALG_CBC_NO_PADDING, 1) == PSA_SUCCESS,
          "compat keeps CBC decryption");
    check(pbkdf2_setup() == PSA_SUCCESS, "compat keeps PBKDF2");
    check(ecc == PSA_SUCCESS, "compat keeps ECC");
#elif defined(WT_SECURE_PSA_standard)
    check(aes_oneshot(PSA_ALG_CBC_NO_PADDING, 0) == PSA_ERROR_NOT_SUPPORTED,
          "standard compiles out CBC");
    check(pbkdf2_setup() == PSA_ERROR_NOT_SUPPORTED,
          "standard compiles out PBKDF2");
    check(ecc == PSA_SUCCESS, "standard keeps ECC");
#elif defined(WT_SECURE_PSA_lean)
    check(aes_oneshot(PSA_ALG_ECB_NO_PADDING, 1) == PSA_ERROR_NOT_SUPPORTED,
          "lean compiles out AES decryption");
    check(ecc == PSA_SUCCESS, "lean keeps ECC");
#elif defined(WT_SECURE_PSA_symmetric)
    check(ecc == PSA_ERROR_NOT_SUPPORTED, "symmetric compiles out ECC");
#endif
}

static psa_status_t raw_init(void)
{
    wt_crypto_wire_req_t hdr;
    wt_psa_wire_args_t args;
    uint8_t resp[64];
    size_t got = 0U;

    (void)memset(&hdr, 0, sizeof(hdr));
    (void)memset(&args, 0, sizeof(args));
    hdr.op = WT_CRYPTO_OP_PSA;
    hdr.usage = WT_PSA_FN_CRYPTO_INIT;
    hdr.key_type = WT_PSA_WIRE_VERSION << WT_PSA_WIRE_VER_SHIFT;
    return wt_crypto_native_call(&hdr, (const uint8_t*)&args, sizeof(args),
                                 resp, sizeof(resp), &got);
}

static psa_status_t raw_key_op(uint8_t op, uint64_t uid)
{
    wt_crypto_wire_req_t hdr;
    uint8_t resp[64];
    size_t got = 0U;

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.op = op;
    hdr.uid = uid;
    return wt_crypto_native_call(&hdr, NULL, 0U, resp, sizeof(resp), &got);
}

static void test_lost_message(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_key_id_t k;
    psa_status_t st;
    static uint8_t big[BIG];
    static uint8_t ct[BIG + 16U];
    static uint8_t pt[BIG];
    uint8_t nonce[12];
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t len = 0U;
    size_t len2 = 0U;

    (void)memset(big, 0x5A, sizeof(big));
    (void)memset(nonce, 3, sizeof(nonce));
    wt_test_set_client(GUEST0);
    check(psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS,
          "hash setup for the lost-message test");
    wt_test_fail_call(2);
    check(psa_hash_update(&op, big, sizeof(big)) ==
          PSA_ERROR_COMMUNICATION_FAILURE,
          "a lost second piece fails a long update");
    check(psa_hash_abort(&op) == PSA_SUCCESS &&
          psa_hash_compute(PSA_ALG_SHA_256, big, sizeof(big), hash,
                           sizeof(hash), &len) == PSA_SUCCESS,
          "a long hash works again after the lost piece");
    k = aes_key(PSA_KEY_ID_NULL, 0x77, &st);
    check(st == PSA_SUCCESS &&
          psa_aead_encrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), NULL, 0U,
                           big, sizeof(big), ct, sizeof(ct), &len) ==
          PSA_SUCCESS, "AEAD encrypt for the lost-message decrypt");
    (void)memset(pt, 0xAA, sizeof(pt));
    wt_test_fail_call(7);
    check(psa_aead_decrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), NULL, 0U,
                           ct, len, pt, sizeof(pt), &len2) ==
          PSA_ERROR_COMMUNICATION_FAILURE && len2 == 0U && pt[0] == 0U &&
          pt[100] == 0U, "a lost piece of a long decrypt leaves no plaintext");
    check(psa_aead_decrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), NULL, 0U,
                           ct, len, pt, sizeof(pt), &len2) == PSA_SUCCESS &&
          len2 == sizeof(big) && memcmp(pt, big, sizeof(big)) == 0,
          "the decrypt works again after the lost piece");
    (void)psa_destroy_key(k);
}

static void test_malformed_reply(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    static uint8_t out[1500];

    wt_test_set_client(-1);
    wt_test_mangle_reply(1, WT_TEST_REPLY_SHORT);
    check(psa_hash_setup(&op, PSA_ALG_SHA_256) ==
          PSA_ERROR_COMMUNICATION_FAILURE, "a short reply fails the call");
    (void)psa_hash_abort(&op);
    wt_test_mangle_reply(2, WT_TEST_REPLY_SHORT);
    check(psa_generate_random(out, sizeof(out)) ==
          PSA_ERROR_COMMUNICATION_FAILURE,
          "a short reply to a later piece fails the call");
    wt_test_mangle_reply(1, WT_TEST_REPLY_OVERSIZE);
    check(psa_generate_random(out, sizeof(out)) ==
          PSA_ERROR_COMMUNICATION_FAILURE,
          "an output length past the capacity fails the call");
    check(psa_generate_random(out, sizeof(out)) == PSA_SUCCESS,
          "a long call works again after the malformed replies");
}

/* One-shots past one message run as multi-part sequences and match it. */
static void test_large_oneshots(psa_key_id_t k, const uint8_t* nonce)
{
    static uint8_t msg[HUGE];
    static uint8_t ct[HUGE + 16U];
    static uint8_t pt[HUGE];
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    uint8_t hash[32];
    uint8_t hash2[32];
    size_t len = 0U;
    size_t len2 = 0U;
    size_t i;

    for (i = 0U; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i * 7U);
    }
    check(psa_aead_encrypt(k, WT_TEST_AEAD, nonce, 12U, msg, 700U, msg,
                           sizeof(msg), ct, sizeof(ct), &len) == PSA_SUCCESS &&
          len == sizeof(msg) + 16U &&
          psa_aead_decrypt(k, WT_TEST_AEAD, nonce, 12U, msg, 700U, ct, len, pt,
                           sizeof(pt), &len2) == PSA_SUCCESS &&
          len2 == sizeof(msg) && memcmp(pt, msg, sizeof(msg)) == 0,
          "5,000-byte AEAD round trip with a 700-byte AD");
    check(psa_aead_encrypt(k, WT_TEST_AEAD, nonce, 12U, msg, 700U, msg,
                           sizeof(msg), ct, sizeof(msg), &len) ==
          PSA_ERROR_BUFFER_TOO_SMALL && len == 0U,
          "a long AEAD encrypt with no room for the tag fails");
    ct[sizeof(msg) - 1U] ^= 1U;
    (void)memset(pt, 0xAA, sizeof(pt));
    check(psa_aead_decrypt(k, WT_TEST_AEAD, nonce, 12U, msg, 700U, ct,
                           sizeof(msg) + 16U, pt, sizeof(pt), &len2) ==
          PSA_ERROR_INVALID_SIGNATURE && len2 == 0U && pt[0] == 0U &&
          pt[sizeof(pt) - 1U] == 0U,
          "a long AEAD decrypt with a bad tag leaves no plaintext");
    check(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash,
                           sizeof(hash), &len) == PSA_SUCCESS &&
          psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS &&
          psa_hash_update(&op, msg, 100U) == PSA_SUCCESS &&
          psa_hash_update(&op, msg + 100U, sizeof(msg) - 100U) ==
          PSA_SUCCESS &&
          psa_hash_finish(&op, hash2, sizeof(hash2), &len2) == PSA_SUCCESS &&
          memcmp(hash, hash2, sizeof(hash)) == 0,
          "a 5,000-byte one-shot hash matches the multi-part hash");
    check(psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg), hash,
                           sizeof(hash)) == PSA_SUCCESS,
          "a 5,000-byte hash_compare matches");
    hash[0] ^= 1U;
    check(psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg), hash,
                           sizeof(hash)) == PSA_ERROR_INVALID_SIGNATURE,
          "a 5,000-byte hash_compare against a wrong hash fails");
}

/* A guest holding all it can in its own arena does not starve the other. */
static void test_arena_isolation(void)
{
    psa_aead_operation_t ops[8];
    psa_key_id_t keys[10];
    psa_key_id_t k;
    psa_status_t st = PSA_SUCCESS;
    static uint8_t msg[HUGE];
    static uint8_t ct[HUGE + 16U];
    uint8_t nonce[12];
    size_t nops = 0U;
    size_t nkeys = 0U;
    size_t len = 0U;
    size_t i;

    (void)memset(msg, 0x42, sizeof(msg));
    (void)memset(nonce, 9, sizeof(nonce));
    wt_test_set_client(GUEST0);
    k = aes_key(PSA_KEY_ID_NULL, 0x24, &st);
    for (nops = 0U; st == PSA_SUCCESS && nops < 8U; nops++) {
        ops[nops] = psa_aead_operation_init();
        st = psa_aead_encrypt_setup(&ops[nops], k, WT_TEST_AEAD);
        if (st == PSA_SUCCESS) {
            st = psa_aead_set_nonce(&ops[nops], nonce, sizeof(nonce));
        }
    }
    check(st == PSA_ERROR_INSUFFICIENT_MEMORY,
          "guest0 fills its operation slots or its arena");
    st = PSA_SUCCESS;
    for (nkeys = 0U; st == PSA_SUCCESS && nkeys < 10U; nkeys++) {
        keys[nkeys] = aes_key(PSA_KEY_ID_NULL, 0x25, &st);
    }
    check(st == PSA_ERROR_INSUFFICIENT_MEMORY,
          "guest0 fills its key slots or its arena");

    wt_test_set_client(GUEST1);
    k = aes_key(PSA_KEY_ID_NULL, 0x26, &st);
    check(st == PSA_SUCCESS &&
          psa_aead_encrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), msg, 300U,
                           msg, sizeof(msg), ct, sizeof(ct), &len) ==
          PSA_SUCCESS && len == sizeof(msg) + 16U,
          "guest1 runs a long AEAD while guest0 holds everything it can");
    (void)psa_destroy_key(k);

    wt_test_set_client(GUEST0);
    for (i = 0U; i + 1U < nops; i++) {
        (void)psa_aead_abort(&ops[i]);
    }
    check(raw_init() == PSA_SUCCESS, "guest0 restarts and drops its state");
    k = aes_key(PSA_KEY_ID_NULL, 0x27, &st);
    check(st == PSA_SUCCESS &&
          psa_aead_encrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), NULL, 0U,
                           msg, sizeof(msg), ct, sizeof(ct), &len) ==
          PSA_SUCCESS, "guest0's arena is whole again after its restart");
    (void)psa_destroy_key(k);
    (void)keys;
}

static void test_basic(void)
{
    static uint8_t big[BIG];
    static uint8_t ct[BIG + 16];
    static uint8_t pt[BIG];
    uint8_t hash[32];
    uint8_t hash2[32];
    uint8_t sig[64];
    uint8_t pub[65];
    uint8_t nonce[12];
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_key_attributes_t attr;
    psa_key_id_t k;
    psa_status_t st;
    size_t len = 0U;
    size_t len2 = 0U;
    size_t i;

    for (i = 0U; i < sizeof(big); i++) {
        big[i] = (uint8_t)i;
    }
    (void)memset(nonce, 7, sizeof(nonce));
    check(psa_crypto_init() == PSA_SUCCESS, "psa_crypto_init");
    check(psa_generate_random(big, 600) == PSA_SUCCESS,
          "generate_random over two messages");
    for (i = 0U; i < sizeof(big); i++) {
        big[i] = (uint8_t)i;
    }
    check(psa_hash_compute(PSA_ALG_SHA_256, big, sizeof(big), hash,
                           sizeof(hash), &len) == PSA_SUCCESS && len == 32U,
          "hash_compute over a 1500-byte input");
    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&op, big, 700U);
    }
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&op, big + 700U, sizeof(big) - 700U);
    }
    if (st == PSA_SUCCESS) {
        st = psa_hash_finish(&op, hash2, sizeof(hash2), &len2);
    }
    check(st == PSA_SUCCESS && op.opaque == 0U &&
          memcmp(hash, hash2, sizeof(hash)) == 0,
          "multipart hash matches one-shot and releases its slot");

    k = aes_key(PSA_KEY_ID_NULL, 0x11, &st);
    check(st == PSA_SUCCESS, "import volatile AES key");
    attr = psa_key_attributes_init();
    check(psa_get_key_attributes(k, &attr) == PSA_SUCCESS &&
          psa_get_key_type(&attr) == PSA_KEY_TYPE_AES &&
          psa_get_key_bits(&attr) == 128U, "get_key_attributes of the new key");
    st = psa_aead_encrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), big, 20U, big,
                          sizeof(big), ct, sizeof(ct), &len);
    check(st == PSA_SUCCESS && len == sizeof(big) + 16U,
          "AEAD encrypt of 1500 bytes");
    st = psa_aead_decrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), big, 20U, ct,
                          len, pt, sizeof(pt), &len2);
    check(st == PSA_SUCCESS && len2 == sizeof(big) &&
          memcmp(pt, big, sizeof(big)) == 0, "AEAD decrypt round trip");
    ct[5] ^= 1U;
    (void)memset(pt, 0xAA, sizeof(pt));
    st = psa_aead_decrypt(k, WT_TEST_AEAD, nonce, sizeof(nonce), big, 20U, ct,
                          len, pt, sizeof(pt), &len2);
    check(st == PSA_ERROR_INVALID_SIGNATURE && len2 == 0U && pt[0] == 0U &&
          pt[100] == 0U && pt[sizeof(pt) - 1U] == 0U,
          "AEAD bad tag fails and releases no plaintext");
    test_large_oneshots(k, nonce);
    check(psa_destroy_key(k) == PSA_SUCCESS, "destroy volatile key");

#ifndef WT_SECURE_PSA_symmetric
    k = ecc_key(&st);
    check(st == PSA_SUCCESS, "generate P-256 key in Secure");
    st = psa_sign_hash(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash),
                       sig, sizeof(sig), &len);
    check(st == PSA_SUCCESS && len == 64U, "sign_hash");
    check(psa_verify_hash(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                          sizeof(hash), sig, len) == PSA_SUCCESS,
          "verify_hash");
    check(psa_sign_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), big, 100U, sig,
                           sizeof(sig), &len) == PSA_SUCCESS &&
          psa_verify_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), big, 100U,
                             sig, len) == PSA_SUCCESS,
          "sign and verify a message in one request");
    check(psa_sign_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), big,
                           sizeof(big), sig, sizeof(sig), &len) ==
          PSA_SUCCESS &&
          psa_verify_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), big,
                             sizeof(big), sig, len) == PSA_SUCCESS,
          "sign and verify a 1500-byte message through its hash");
    big[7] ^= 1U;
    check(psa_verify_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), big,
                             sizeof(big), sig, len) ==
          PSA_ERROR_INVALID_SIGNATURE,
          "a changed 1500-byte message fails verification");
    big[7] ^= 1U;
    check(psa_export_public_key(k, pub, sizeof(pub), &len) == PSA_SUCCESS &&
          len == 65U, "export_public_key");
    check(psa_export_key(k, big, sizeof(big), &len) ==
          PSA_ERROR_NOT_PERMITTED, "private key export refused by policy");
    check(psa_destroy_key(k) == PSA_SUCCESS, "destroy P-256 key");
#else
    (void)sig;
    (void)pub;
#endif
}

static void test_isolation(void)
{
    uint8_t buf[32];
    uint8_t a[16];
    uint8_t b[16];
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t stolen;
    psa_key_id_t k;
    psa_key_id_t pa;
    psa_key_id_t pb;
    psa_status_t st;
    size_t len = 0U;

    (void)memset(buf, 0, sizeof(buf));
    wt_test_set_client(GUEST0);
    k = aes_key(PSA_KEY_ID_NULL, 0x22, &st);
    check(st == PSA_SUCCESS, "guest0 imports a volatile key");
    check(psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS,
          "guest0 starts a hash");

    wt_test_set_client(GUEST1);
    check(psa_export_key(k, buf, sizeof(buf), &len) ==
          PSA_ERROR_INVALID_HANDLE, "guest1 cannot export guest0's key");
    check(psa_destroy_key(k) == PSA_ERROR_INVALID_HANDLE,
          "guest1 cannot destroy guest0's key");
    stolen = op;
    check(psa_hash_update(&stolen, buf, 4U) == PSA_ERROR_BAD_STATE,
          "guest1 cannot drive guest0's operation token");
    wt_test_set_client(GUEST0);
    stolen.opaque = op.opaque ^ 1U;
    st = psa_hash_update(&stolen, buf, 4U);
    stolen.opaque = op.opaque ^ 0x100U;
    st = (st == PSA_ERROR_BAD_STATE) ? psa_hash_update(&stolen, buf, 4U) : st;
    stolen.opaque = op.opaque ^ 0x10000U;
    st = (st == PSA_ERROR_BAD_STATE) ? psa_hash_update(&stolen, buf, 4U) : st;
    stolen.opaque = op.opaque ^ 0x1000000U;
    st = (st == PSA_ERROR_BAD_STATE) ? psa_hash_update(&stolen, buf, 4U) : st;
    check(st == PSA_ERROR_BAD_STATE,
          "a token with any byte forged does not validate");
    check(psa_hash_abort(&op) == PSA_SUCCESS, "guest0 aborts its hash");
    check(psa_export_key(k, buf, sizeof(buf), &len) == PSA_SUCCESS,
          "guest0 still owns its key");

    pa = aes_key(5U, 0xA5, &st);
    check(st == PSA_SUCCESS && pa == 5U, "guest0 persistent key id 5");
    wt_test_set_client(GUEST1);
    pb = aes_key(5U, 0x5A, &st);
    check(st == PSA_SUCCESS && pb == 5U,
          "guest1 persistent key id 5 lives in its own namespace");
    check(psa_export_key(5U, b, sizeof(b), &len) == PSA_SUCCESS && b[0] ==
          0x5AU, "guest1 reads its own id 5");
    wt_test_set_client(GUEST0);
    check(psa_export_key(5U, a, sizeof(a), &len) == PSA_SUCCESS && a[0] ==
          0xA5U, "guest0 reads its own id 5");
    (void)aes_key(PSA_KEY_ID_VENDOR_MIN, 0x01, &st);
    check(st == PSA_ERROR_INVALID_ARGUMENT,
          "persistent vendor-range id refused from Non-secure");
    check(raw_key_op(WT_CRYPTO_OP_KEY_DESTROY, WT_PSA_UID(5U)) ==
          PSA_ERROR_NOT_PERMITTED &&
          psa_export_key(5U, a, sizeof(a), &len) == PSA_SUCCESS,
          "the native key wire cannot destroy a PSA key record");
    check(raw_key_op(WT_CRYPTO_OP_KEY_GENERATE, WT_PSA_UID(6U)) ==
          PSA_ERROR_NOT_PERMITTED,
          "the native key wire cannot create in the PSA uid range");
}

static void refused(psa_status_t st, const char* what)
{
    check(st == PSA_ERROR_INVALID_HANDLE, what);
}

/* Every wire call that names a key, from the client that does not own it */
static void test_foreign_key(void)
{
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_mac_operation_t mop = PSA_MAC_OPERATION_INIT;
    psa_cipher_operation_t cop = PSA_CIPHER_OPERATION_INIT;
    psa_aead_operation_t aop = PSA_AEAD_OPERATION_INIT;
    psa_key_derivation_operation_t kop = PSA_KEY_DERIVATION_OPERATION_INIT;
    const psa_algorithm_t hmac = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    uint8_t in[32];
    uint8_t out[80];
    uint8_t nonce[13];
    psa_key_id_t k;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t st;
    size_t len = 0U;

    (void)memset(in, 0x3C, sizeof(in));
    (void)memset(out, 0x5A, sizeof(out));
    (void)memset(nonce, 0x11, sizeof(nonce));
    wt_test_set_client(GUEST0);
    k = aes_key(PSA_KEY_ID_NULL, 0x44, &st);
    check(st == PSA_SUCCESS, "guest0 imports the key guest1 will name");

    wt_test_set_client(GUEST1);
    refused(psa_get_key_attributes(k, &attr), "foreign key: get attributes");
    refused(psa_export_public_key(k, out, sizeof(out), &len),
            "foreign key: export public key");
    refused(psa_purge_key(k), "foreign key: purge");
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    refused(psa_copy_key(k, &attr, &id), "foreign key: copy");
    refused(psa_mac_compute(k, hmac, in, 16U, out, sizeof(out), &len),
            "foreign key: MAC compute");
    refused(psa_mac_verify(k, hmac, in, 16U, in, 32U),
            "foreign key: MAC verify");
    refused(psa_mac_sign_setup(&mop, k, hmac), "foreign key: MAC sign setup");
    (void)psa_mac_abort(&mop);
    refused(psa_mac_verify_setup(&mop, k, hmac),
            "foreign key: MAC verify setup");
    (void)psa_mac_abort(&mop);
    refused(psa_cipher_encrypt(k, PSA_ALG_ECB_NO_PADDING, in, 16U, out,
                               sizeof(out), &len), "foreign key: cipher encrypt");
    refused(psa_cipher_decrypt(k, PSA_ALG_ECB_NO_PADDING, in, 16U, out,
                               sizeof(out), &len), "foreign key: cipher decrypt");
    refused(psa_cipher_encrypt_setup(&cop, k, PSA_ALG_ECB_NO_PADDING),
            "foreign key: cipher encrypt setup");
    (void)psa_cipher_abort(&cop);
    refused(psa_cipher_decrypt_setup(&cop, k, PSA_ALG_ECB_NO_PADDING),
            "foreign key: cipher decrypt setup");
    (void)psa_cipher_abort(&cop);
    refused(psa_aead_encrypt(k, WT_TEST_AEAD, nonce, 12U, in, 8U, in, 16U, out,
                             sizeof(out), &len), "foreign key: AEAD encrypt");
    refused(psa_aead_decrypt(k, WT_TEST_AEAD, nonce, 12U, in, 8U, in, 32U, out,
                             sizeof(out), &len), "foreign key: AEAD decrypt");
    refused(psa_aead_encrypt_setup(&aop, k, WT_TEST_AEAD),
            "foreign key: AEAD encrypt setup");
    (void)psa_aead_abort(&aop);
    refused(psa_aead_decrypt_setup(&aop, k, WT_TEST_AEAD),
            "foreign key: AEAD decrypt setup");
    (void)psa_aead_abort(&aop);
    if (psa_key_derivation_setup(&kop, PSA_ALG_HKDF(PSA_ALG_SHA_256)) ==
            PSA_SUCCESS) {
        refused(psa_key_derivation_input_key(&kop,
                PSA_KEY_DERIVATION_INPUT_SECRET, k), "foreign key: KDF input");
        refused(psa_key_derivation_verify_key(&kop, k),
                "foreign key: KDF verify key");
#ifndef WT_SECURE_PSA_symmetric
        refused(psa_key_derivation_key_agreement(&kop,
                PSA_KEY_DERIVATION_INPUT_SECRET, k, out, 65U),
                "foreign key: KDF key agreement");
#endif
        (void)psa_key_derivation_abort(&kop);
    }
#ifndef WT_SECURE_PSA_symmetric
    refused(psa_sign_hash(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), in, 32U, out,
                          sizeof(out), &len), "foreign key: sign hash");
    refused(psa_verify_hash(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), in, 32U, out,
                            64U), "foreign key: verify hash");
    refused(psa_sign_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), in, 16U, out,
                             sizeof(out), &len), "foreign key: sign message");
    refused(psa_verify_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), in, 16U, out,
                               64U), "foreign key: verify message");
    refused(psa_asymmetric_encrypt(k, PSA_ALG_RSA_PKCS1V15_CRYPT, in, 16U,
                                   NULL, 0U, out, sizeof(out), &len),
            "foreign key: asymmetric encrypt");
    refused(psa_asymmetric_decrypt(k, PSA_ALG_RSA_PKCS1V15_CRYPT, in, 16U,
                                   NULL, 0U, out, sizeof(out), &len),
            "foreign key: asymmetric decrypt");
    refused(psa_raw_key_agreement(PSA_ALG_ECDH, k, out, 65U, in, sizeof(in),
                                  &len), "foreign key: raw key agreement");
    refused(psa_key_agreement(k, out, 65U, PSA_ALG_ECDH, &attr, &id),
            "foreign key: key agreement");
#endif

    wt_test_set_client(GUEST0);
    check(psa_destroy_key(k) == PSA_SUCCESS, "guest0 still owns the key");
}

static void test_quota_and_reset(void)
{
    psa_key_id_t keys[10];
    psa_key_id_t k;
    psa_status_t st = PSA_SUCCESS;
    uint8_t buf[16];
    size_t len = 0U;
    size_t n;

    wt_test_set_client(GUEST0);
    for (n = 0U; n < 10U; n++) {
        keys[n] = aes_key(PSA_KEY_ID_NULL, 0x33, &st);
        if (st != PSA_SUCCESS) {
            break;
        }
    }
    check(st == PSA_ERROR_INSUFFICIENT_MEMORY && n > 0U && n < 10U,
          "per-client volatile key quota");
    wt_test_set_client(GUEST1);
    k = aes_key(PSA_KEY_ID_NULL, 0x44, &st);
    check(st == PSA_SUCCESS, "guest1 unaffected by guest0's quota");

    wt_test_set_client(GUEST0);
    check(raw_init() == PSA_SUCCESS, "guest0 restarts PSA Crypto");
    check(psa_export_key(keys[0], buf, sizeof(buf), &len) ==
          PSA_ERROR_INVALID_HANDLE, "restart drops guest0's volatile keys");
    check(psa_export_key(5U, buf, sizeof(buf), &len) == PSA_SUCCESS,
          "restart keeps guest0's persistent key");
    wt_test_set_client(GUEST1);
    check(psa_export_key(k, buf, sizeof(buf), &len) == PSA_SUCCESS,
          "guest0's restart leaves guest1's keys");
}

static void test_service_restart(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_key_id_t k;
    psa_status_t st;
    uint8_t buf[16];
    size_t len = 0U;

    (void)memset(buf, 0, sizeof(buf));
    wt_test_set_client(GUEST0);
    k = aes_key(PSA_KEY_ID_NULL, 0x66, &st);
    check(st == PSA_SUCCESS && psa_hash_setup(&op, PSA_ALG_SHA_256) ==
          PSA_SUCCESS, "state before the service restart");
    check(wt_test_service_restart() == 0, "service restarted");
    check(psa_hash_update(&op, buf, 1U) == PSA_ERROR_BAD_STATE,
          "pre-restart token is dead");
    check(psa_export_key(k, buf, sizeof(buf), &len) ==
          PSA_ERROR_INVALID_HANDLE, "pre-restart volatile key is gone");
    check(psa_export_key(5U, buf, sizeof(buf), &len) == PSA_SUCCESS &&
          buf[0] == 0xA5U, "persistent key survives the restart");
    check(psa_destroy_key(5U) == PSA_SUCCESS, "destroy persistent key");
    check(psa_export_key(5U, buf, sizeof(buf), &len) ==
          PSA_ERROR_INVALID_HANDLE, "destroyed persistent key is gone");
    wt_test_set_client(GUEST1);
    check(psa_export_key(5U, buf, sizeof(buf), &len) == PSA_SUCCESS &&
          buf[0] == 0x5AU, "guest1's id 5 untouched by guest0's destroy");
    (void)psa_destroy_key(5U);
}

/* Built with a small WT_PSA_GEN_MAX so a client spends its slots quickly. */
static void test_token_exhaustion(void)
{
    const psa_hash_operation_t init = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op = init;
    psa_hash_operation_t stale = init;
    psa_status_t st;
    uintptr_t first;
    uint8_t b = 0U;
    int stale_ok = 1;
    size_t n = 0U;

    wt_test_set_client(GUEST0);
    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    first = op.opaque;
    (void)psa_hash_abort(&op);
    while (st == PSA_SUCCESS && n < 100000U) {
        op = init;
        st = psa_hash_setup(&op, PSA_ALG_SHA_256);
        if (st == PSA_SUCCESS) {
            stale.opaque = first;
            if (psa_hash_update(&stale, &b, 1U) != PSA_ERROR_BAD_STATE) {
                stale_ok = 0;
            }
            (void)psa_hash_abort(&op);
            n++;
        }
    }
    check(st == PSA_ERROR_INSUFFICIENT_MEMORY && n > 0U && n < 100000U,
          "a client's spent operation slots retire instead of wrapping");
    check(stale_ok, "a stale operation token never validates again");
    wt_test_set_client(GUEST1);
    op = init;
    check(psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS &&
          psa_hash_abort(&op) == PSA_SUCCESS,
          "guest1 keeps its own operation slots");
    check(wt_test_service_restart() == 0, "service restarted after exhaustion");
    wt_test_set_client(GUEST0);
    op = init;
    check(psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS &&
          psa_hash_abort(&op) == PSA_SUCCESS,
          "a service restart gives guest0 fresh slots");
}

int main(void)
{
    wt_test_set_client(GUEST0);
    test_basic();
    test_profile();
    test_isolation();
    test_foreign_key();
    test_quota_and_reset();
    test_service_restart();
    test_token_exhaustion();
    test_lost_message();
    test_malformed_reply();
    test_arena_isolation();
    (void)printf("%s: %d failure(s)\n", g_failures ? "FAIL" : "PASS",
                 g_failures);
    return g_failures ? 1 : 0;
}
