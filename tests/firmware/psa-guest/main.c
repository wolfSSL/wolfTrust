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

/* Portable bare-metal PSA test guest: the Non-secure client lifecycle the
 * STM32H563 Zephyr guest runs, on no operating system, so every port can
 * prove the same PSA behaviour from a guest that needs only a linker window
 * and a console. Crypto rides wolfPSA over the SPM-mediated client, storage
 * and attestation ride the OS-neutral FF-M clients, and each milestone prints
 * one marker line prefixed with the guest's name. The same source links into
 * both guest windows. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "board.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

#include <psa/crypto.h>
#include <psa/initial_attestation.h>
#include <psa/internal_trusted_storage.h>
#include <psa/protected_storage.h>

#include "psa/client.h"
#include "wolftrust/attestation.h"
#include "attestation_verify.h"

#if defined(WT_ENGINE_HSM)
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfpsa/psa_engine.h"
#endif

#if defined(WT_HSM_ATTACK_PROBE)
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_nvm.h"
#include "wolftrust/services/hsm.h"
#endif

#ifndef GUEST_NAME
#error "GUEST_NAME must name the guest"
#endif

#if defined(WT_RUN_CONFORMANCE)
/* Arm psa-arch-tests val NSPE entry. */
extern int32_t val_entry(void);
#endif

#ifndef WT_EXPECTED_MEASUREMENT_HEX
#define WT_EXPECTED_MEASUREMENT_HEX ""
#endif
#ifndef WT_EXPECTED_LIFECYCLE
#define WT_EXPECTED_LIFECYCLE 0x3000u
#endif

#define GUEST_SERVICE_HSM_SID   4102u
#define GUEST_SERVICE_FWU_SID   4101u
#define GUEST_SERVICE_VERSION   1u
#define GUEST_UNKNOWN_SID       0x4200u

/* SWD-readable progress: the milestone bits the STM32H563 guest latches,
 * so a hardware adapter can read the lifecycle without the console. */
#define GUEST_LC_TEE     0x001u
#define GUEST_LC_CRYPTO  0x002u
#define GUEST_LC_ITS     0x004u
#define GUEST_LC_PS      0x008u
#define GUEST_LC_KEYOPS  0x010u
#define GUEST_LC_SHAKAT  0x020u
#define GUEST_LC_COSE    0x040u
#define GUEST_LC_DONE    0x080u

#define GUEST_SIGNATURE  0x50534147u   /* "PSAG" */

typedef struct guest_mailbox {
    uint32_t signature;
    uint32_t lifecycle;
    uint32_t ffm_neg;
    uint32_t probe;
    uint32_t beat;
} guest_mailbox_t;

__attribute__((section(".shared"), used))
volatile guest_mailbox_t g_guest_mailbox;

extern uint32_t _estack;
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;

void Reset_Handler(void);
static void Default_Handler(void);

__attribute__((section(".vectors"), used))
const uint32_t g_vectors[16] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0u, 0u, 0u,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0u,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
};

static void Default_Handler(void)
{
    for (;;) {
    }
}

/* ---- console ---------------------------------------------------------- */

static void guest_puts(const char* s)
{
    while (*s != '\0') {
        guest_board_uart_putc(*s);
        s++;
    }
}

static void guest_put_i32(int32_t v)
{
    char buf[12];
    uint32_t u;
    int i = (int)sizeof(buf) - 1;

    buf[i] = '\0';
    u = (v < 0) ? (uint32_t)(-(v + 1)) + 1u : (uint32_t)v;
    do {
        i--;
        buf[i] = (char)('0' + (u % 10u));
        u /= 10u;
    } while (u != 0u && i > 1);
    if (v < 0) {
        i--;
        buf[i] = '-';
    }
    guest_puts(&buf[i]);
}

static void guest_put_hex(const uint8_t* p, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0u; i < n; i++) {
        guest_board_uart_putc(digits[(p[i] >> 4) & 0x0Fu]);
        guest_board_uart_putc(digits[p[i] & 0x0Fu]);
    }
}

/* One marker line: "<guest>: <text>". */
static void guest_line(const char* s)
{
    guest_puts(GUEST_NAME ": ");
    guest_puts(s);
    guest_puts("\r\n");
}

/* "<guest>: <text>=<number>" for status-carrying markers. */
static void guest_line_i32(const char* s, int32_t v)
{
    guest_puts(GUEST_NAME ": ");
    guest_puts(s);
    guest_put_i32(v);
    guest_puts("\r\n");
}

/* ---- entropy and client bring-up -------------------------------------- */

int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    (void)os;
    return wolftrust_guest_rng_stub((unsigned char*)output, (unsigned int)sz);
}

#if defined(WT_ENGINE_HSM)
extern int wolfhsm_guest_init(void);
extern whClientContext* wolfhsm_guest_client(void);
#endif

static int guest_crypto_init(void)
{
    psa_status_t st;
#if defined(WT_ENGINE_HSM)
    int rc;

    rc = wolfhsm_guest_init();
    if (rc != WH_ERROR_OK) {
        guest_line_i32("hsm client init FAILED rc=", (int32_t)rc);
        return -1;
    }
    (void)wolfPSA_SetDefaultDevID(WH_DEV_ID);
#endif
    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        guest_line_i32("psa_crypto_init FAILED st=", (int32_t)st);
        return -1;
    }
    return 0;
}

/* ---- FF-M framework ----------------------------------------------------- */

static void exercise_framework(void)
{
    uint32_t fw = psa_framework_version();

    if (fw == PSA_FRAMEWORK_VERSION) {
        guest_line("wolfTrust FF-M psa_framework_version=0x0100");
        g_guest_mailbox.lifecycle |= GUEST_LC_TEE;
    }
    else {
        guest_line_i32("wolfTrust FF-M psa_framework_version unexpected=",
                       (int32_t)fw);
    }
}

/* ---- mediated crypto ---------------------------------------------------- */

static void exercise_ffm_crypto(void)
{
    static const uint8_t input[] =
        "wolfTrust FF-M SERVICE_CRYPTO dispatch test";
    static const uint8_t expected[32] = {
        0x20, 0x03, 0xdf, 0x15, 0x2a, 0x52, 0x8a, 0x06,
        0xc8, 0xd3, 0x48, 0xb8, 0xfa, 0x8b, 0x2f, 0x87,
        0xf7, 0x1f, 0xae, 0xc6, 0x24, 0x6c, 0x7e, 0x72,
        0x8e, 0x27, 0xa4, 0xb5, 0x0a, 0x49, 0x84, 0x66
    };
    uint8_t digest[sizeof(expected)];
    size_t digest_len = 0u;
    psa_status_t st;

    st = psa_hash_compute(PSA_ALG_SHA_256, input, sizeof(input) - 1u,
                          digest, sizeof(digest), &digest_len);
    if (st != PSA_SUCCESS || digest_len != sizeof(expected) ||
            memcmp(digest, expected, sizeof(expected)) != 0) {
        guest_line_i32("FF-M SERVICE_CRYPTO SHA-256 KAT failed st=", (int32_t)st);
        return;
    }
    guest_line("wolfTrust FF-M mediated crypto dispatch verified");
    g_guest_mailbox.lifecycle |= GUEST_LC_CRYPTO;
}

/* ---- storage ------------------------------------------------------------ */

static void exercise_its(void)
{
    static const uint8_t payload[] = "wolfTrust ITS on-target probe";
    uint8_t getbuf[sizeof(payload)];
    size_t got = 0u;
    psa_status_t st;

    st = psa_its_set(0x57544954u, sizeof(payload), payload, 0u);
    if (st != PSA_SUCCESS) {
        guest_line_i32("psa_its_set failed st=", (int32_t)st);
        return;
    }
    memset(getbuf, 0, sizeof(getbuf));
    st = psa_its_get(0x57544954u, 0u, sizeof(getbuf), getbuf, &got);
    if (st != PSA_SUCCESS) {
        guest_line_i32("psa_its_get failed st=", (int32_t)st);
        return;
    }
    if (got != sizeof(payload) || memcmp(getbuf, payload, sizeof(payload)) != 0) {
        guest_line("wolfTrust ITS get returned wrong data");
        return;
    }
    guest_line("wolfTrust ITS set/get verified");
    g_guest_mailbox.lifecycle |= GUEST_LC_ITS;
}

static void exercise_ps(void)
{
    static const uint8_t payload[] = "wolfTrust PS on-target secret";
    uint8_t getbuf[sizeof(payload)];
    size_t got = 0u;
    psa_status_t st;

    st = psa_ps_set(0x57545053u, sizeof(payload), payload, 0u);
    if (st != PSA_SUCCESS) {
        guest_line_i32("psa_ps_set failed st=", (int32_t)st);
        return;
    }
    memset(getbuf, 0, sizeof(getbuf));
    st = psa_ps_get(0x57545053u, 0u, sizeof(getbuf), getbuf, &got);
    if (st != PSA_SUCCESS) {
        guest_line_i32("psa_ps_get failed st=", (int32_t)st);
        return;
    }
    if (got != sizeof(payload) || memcmp(getbuf, payload, sizeof(payload)) != 0) {
        guest_line("wolfTrust PS get returned wrong data");
        return;
    }
    guest_line("wolfTrust PS sealed set/get verified");
    g_guest_mailbox.lifecycle |= GUEST_LC_PS;
}

/* ---- key operations ----------------------------------------------------- */

static void guest_p256_attributes(psa_key_attributes_t* attr)
{
    psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_HASH |
                                  PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_algorithm(attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_bits(attr, 256);
}

static void exercise_keys(void)
{
    static const uint8_t digest[32] = {
        0x57, 0x54, 0x4B, 0x56, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C
    };
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(256)];
    uint8_t tampered[sizeof(digest)];
    size_t sig_len = 0u;
    psa_status_t st;
    int ok = 1;

    guest_p256_attributes(&attr);
    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS) {
        guest_line_i32("key generate failed st=", (int32_t)st);
        return;
    }
    st = psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest,
                       sizeof(digest), sig, sizeof(sig), &sig_len);
    if (st != PSA_SUCCESS) {
        guest_line_i32("key sign failed st=", (int32_t)st);
        ok = 0;
    }
    if (ok) {
        st = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             digest, sizeof(digest), sig, sig_len);
        if (st != PSA_SUCCESS) {
            guest_line_i32("key verify failed st=", (int32_t)st);
            ok = 0;
        }
    }
    if (ok) {
        memcpy(tampered, digest, sizeof(tampered));
        tampered[0] ^= 0x01u;
        st = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             tampered, sizeof(tampered), sig, sig_len);
        if (st != PSA_ERROR_INVALID_SIGNATURE) {
            guest_line_i32("tampered verify not refused st=", (int32_t)st);
            ok = 0;
        }
    }
    if (ok) {
        guest_line("wolfTrust key-ops sign/verify verified");
        g_guest_mailbox.lifecycle |= GUEST_LC_KEYOPS;
    }
    (void)psa_destroy_key(key);
}

static void exercise_key_negatives(void)
{
    static const uint8_t digest[32] = {
        0x4E, 0x45, 0x47, 0x41, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C
    };
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_a = PSA_KEY_ID_NULL;
    psa_key_id_t key_b = PSA_KEY_ID_NULL;
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(256)];
    size_t sig_len = 0u;
    psa_status_t st;
    int ok = 1;

    guest_p256_attributes(&attr);
    st = psa_generate_key(&attr, &key_a);
    if (st != PSA_SUCCESS) {
        guest_line_i32("negatives key A generate failed st=", (int32_t)st);
        return;
    }
    st = psa_generate_key(&attr, &key_b);
    if (st != PSA_SUCCESS) {
        guest_line_i32("negatives key B generate failed st=", (int32_t)st);
        (void)psa_destroy_key(key_a);
        return;
    }
    st = psa_sign_hash(key_a, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest,
                       sizeof(digest), sig, sizeof(sig), &sig_len);
    if (st != PSA_SUCCESS) {
        guest_line_i32("negatives sign under A failed st=", (int32_t)st);
        ok = 0;
    }
    if (ok) {
        st = psa_verify_hash(key_a, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             digest, sizeof(digest), sig, sig_len);
        if (st != PSA_SUCCESS) {
            guest_line_i32("negatives verify under A failed st=", (int32_t)st);
            ok = 0;
        }
    }
    if (ok) {
        st = psa_verify_hash(key_b, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             digest, sizeof(digest), sig, sig_len);
        if (st != PSA_ERROR_INVALID_SIGNATURE) {
            guest_line_i32("cross-key verify under B not refused st=",
                           (int32_t)st);
            ok = 0;
        }
    }
    if (ok) {
        guest_line("wolfTrust key negatives verified");
    }
    (void)psa_destroy_key(key_a);
    (void)psa_destroy_key(key_b);
}

/* ---- FF-M IPC negatives ------------------------------------------------- */

/* Mailbox bits: 1 forged handle, 2 oversized vector, 4 cross-guest vector,
 * 8 unknown SID; set only when the SPM rejected the abuse. */
static void exercise_ffm_negatives(void)
{
    static const uint8_t input[] = "wolfTrust FF-M negative probe";
    uint8_t digest[32];
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_handle_t handle;
    psa_handle_t bad;
    psa_status_t st;

    handle = psa_connect(GUEST_SERVICE_HSM_SID, GUEST_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        guest_line_i32("FF-M negative setup connect failed handle=",
                       (int32_t)handle);
        return;
    }

    in_vec.base = input;
    in_vec.len = sizeof(input) - 1u;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    st = psa_call((psa_handle_t)(handle + 0x1000), PSA_IPC_CALL,
                  &in_vec, 1u, &out_vec, 1u);
    if (st != PSA_SUCCESS) {
        g_guest_mailbox.ffm_neg |= 1u;
        guest_line_i32("wolfTrust FF-M forged-handle call rejected st=",
                       (int32_t)st);
    }
    else {
        guest_line("FF-M forged-handle call NOT rejected");
    }

    in_vec.base = input;
    in_vec.len = 2048u;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    st = psa_call(handle, PSA_IPC_CALL, &in_vec, 1u, &out_vec, 1u);
    if (st != PSA_SUCCESS) {
        g_guest_mailbox.ffm_neg |= 2u;
        guest_line_i32("wolfTrust FF-M oversized-vector call rejected st=",
                       (int32_t)st);
    }
    else {
        guest_line("FF-M oversized-vector call NOT rejected");
    }

#if defined(GUEST_PEER_RAM)
    /* A vector inside the peer guest's window must be refused by the
     * caller-banded memcheck: guests are isolated from each other through
     * the SPM, not merely Non-secure from Secure. */
    in_vec.base = (const void*)GUEST_PEER_RAM;
    in_vec.len = 16u;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    st = psa_call(handle, PSA_IPC_CALL, &in_vec, 1u, &out_vec, 1u);
    if (st != PSA_SUCCESS) {
        g_guest_mailbox.ffm_neg |= 4u;
        guest_line_i32("wolfTrust FF-M cross-guest vector rejected st=",
                       (int32_t)st);
    }
    else {
        guest_line("FF-M cross-guest vector NOT rejected");
    }
#endif

    psa_close(handle);

    bad = psa_connect(GUEST_UNKNOWN_SID, GUEST_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(bad)) {
        g_guest_mailbox.ffm_neg |= 8u;
        guest_line("wolfTrust FF-M unknown-SID connect refused");
    }
    else {
        guest_line("FF-M unknown-SID connect NOT refused");
        psa_close(bad);
    }
}

/* ---- PSA Crypto API ----------------------------------------------------- */

static void exercise_psa_rng(void)
{
    uint8_t out[16];
    psa_status_t st;

    st = psa_generate_random(out, sizeof(out));
    guest_line_i32("psa_generate_random st=", (int32_t)st);
}

static void exercise_psa_hash(void)
{
    static const uint8_t input[] = "wolfTrust/wolfPSA/wolfHSM/CMSE chain test";
    static const uint8_t expected[32] = {
        0x02, 0x7b, 0x1a, 0xec, 0xb3, 0x27, 0x3a, 0x54,
        0x38, 0x6a, 0xea, 0x85, 0x66, 0x45, 0xa2, 0x6a,
        0xe1, 0xce, 0xc4, 0xdf, 0x1e, 0x00, 0x72, 0x71,
        0xab, 0x5f, 0x10, 0x21, 0x40, 0x57, 0xed, 0x67
    };
    uint8_t digest[sizeof(expected)];
    size_t digest_len = 0u;
    psa_status_t st;

    st = psa_hash_compute(PSA_ALG_SHA_256, input, sizeof(input) - 1u,
                          digest, sizeof(digest), &digest_len);
    if (st != PSA_SUCCESS || digest_len != sizeof(expected) ||
            memcmp(digest, expected, sizeof(expected)) != 0) {
        guest_line_i32("psa_hash_compute(SHA-256) KAT failed st=", (int32_t)st);
        return;
    }
    guest_line("psa_hash_compute(SHA-256) KAT verified");
    g_guest_mailbox.lifecycle |= GUEST_LC_SHAKAT;
}

static void exercise_psa_cipher(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t plaintext[16];
    uint8_t ciphertext[PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES,
                                                      PSA_ALG_CTR,
                                                      sizeof(plaintext))];
    size_t ct_len = 0u;
    psa_status_t st;

    memset(plaintext, 0xA5, sizeof(plaintext));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
                                   PSA_KEY_USAGE_DECRYPT);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_algorithm(&attr, PSA_ALG_CTR);
    psa_set_key_bits(&attr, 128);

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS) {
        guest_line_i32("psa_generate_key(AES) st=", (int32_t)st);
        return;
    }
    st = psa_cipher_encrypt(key, PSA_ALG_CTR, plaintext, sizeof(plaintext),
                            ciphertext, sizeof(ciphertext), &ct_len);
    guest_line_i32("psa_cipher_encrypt(AES-CTR) st=", (int32_t)st);
    (void)psa_destroy_key(key);
}

/* ---- initial attestation ------------------------------------------------ */

static void exercise_attestation(void)
{
    uint8_t challenge[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32];
    uint8_t token[640];
    uint8_t short_token[1];
    uint8_t public_key[65];
    uint8_t measurement[32];
    size_t token_size = 0u;
    size_t short_size = sizeof(short_token);
    size_t public_key_size = 0u;
    uint32_t verified_lifecycle = 0u;
    psa_status_t st;
    int verify;
    size_t i;

    for (i = 0u; i < sizeof(challenge); i++) {
        challenge[i] = (uint8_t)(0xA0u + i);
    }

    st = psa_initial_attest_get_token_size(sizeof(challenge), &token_size);
    if (st != PSA_SUCCESS || token_size > sizeof(token)) {
        guest_line_i32("psa_initial_attestation unavailable st=", (int32_t)st);
        return;
    }
    st = psa_initial_attest_get_token(challenge, sizeof(challenge),
                                      short_token, sizeof(short_token),
                                      &short_size);
    if (st != PSA_ERROR_BUFFER_TOO_SMALL) {
        guest_line_i32("psa_initial_attestation short-buffer mapping failed st=",
                       (int32_t)st);
        return;
    }
    guest_line("psa_initial_attestation short-buffer rejected correctly");

    st = psa_initial_attest_get_token(challenge, sizeof(challenge), token,
                                      sizeof(token), &token_size);
    guest_line_i32("psa_initial_attestation st=", (int32_t)st);
    if (st != PSA_SUCCESS) {
        return;
    }
    st = wolftrust_attestation_get_iak_public_key(public_key,
                                                  sizeof(public_key),
                                                  &public_key_size);
    if (st != PSA_SUCCESS) {
        guest_line_i32("psa_initial_attestation public_key_st=", (int32_t)st);
        return;
    }
    verify = wt_attestation_verify_ex(token, token_size, public_key,
                                      public_key_size, challenge,
                                      sizeof(challenge),
                                      WT_EXPECTED_MEASUREMENT_HEX,
                                      WT_EXPECTED_LIFECYCLE,
                                      &verified_lifecycle, measurement);
    if (verify != 0) {
        guest_line_i32("wolfTrust attestation: COSE_Sign1 verification failed rc=",
                       (int32_t)verify);
        guest_line_i32("wolfTrust attestation: received lifecycle=",
                       (int32_t)verified_lifecycle);
        return;
    }
    guest_line("wolfTrust attestation: COSE_Sign1 verified");
    g_guest_mailbox.lifecycle |= GUEST_LC_COSE;
    guest_puts(GUEST_NAME ": wolfTrust attestation: token measurement=");
    guest_put_hex(measurement, sizeof(measurement));
    guest_puts("\r\n");
    guest_line("attestation verify=0 challenge=ok identity=ok measurement=ok "
               "cose=ES256");
}

#if defined(WT_ATTEST_NEG_PROBE)
/* The Secure side must reject invalid attestation requests with the PSA
 * statuses Arm's test_a001 depends on, and a tampered or misattributed
 * token must fail the guest verify. */
static void exercise_attestation_negatives(void)
{
    uint8_t challenge[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 + 1u];
    uint8_t token[640];
    uint8_t public_key[65];
    size_t token_size = 0u;
    size_t public_key_size = 0u;
    size_t query_size = 0u;
    uint32_t verified_lifecycle = 0u;
    psa_status_t st;
    int verify;
    size_t i;

    for (i = 0u; i < sizeof(challenge); i++) {
        challenge[i] = (uint8_t)(0xC0u + i);
    }

    st = psa_initial_attest_get_token_size(sizeof(challenge), &query_size);
    if (st != PSA_ERROR_INVALID_ARGUMENT) {
        guest_line_i32("attestneg oversized challenge not rejected st=",
                       (int32_t)st);
        return;
    }
    guest_line_i32("attestneg oversized challenge rejected st=", (int32_t)st);

    st = psa_initial_attest_get_token(challenge,
                                      PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
                                      token, 0u, &token_size);
    if (st != PSA_ERROR_INVALID_ARGUMENT) {
        guest_line_i32("attestneg zero token buffer not rejected st=",
                       (int32_t)st);
        return;
    }
    guest_line_i32("attestneg zero token buffer rejected st=", (int32_t)st);

    st = psa_initial_attest_get_token(challenge,
                                      PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
                                      token, sizeof(token), &token_size);
    if (st != PSA_SUCCESS) {
        guest_line_i32("attestneg baseline token failed st=", (int32_t)st);
        return;
    }
    st = wolftrust_attestation_get_iak_public_key(public_key,
                                                  sizeof(public_key),
                                                  &public_key_size);
    if (st != PSA_SUCCESS) {
        guest_line_i32("attestneg public key fetch failed st=", (int32_t)st);
        return;
    }

    token[token_size - 1u] ^= 0x01u;
    verify = wt_attestation_verify(token, token_size, public_key,
                                   public_key_size, challenge,
                                   PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
                                   WT_EXPECTED_MEASUREMENT_HEX,
                                   WT_EXPECTED_LIFECYCLE, &verified_lifecycle);
    if (verify == 0) {
        guest_line("attestneg tampered token accepted");
        return;
    }
    token[token_size - 1u] ^= 0x01u;
    guest_line("attestneg tampered token rejected");

    verify = wt_attestation_verify(token, token_size, public_key,
                                   public_key_size, challenge,
                                   PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
                                   WT_EXPECTED_MEASUREMENT_HEX, 0xEEEEu,
                                   &verified_lifecycle);
    if (verify == 0) {
        guest_line("attestneg lifecycle mismatch accepted");
        return;
    }
    guest_line("attestneg lifecycle mismatch rejected");
    guest_line("wolfTrust attestation negatives verified");
}
#endif

#if defined(WT_HSM_ATTACK_PROBE)
/* Compromised-guest probe: forge a COMM_INIT claiming the attestation-reserved
 * client_id and try to sign with the committed IAK, then try an NVM-group
 * read of the rollback table. Both must fail; own crypto must still work. */
#define GUEST_HSM_ATTACK_IAK_KEY_ID 0xF0u

static void exercise_hsm_attack_probe(void)
{
    whClientContext* ctx = wolfhsm_guest_client();
    ecc_key key;
    uint8_t hash[32];
    uint8_t sig[72];
    uint16_t sig_len = (uint16_t)sizeof(sig);
    uint8_t nvmbuf[16];
    uint8_t rngbuf[16];
    uint16_t r_group = 0u;
    uint16_t r_action = 0u;
    uint16_t r_size = 0u;
    uint32_t out_client_id = 0u;
    uint32_t out_server_id = 0u;
    int guard = 0;
    psa_status_t st;
    int rc;

    if (ctx == NULL) {
        guest_line("hsmattackneg no wolfHSM client context");
        return;
    }

    ctx->comm->client_id = WH_CLIENT_ID_MAX;
    do {
        rc = wh_Client_CommInitRequest(ctx);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == WH_ERROR_OK) {
        do {
            rc = wh_Client_CommInitResponse(ctx, &out_client_id,
                                            &out_server_id);
        } while (rc == WH_ERROR_NOTREADY);
    }
    guest_line_i32("hsmattackneg forged COMM_INIT rc=", (int32_t)rc);

    (void)memset(hash, 0x42, sizeof(hash));
    (void)wc_ecc_init(&key);
    rc = wh_Client_EccSetKeyId(&key, GUEST_HSM_ATTACK_IAK_KEY_ID);
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_EccSign(ctx, &key, hash, (uint16_t)sizeof(hash),
                               sig, &sig_len);
    }
    wc_ecc_free(&key);
    if (rc != WH_ERROR_OK) {
        guest_line_i32("hsmattackneg IAK sign refused rc=", (int32_t)rc);
        g_guest_mailbox.probe |= 0x1u;
    }
    else {
        guest_line("hsmattackneg IAK sign SUCCEEDED");
    }

    (void)memset(nvmbuf, 0, sizeof(nvmbuf));
    nvmbuf[0] = (uint8_t)(WT_HSM_ROLLBACK_TABLE_ID & 0xFFu);
    nvmbuf[1] = (uint8_t)((WT_HSM_ROLLBACK_TABLE_ID >> 8) & 0xFFu);
    rc = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_NVM,
                               WH_MESSAGE_NVM_ACTION_READ,
                               (uint16_t)sizeof(nvmbuf), nvmbuf);
    if (rc == WH_ERROR_OK) {
        guard = 1000;
        do {
            rc = wh_Client_RecvResponse(ctx, &r_group, &r_action, &r_size,
                                        (uint16_t)sizeof(nvmbuf), nvmbuf);
        } while (rc == WH_ERROR_NOTREADY && guard-- > 0);
    }
    if (rc != WH_ERROR_OK) {
        guest_line_i32("hsmattackneg rollback NVM group refused rc=",
                       (int32_t)rc);
        g_guest_mailbox.probe |= 0x2u;
    }
    else {
        guest_line("hsmattackneg rollback NVM group SUCCEEDED");
    }

    st = psa_generate_random(rngbuf, sizeof(rngbuf));
    if (st == PSA_SUCCESS) {
        guest_line("hsmattackneg own-namespace crypto still works");
        g_guest_mailbox.probe |= 0x4u;
    }
    else {
        guest_line_i32("hsmattackneg own-namespace crypto FAILED st=",
                       (int32_t)st);
    }
}
#endif

#if defined(WT_FWU_PROBE)
/* Drive SERVICE_FWU: the privileged FWU SP stages a candidate into the real
 * wolfBoot update partition and verifies each block by read-back, then the
 * PSA FWU 1.0 reject/clean tail restores READY. */
#define GUEST_FWU_OP_QUERY   1u
#define GUEST_FWU_OP_START   2u
#define GUEST_FWU_OP_WRITE   3u
#define GUEST_FWU_OP_FINISH  4u
#define GUEST_FWU_OP_INSTALL 5u
#define GUEST_FWU_OP_CLEAN   7u
#define GUEST_FWU_OP_REJECT  8u
#define GUEST_FWU_READY      0u
#define GUEST_FWU_STAGED     3u
#define GUEST_FWU_FAILED     4u

struct guest_fwu_req {
    uint32_t component;
    uint32_t offset;
    uint32_t size;
    uint32_t version;
};

static int32_t guest_fwu_call(psa_handle_t handle, uint32_t op,
                              const void* in, size_t in_len,
                              void* out, size_t out_len)
{
    psa_invec in_vec;
    psa_outvec out_vec;

    in_vec.base = in;
    in_vec.len = in_len;
    out_vec.base = out;
    out_vec.len = out_len;
    return (int32_t)psa_call(handle, (int32_t)op, &in_vec, 1u,
                             (out != NULL) ? &out_vec : NULL,
                             (out != NULL) ? 1u : 0u);
}

static void exercise_fwu(void)
{
    struct guest_fwu_req req;
    uint8_t writebuf[16 + 512];
    uint32_t info[8];
    uint32_t word;
    uint32_t tail_off = 1024u;
#if defined(WT_FWU_PROBE_STREAM_BYTES)
    uint32_t off;
#endif
    psa_handle_t handle;
    int32_t st;
    int ok = 1;

    handle = psa_connect(GUEST_SERVICE_FWU_SID, GUEST_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        guest_line_i32("FF-M psa_connect(SERVICE_FWU) failed handle=",
                       (int32_t)handle);
        return;
    }

    memset(&req, 0, sizeof(req));
    req.size = 32u;
    memset(writebuf, 0, sizeof(writebuf));
    memcpy(writebuf, &req, sizeof(req));
    /* The payload length matches req.size so only the READY state refuses. */
    st = guest_fwu_call(handle, GUEST_FWU_OP_WRITE, writebuf,
                        sizeof(req) + req.size, NULL, 0u);
    if (st == 0) {
        guest_line("wolfTrust FWU write-before-start was not refused");
        ok = 0;
    }
    else {
        guest_line("wolfTrust FWU write-before-start refused");
    }

    memset(&req, 0, sizeof(req));
    req.version = 7u;
    st = guest_fwu_call(handle, GUEST_FWU_OP_START, &req, sizeof(req),
                        NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU start failed st=", st);
        ok = 0;
    }

    /* A minimal valid wolfBoot image: the 0x400 header carries the magic,
     * the payload size, and a version TLV matching the declared candidate. */
    memset(&req, 0, sizeof(req));
    req.offset = 0u;
    req.size = 512u;
    memcpy(writebuf, &req, sizeof(req));
    memset(writebuf + 16, 0xFF, 512u);
    word = 0x464C4F57u;
    memcpy(writebuf + 16, &word, 4u);
    word = 32u;
    memcpy(writebuf + 20, &word, 4u);
    writebuf[24] = 0x01u;
    writebuf[25] = 0x00u;
    writebuf[26] = 0x04u;
    writebuf[27] = 0x00u;
    word = 7u;
    memcpy(writebuf + 28, &word, 4u);
    st = guest_fwu_call(handle, GUEST_FWU_OP_WRITE, writebuf,
                        sizeof(writebuf), NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU write#0 failed st=", st);
        ok = 0;
    }

    req.offset = 512u;
    memcpy(writebuf, &req, sizeof(req));
    memset(writebuf + 16, 0xFF, 512u);
    st = guest_fwu_call(handle, GUEST_FWU_OP_WRITE, writebuf,
                        sizeof(writebuf), NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU write#1 failed st=", st);
        ok = 0;
    }

#if defined(WT_FWU_PROBE_STREAM_BYTES)
    /* Stream a body across the update partition so every data sector sees
     * an erase and a program through the real backend before the tail. */
    for (off = 1024u; ok && off < (uint32_t)WT_FWU_PROBE_STREAM_BYTES;
         off += 512u) {
        memset(&req, 0, sizeof(req));
        req.offset = off;
        req.size = 512u;
        memcpy(writebuf, &req, sizeof(req));
        memset(writebuf + 16, (int)((off / 512u) & 0xFFu), 512u);
        st = guest_fwu_call(handle, GUEST_FWU_OP_WRITE, writebuf,
                            sizeof(writebuf), NULL, 0u);
        if (st != 0) {
            guest_line_i32("wolfTrust FWU streamed write failed st=", st);
            ok = 0;
        }
    }
    if (ok) {
        guest_line("wolfTrust FWU streamed candidate body across the update "
                   "partition");
    }
    tail_off = (uint32_t)WT_FWU_PROBE_STREAM_BYTES;
#endif

    memset(&req, 0, sizeof(req));
    req.offset = tail_off;
    req.size = 32u;
    memcpy(writebuf, &req, sizeof(req));
    memset(writebuf + 16, 0x22, 32u);
    st = guest_fwu_call(handle, GUEST_FWU_OP_WRITE, writebuf, 16u + 32u,
                        NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU write#2 failed st=", st);
        ok = 0;
    }

    memset(&req, 0, sizeof(req));
    st = guest_fwu_call(handle, GUEST_FWU_OP_FINISH, &req, sizeof(req),
                        NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU finish failed st=", st);
        ok = 0;
    }

    memset(&req, 0, sizeof(req));
    st = guest_fwu_call(handle, GUEST_FWU_OP_INSTALL, &req, sizeof(req),
                        NULL, 0u);
    if (st != 1) {
        guest_line_i32("wolfTrust FWU install st=", st);
        ok = 0;
    }

    memset(&req, 0, sizeof(req));
    memset(info, 0, sizeof(info));
    st = guest_fwu_call(handle, GUEST_FWU_OP_QUERY, &req, sizeof(req),
                        info, sizeof(info));
    if (st != 0 || info[0] != GUEST_FWU_STAGED) {
        guest_line_i32("wolfTrust FWU query after install state=",
                       (int32_t)info[0]);
        ok = 0;
    }
    if (ok) {
        guest_line("wolfTrust FWU staged signed-header candidate to update "
                   "partition, armed, verified");
    }

    memset(&req, 0, sizeof(req));
    req.version = (uint32_t)-132;
    st = guest_fwu_call(handle, GUEST_FWU_OP_REJECT, &req, sizeof(req),
                        NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU reject failed st=", st);
        ok = 0;
    }
    memset(&req, 0, sizeof(req));
    memset(info, 0, sizeof(info));
    st = guest_fwu_call(handle, GUEST_FWU_OP_QUERY, &req, sizeof(req),
                        info, sizeof(info));
    if (st != 0 || (info[0] & 0xFFu) != GUEST_FWU_FAILED) {
        guest_line_i32("wolfTrust FWU post-reject state=", (int32_t)info[0]);
        ok = 0;
    }
    memset(&req, 0, sizeof(req));
    st = guest_fwu_call(handle, GUEST_FWU_OP_CLEAN, &req, sizeof(req),
                        NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU clean failed st=", st);
        ok = 0;
    }
    memset(&req, 0, sizeof(req));
    memset(info, 0, sizeof(info));
    st = guest_fwu_call(handle, GUEST_FWU_OP_QUERY, &req, sizeof(req),
                        info, sizeof(info));
    if (st != 0 || (info[0] & 0xFFu) != GUEST_FWU_READY) {
        guest_line_i32("wolfTrust FWU post-clean state=", (int32_t)info[0]);
        ok = 0;
    }
    if (ok) {
        guest_line("wolfTrust FWU reject disarmed and clean restored READY");
    }

#if defined(WT_FWU_PROBE_SEQUENTIAL)
    /* A fresh session: a block that skips ahead of the staged extent must be
     * refused, which fails the candidate, and clean must restore READY. */
    ok = 1;
    memset(&req, 0, sizeof(req));
    req.version = 7u;
    st = guest_fwu_call(handle, GUEST_FWU_OP_START, &req, sizeof(req),
                        NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU second start failed st=", st);
        ok = 0;
    }
    memset(&req, 0, sizeof(req));
    req.offset = 0u;
    req.size = 512u;
    memcpy(writebuf, &req, sizeof(req));
    memset(writebuf + 16, 0x33, 512u);
    st = guest_fwu_call(handle, GUEST_FWU_OP_WRITE, writebuf,
                        sizeof(writebuf), NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU second write#0 failed st=", st);
        ok = 0;
    }
    req.offset = 4096u;
    memcpy(writebuf, &req, sizeof(req));
    st = guest_fwu_call(handle, GUEST_FWU_OP_WRITE, writebuf,
                        sizeof(writebuf), NULL, 0u);
    if (st == 0) {
        guest_line("wolfTrust FWU out-of-order write was not refused");
        ok = 0;
    }
    memset(&req, 0, sizeof(req));
    memset(info, 0, sizeof(info));
    st = guest_fwu_call(handle, GUEST_FWU_OP_QUERY, &req, sizeof(req),
                        info, sizeof(info));
    if (st != 0 || (info[0] & 0xFFu) != GUEST_FWU_FAILED) {
        guest_line_i32("wolfTrust FWU post-skip state=", (int32_t)info[0]);
        ok = 0;
    }
    memset(&req, 0, sizeof(req));
    st = guest_fwu_call(handle, GUEST_FWU_OP_CLEAN, &req, sizeof(req),
                        NULL, 0u);
    if (st != 0) {
        guest_line_i32("wolfTrust FWU second clean failed st=", st);
        ok = 0;
    }
    memset(&req, 0, sizeof(req));
    memset(info, 0, sizeof(info));
    st = guest_fwu_call(handle, GUEST_FWU_OP_QUERY, &req, sizeof(req),
                        info, sizeof(info));
    if (st != 0 || (info[0] & 0xFFu) != GUEST_FWU_READY) {
        guest_line_i32("wolfTrust FWU post-skip clean state=",
                       (int32_t)info[0]);
        ok = 0;
    }
    if (ok) {
        guest_line("wolfTrust FWU out-of-order write refused and cleaned");
    }
#endif
    psa_close(handle);
}
#endif

/* ---- entry -------------------------------------------------------------- */

void Reset_Handler(void)
{
    uint32_t* src;
    uint32_t* dst;

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; ) {
        *dst = *src;
        dst++;
        src++;
    }
    for (dst = &_sbss; dst < &_ebss; ) {
        *dst = 0u;
        dst++;
    }

    g_guest_mailbox.signature = GUEST_SIGNATURE;
    g_guest_mailbox.lifecycle = 0u;
    g_guest_mailbox.ffm_neg = 0u;
    g_guest_mailbox.probe = 0u;
    g_guest_mailbox.beat = 0u;

    guest_board_uart_init();
    guest_line("alive");

#if defined(WT_GUEST_FAULT_PROBE)
    /* A Non-secure read of Secure RAM faults on every launch. */
    g_guest_mailbox.probe = *(volatile const uint32_t*)GUEST_SECURE_RAM_ADDR;
#endif

    exercise_framework();
    if (guest_crypto_init() == 0) {
        exercise_ffm_crypto();
    }
    exercise_its();
    exercise_ps();
    exercise_keys();
    exercise_key_negatives();
    exercise_ffm_negatives();
#if defined(WT_HSM_ATTACK_PROBE)
    exercise_hsm_attack_probe();
#endif
#if defined(WT_FWU_PROBE)
    exercise_fwu();
#endif
#if !defined(WT_RUN_CONFORMANCE)
    /* The COSE verify needs a deep stack the val framework then wants for
     * itself; the PSA lifecycle scenarios cover attestation. */
    exercise_attestation();
#if defined(WT_ATTEST_NEG_PROBE)
    exercise_attestation_negatives();
#endif
    exercise_psa_rng();
    exercise_psa_hash();
    exercise_psa_cipher();
#else
    guest_line("wolfTrust FF-M conformance: val_entry start");
    (void)val_entry();
#endif

    guest_line("done");
    g_guest_mailbox.lifecycle |= GUEST_LC_DONE;

#if defined(WT_M33MU_EXPECT_BKPT)
    __asm volatile("bkpt #0x7f");
#endif

    for (;;) {
        g_guest_mailbox.beat++;
    }
}
