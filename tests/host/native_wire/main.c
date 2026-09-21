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

/* Native crypto wire suite: drives wt_native_submit with real request
 * packets over a RAM-backed NVM store, exactly as SERVICE_HSM's relay hands
 * them over on target — every operation, the per-client key namespace, usage
 * and type enforcement, malformed packets, and AES-GCM tamper rejection. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/crypto_native.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_OWNER     6
#define TEST_NS_GUEST0 (-1)
#define TEST_NS_GUEST1 (-2)

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];
static whFlashRamsimCfg g_ramsim_cfg;
static whFlashRamsimCtx g_ramsim_ctx;
static const whFlashCb g_ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
static whNvmFlashConfig g_nvm_flash_cfg;
static whNvmFlashContext g_nvm_flash_ctx;
static const whNvmCb g_nvm_cb[1] = {WH_NVM_FLASH_CB};
static whNvmConfig g_nvm_cfg;
static whNvmContext g_nvm_ctx;

static int g_failures;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    }
    else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static int test_store_up(void)
{
    (void)memset(&g_ramsim_cfg, 0, sizeof(g_ramsim_cfg));
    g_ramsim_cfg.memory = g_flash_memory;
    g_ramsim_cfg.size = RAMSIM_SIZE;
    g_ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    g_ramsim_cfg.pageSize = RAMSIM_PAGE;
    g_ramsim_cfg.erasedByte = 0xFF;
    (void)memset(&g_ramsim_ctx, 0, sizeof(g_ramsim_ctx));
    (void)memset(&g_nvm_flash_cfg, 0, sizeof(g_nvm_flash_cfg));
    g_nvm_flash_cfg.cb = g_ramsim_cb;
    g_nvm_flash_cfg.context = &g_ramsim_ctx;
    g_nvm_flash_cfg.config = &g_ramsim_cfg;
    (void)memset(&g_nvm_flash_ctx, 0, sizeof(g_nvm_flash_ctx));
    (void)memset(&g_nvm_cfg, 0, sizeof(g_nvm_cfg));
    g_nvm_cfg.cb = (whNvmCb*)g_nvm_cb;
    g_nvm_cfg.context = &g_nvm_flash_ctx;
    g_nvm_cfg.config = &g_nvm_flash_cfg;
    (void)memset(&g_nvm_ctx, 0, sizeof(g_nvm_ctx));
    if (wh_Nvm_Init(&g_nvm_ctx, &g_nvm_cfg) != WH_ERROR_OK) {
        return -1;
    }
    if (wt_hsm_vault_init(&g_nvm_ctx) != 0) {
        return -1;
    }
    if (wt_hsm_keyvault_init(&g_nvm_ctx) != 0) {
        return -1;
    }
    return 0;
}

/* One wire round trip as the relay performs it: [header][payload] in,
 * [status][payload] out, both bounded by the relay's copied buffers. */
static int wire(int32_t client, uint32_t op, uint64_t uid, uint32_t usage,
                uint32_t key_type, const uint8_t* payload,
                size_t payload_len, uint8_t* out, size_t out_cap,
                size_t* out_len, psa_status_t* status)
{
    uint8_t req[WT_HSM_RELAY_MSG_MAX];
    uint8_t resp[WT_HSM_RELAY_MSG_MAX];
    wt_crypto_wire_req_t hdr;
    size_t resp_len = 0U;
    size_t got;
    int32_t wire_status = 0;
    int rc;

    if (sizeof(hdr) + payload_len > sizeof(req)) {
        return -2;
    }
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.uid = uid;
    hdr.op = op;
    hdr.usage = usage;
    hdr.key_type = key_type;
    (void)memcpy(req, &hdr, sizeof(hdr));
    if (payload_len != 0U) {
        (void)memcpy(req + sizeof(hdr), payload, payload_len);
    }
    rc = wt_native_submit((void*)(intptr_t)TEST_OWNER, client, req,
                          sizeof(hdr) + payload_len, resp, sizeof(resp),
                          &resp_len);
    if (rc != 0) {
        return rc;
    }
    if (resp_len < sizeof(wire_status)) {
        return -3;
    }
    (void)memcpy(&wire_status, resp, sizeof(wire_status));
    got = resp_len - sizeof(wire_status);
    if (out != NULL) {
        if (got > out_cap) {
            return -4;
        }
        (void)memcpy(out, resp + sizeof(wire_status), got);
    }
    if (out_len != NULL) {
        *out_len = got;
    }
    *status = (psa_status_t)wire_status;
    return 0;
}

static void test_random_and_hash(void)
{
    /* SHA-256("abc") */
    static const uint8_t abc_digest[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t out[WT_HSM_RELAY_MSG_MAX];
    uint8_t zero[64];
    size_t got = 0U;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int rc;

    (void)memset(zero, 0, sizeof(zero));
    (void)memset(out, 0, sizeof(out));
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_RANDOM, 0U, 64U, 0U, NULL, 0U,
              out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_SUCCESS && got == 64U &&
          memcmp(out, zero, sizeof(zero)) != 0,
          "RANDOM returns exactly the requested nonzero bytes");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_RANDOM, 0U, 0U, 0U, NULL, 0U,
              out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_ARGUMENT && got == 0U,
          "RANDOM refuses a zero-length request");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_RANDOM, 0U,
              WT_CRYPTO_RANDOM_MAX + 1U, 0U, NULL, 0U, out, sizeof(out),
              &got, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_ARGUMENT && got == 0U,
          "RANDOM refuses a request above the per-call cap");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_HASH, 0U, 0U, 0U,
              (const uint8_t*)"abc", 3U, out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_SUCCESS && got == sizeof(abc_digest) &&
          memcmp(out, abc_digest, sizeof(abc_digest)) == 0,
          "HASH returns the SHA-256 known answer");
}

static void test_p256_lifecycle(void)
{
    static const uint8_t digest[32] = {
        0x57, 0x54, 0x4e, 0x57, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c
    };
    uint8_t out[WT_HSM_RELAY_MSG_MAX];
    uint8_t sig[WT_VAULT_KEY_SIG_LEN];
    uint8_t verify_in[WT_VAULT_KEY_DIGEST_LEN + WT_VAULT_KEY_SIG_LEN];
    size_t got = 0U;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int rc;

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_GENERATE, 0x1001ULL,
              WT_VAULT_KEY_USAGE_SIGN | WT_VAULT_KEY_USAGE_VERIFY,
              WT_VAULT_KEY_P256, NULL, 0U, NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_SUCCESS, "P-256 key generates");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_GENERATE, 0x1001ULL,
              WT_VAULT_KEY_USAGE_SIGN, WT_VAULT_KEY_P256, NULL, 0U, NULL,
              0U, &got, &status);
    check(rc == 0 && status == PSA_ERROR_ALREADY_EXISTS,
          "generate refuses an occupied UID");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_EXPORT_PUBLIC, 0x1001ULL, 0U,
              0U, NULL, 0U, out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_SUCCESS && got == WT_VAULT_KEY_PUB_LEN &&
          out[0] == 0x04U,
          "public export returns the 65-byte X9.63 point");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_SIGN, 0x1001ULL, 0U, 0U,
              digest, sizeof(digest), sig, sizeof(sig), &got, &status);
    check(rc == 0 && status == PSA_SUCCESS && got == sizeof(sig),
          "sign returns a 64-byte r||s signature");

    (void)memcpy(verify_in, digest, sizeof(digest));
    (void)memcpy(verify_in + sizeof(digest), sig, sizeof(sig));
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_VERIFY, 0x1001ULL, 0U, 0U,
              verify_in, sizeof(verify_in), NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_SUCCESS, "verify accepts the signature");

    verify_in[0] ^= 0x01U;
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_VERIFY, 0x1001ULL, 0U, 0U,
              verify_in, sizeof(verify_in), NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_SIGNATURE,
          "verify rejects a tampered digest");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_VERIFY, 0x1001ULL, 0U, 0U,
              verify_in, sizeof(verify_in) - 1U, NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_ARGUMENT,
          "verify refuses a malformed digest+signature payload");

    /* The key namespace is (owner, SPM-stamped client, uid): another client
     * using the same UID reaches nothing. */
    rc = wire(TEST_NS_GUEST1, WT_CRYPTO_OP_KEY_SIGN, 0x1001ULL, 0U, 0U,
              digest, sizeof(digest), sig, sizeof(sig), &got, &status);
    check(rc == 0 && status == PSA_ERROR_DOES_NOT_EXIST && got == 0U,
          "another client cannot sign with this client's key");
    rc = wire(TEST_NS_GUEST1, WT_CRYPTO_OP_KEY_EXPORT_PUBLIC, 0x1001ULL, 0U,
              0U, NULL, 0U, out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_ERROR_DOES_NOT_EXIST,
          "another client cannot export this client's public key");
    rc = wire(TEST_NS_GUEST1, WT_CRYPTO_OP_KEY_DESTROY, 0x1001ULL, 0U, 0U,
              NULL, 0U, NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_ERROR_DOES_NOT_EXIST,
          "another client cannot destroy this client's key");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_DESTROY, 0x1001ULL, 0U, 0U,
              NULL, 0U, NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_SUCCESS, "owner destroys the key");
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_EXPORT_PUBLIC, 0x1001ULL, 0U,
              0U, NULL, 0U, out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_ERROR_DOES_NOT_EXIST,
          "a destroyed key is gone");
}

static void test_usage_and_type(void)
{
    static const uint8_t digest[32] = { 0x01 };
    uint8_t out[WT_HSM_RELAY_MSG_MAX];
    size_t got = 0U;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int rc;

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_GENERATE, 0x2001ULL,
              WT_VAULT_KEY_USAGE_VERIFY, WT_VAULT_KEY_P256, NULL, 0U, NULL,
              0U, &got, &status);
    check(rc == 0 && status == PSA_SUCCESS, "verify-only P-256 key generates");
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_SIGN, 0x2001ULL, 0U, 0U,
              digest, sizeof(digest), out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_ERROR_NOT_PERMITTED && got == 0U,
          "sign is refused without the SIGN usage bit");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_GENERATE, 0x2002ULL, 0U,
              WT_VAULT_KEY_P256, NULL, 0U, NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_ARGUMENT,
          "generate refuses an empty usage mask");
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_GENERATE, 0x2003ULL,
              WT_VAULT_KEY_USAGE_SIGN, 0x7fU, NULL, 0U, NULL, 0U, &got,
              &status);
    check(rc == 0 && status == PSA_ERROR_NOT_SUPPORTED,
          "generate refuses an unknown key type");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_GENERATE, 0x2004ULL,
              WT_VAULT_KEY_USAGE_ENCRYPT | WT_VAULT_KEY_USAGE_DECRYPT,
              WT_VAULT_KEY_AES256, NULL, 0U, NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_SUCCESS, "AES-256 key generates");
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_SIGN, 0x2004ULL, 0U, 0U,
              digest, sizeof(digest), out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_ERROR_NOT_PERMITTED,
          "an AES key cannot be used to sign");
}

static void test_aes_gcm(void)
{
    static const uint8_t plaintext[] = "native wire AES-GCM round trip";
    uint8_t ct[WT_HSM_RELAY_MSG_MAX];
    uint8_t pt[WT_HSM_RELAY_MSG_MAX];
    size_t ct_len = 0U;
    size_t pt_len = 0U;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int rc;

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_ENCRYPT, 0x2004ULL, 0U, 0U,
              plaintext, sizeof(plaintext), ct, sizeof(ct), &ct_len,
              &status);
    check(rc == 0 && status == PSA_SUCCESS &&
          ct_len == sizeof(plaintext) + WT_VAULT_KEY_NONCE_LEN +
                        WT_VAULT_KEY_TAG_LEN,
          "encrypt frames nonce || ciphertext || tag");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_DECRYPT, 0x2004ULL, 0U, 0U,
              ct, ct_len, pt, sizeof(pt), &pt_len, &status);
    check(rc == 0 && status == PSA_SUCCESS && pt_len == sizeof(plaintext) &&
          memcmp(pt, plaintext, sizeof(plaintext)) == 0,
          "decrypt recovers the plaintext");

    ct[ct_len - 1U] ^= 0x01U;
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_DECRYPT, 0x2004ULL, 0U, 0U,
              ct, ct_len, pt, sizeof(pt), &pt_len, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_SIGNATURE && pt_len == 0U,
          "decrypt rejects a tampered tag and returns no plaintext");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_DECRYPT, 0x2004ULL, 0U, 0U,
              ct, WT_VAULT_KEY_NONCE_LEN, pt, sizeof(pt), &pt_len, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_ARGUMENT,
          "decrypt refuses input shorter than nonce + tag");
}

static void test_import(void)
{
    static const uint8_t scalar[WT_VAULT_KEY_MATERIAL_LEN] = {
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
        0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
        0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21
    };
    /* RFC 6979 A.2.5 public point for the scalar above. */
    static const uint8_t expect_x[8] = {
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31
    };
    uint8_t out[WT_HSM_RELAY_MSG_MAX];
    size_t got = 0U;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int rc;

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_IMPORT, 0x3001ULL,
              WT_VAULT_KEY_USAGE_SIGN, WT_VAULT_KEY_P256, scalar,
              sizeof(scalar), NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_SUCCESS, "P-256 scalar imports");
    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_EXPORT_PUBLIC, 0x3001ULL, 0U,
              0U, NULL, 0U, out, sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_SUCCESS && got == WT_VAULT_KEY_PUB_LEN &&
          out[0] == 0x04U && memcmp(out + 1, expect_x, sizeof(expect_x)) == 0,
          "imported key derives the RFC 6979 public point");

    rc = wire(TEST_NS_GUEST0, WT_CRYPTO_OP_KEY_IMPORT, 0x3002ULL,
              WT_VAULT_KEY_USAGE_SIGN, WT_VAULT_KEY_P256, scalar,
              sizeof(scalar) - 1U, NULL, 0U, &got, &status);
    check(rc == 0 && status == PSA_ERROR_INVALID_ARGUMENT,
          "import refuses a short scalar");
}

static void test_malformed(void)
{
    uint8_t req[WT_HSM_RELAY_MSG_MAX];
    uint8_t resp[WT_HSM_RELAY_MSG_MAX];
    uint8_t out[WT_HSM_RELAY_MSG_MAX];
    wt_crypto_wire_req_t hdr;
    size_t resp_len = 0U;
    size_t got = 0U;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int32_t wire_status = 0;
    int rc;

    (void)memset(req, 0, sizeof(req));
    rc = wt_native_submit((void*)(intptr_t)TEST_OWNER, TEST_NS_GUEST0, req,
                          sizeof(hdr) - 1U, resp, sizeof(resp), &resp_len);
    check(rc != 0, "a packet shorter than the header is refused");

    rc = wt_native_submit((void*)(intptr_t)TEST_OWNER, TEST_NS_GUEST0, req,
                          sizeof(hdr), resp, sizeof(wire_status) - 1U,
                          &resp_len);
    check(rc != 0, "a response buffer smaller than the status is refused");

    rc = wt_native_submit((void*)(intptr_t)TEST_OWNER, TEST_NS_GUEST0, NULL,
                          sizeof(hdr), resp, sizeof(resp), &resp_len);
    check(rc != 0, "a NULL request is refused");

    rc = wire(TEST_NS_GUEST0, 0x7fffU, 0U, 0U, 0U, NULL, 0U, out,
              sizeof(out), &got, &status);
    check(rc == 0 && status == PSA_ERROR_NOT_SUPPORTED && got == 0U,
          "an unknown operation is refused");

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.op = WT_CRYPTO_OP_RANDOM;
    hdr.usage = 16U;
    hdr.reserved = 0xdeadbeefU;
    (void)memcpy(req, &hdr, sizeof(hdr));
    resp_len = 0U;
    rc = wt_native_submit((void*)(intptr_t)TEST_OWNER, TEST_NS_GUEST0, req,
                          sizeof(hdr), resp, sizeof(resp), &resp_len);
    (void)memcpy(&wire_status, resp, sizeof(wire_status));
    check(rc == 0 && resp_len == sizeof(wire_status) &&
          wire_status == (int32_t)PSA_ERROR_INVALID_ARGUMENT,
          "a nonzero reserved field is refused");

    /* A response buffer too small for the public point: status only. */
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.uid = 0x3001ULL;
    hdr.op = WT_CRYPTO_OP_KEY_EXPORT_PUBLIC;
    (void)memcpy(req, &hdr, sizeof(hdr));
    rc = wt_native_submit((void*)(intptr_t)TEST_OWNER, TEST_NS_GUEST0, req,
                          sizeof(hdr), resp,
                          sizeof(wire_status) + WT_VAULT_KEY_PUB_LEN - 1U,
                          &resp_len);
    (void)memcpy(&wire_status, resp, sizeof(wire_status));
    check(rc == 0 && resp_len == sizeof(wire_status) &&
          wire_status == (int32_t)PSA_ERROR_BUFFER_TOO_SMALL,
          "an undersized output buffer yields BUFFER_TOO_SMALL and no data");
}

int main(void)
{
    if (test_store_up() != 0) {
        (void)fprintf(stderr, "NVM/keyvault bring-up failed\n");
        return 1;
    }

    test_random_and_hash();
    test_p256_lifecycle();
    test_usage_and_type();
    test_aes_gcm();
    test_import();
    test_malformed();

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: native crypto wire over the vault key backend\n");
    return 0;
}
