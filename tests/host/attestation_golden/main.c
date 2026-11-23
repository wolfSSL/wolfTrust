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

/*
 * Deterministic EAT claims: with a fixed IAK (RFC 6979 P-256 test key),
 * fixed boot handoff, and fixed challenge, the production claim encoder must
 * emit a byte-stable RFC 9783 #tfm claim set — pinned here against an embedded
 * golden vector so any unintended change to the token wire format fails CI.
 * Rebuild with EXTRA_CFLAGS=-DWT_GOLDEN_GEN to print a fresh vector after an
 * intended claim change.
 */

#include "wolftrust/services/initial_attestation.h"
#include "wolftrust/services/hsm.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfcose/wolfcose.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IAK_PUB_SIZE 65u
#define ES256_RAW_SIG_SIZE 64u
#define WT_EAT_CLAIM_BOOT_SEED 268
#define WT_EAT_CLAIM_PROFILE 265

/* RFC 6979 A.2.5 P-256 test key: deterministic IAK for the golden vector. */
static const char* kIakQx =
    "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
static const char* kIakQy =
    "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
static const char* kIakD =
    "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

/* Golden encoded claim set for the fixed key/handoff/challenge above. */
static const uint8_t g_golden_payload[] = {
#include "golden_payload.inc"
};

static int g_checks;
static int g_failures;
static ecc_key g_iak;
static WC_RNG g_rng;
static uint8_t g_iak_pub[IAK_PUB_SIZE];

static void check(int cond, const char* name)
{
    g_checks++;
    if (cond != 0) {
        printf("  [check] PASS  %s\n", name);
    }
    else {
        g_failures++;
        printf("  [check] FAIL  %s\n", name);
    }
}

int wt_hsm_attest_sign(const uint8_t* digest, size_t digestSize,
    uint8_t* signature, size_t signatureCapacity, size_t* signatureSize)
{
    uint8_t der[80];
    uint8_t r[32];
    uint8_t s[32];
    word32 derLen = (word32)sizeof(der);
    word32 rLen = (word32)sizeof(r);
    word32 sLen = (word32)sizeof(s);
    int ret;

    if ((digest == NULL) || (signature == NULL) || (signatureSize == NULL) ||
        (digestSize != 32u) || (signatureCapacity < ES256_RAW_SIG_SIZE)) {
        return -1;
    }
    ret = wc_ecc_sign_hash(digest, (word32)digestSize, der, &derLen, &g_rng,
                           &g_iak);
    if (ret == 0) {
        ret = wc_ecc_sig_to_rs(der, derLen, r, &rLen, s, &sLen);
    }
    if (ret == 0) {
        (void)memset(signature, 0, ES256_RAW_SIG_SIZE);
        (void)memcpy(signature + (32u - rLen), r, rLen);
        (void)memcpy(signature + 32u + (32u - sLen), s, sLen);
        *signatureSize = ES256_RAW_SIG_SIZE;
    }
    return ret == 0 ? 0 : -1;
}

int wt_hsm_attest_public_key(uint8_t* publicKey, size_t publicKeyCapacity,
    size_t* publicKeySize)
{
    if ((publicKey == NULL) || (publicKeySize == NULL) ||
        (publicKeyCapacity < IAK_PUB_SIZE)) {
        return -1;
    }
    (void)memcpy(publicKey, g_iak_pub, IAK_PUB_SIZE);
    *publicKeySize = IAK_PUB_SIZE;
    return 0;
}

static int cose_recover(const uint8_t* token, size_t tokenSize,
    uint8_t* payloadBuf, size_t payloadCap, size_t* payloadLen)
{
    uint8_t scratch[512];
    WOLFCOSE_HDR header;
    WOLFCOSE_KEY coseKey;
    const uint8_t* payload = NULL;
    size_t payloadSize = 0u;
    int coseInited = 0;
    int ret;

    ret = wc_CoseKey_Init(&coseKey);
    if (ret == 0) {
        coseInited = 1;
        ret = wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &g_iak);
    }
    if (ret == 0) {
        (void)memset(&header, 0, sizeof(header));
        ret = wc_CoseSign1_Verify(&coseKey, token, tokenSize, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &header, &payload,
            &payloadSize);
    }
    if ((ret == 0) && (payloadSize <= payloadCap)) {
        (void)memcpy(payloadBuf, payload, payloadSize);
        *payloadLen = payloadSize;
    }
    else if (ret == 0) {
        ret = -1;
    }

    if (coseInited != 0) {
        wc_CoseKey_Free(&coseKey);
    }
    (void)memset(scratch, 0, sizeof(scratch));
    return ret;
}

static int has_claim(const uint8_t* payload, size_t payloadSize,
    int64_t wanted, const uint8_t* expected, size_t expectedSize)
{
    WOLFCOSE_CBOR_CTX cbor;
    const uint8_t* value;
    size_t valueSize;
    size_t mapCount;
    size_t i;
    int64_t label;
    int found = 0;
    int ret;

    (void)memset(&cbor, 0, sizeof(cbor));
    cbor.cbuf = payload;
    cbor.bufSz = payloadSize;
    ret = wc_CBOR_DecodeMapStart(&cbor, &mapCount);
    for (i = 0u; (ret == 0) && (i < mapCount); ++i) {
        ret = wc_CBOR_DecodeInt(&cbor, &label);
        if ((ret == 0) && (label == wanted) && (expected != NULL)) {
            ret = wc_CBOR_DecodeBstr(&cbor, &value, &valueSize);
            found = (ret == 0) && (valueSize == expectedSize) &&
                    (memcmp(value, expected, valueSize) == 0);
        }
        else if (ret == 0) {
            if (label == wanted) {
                found = 1;
            }
            ret = wc_CBOR_Skip(&cbor);
        }
    }
    return ((ret == 0) && (found != 0)) ? 1 : 0;
}

int main(void)
{
    static const uint8_t bootSeedA[WT_ATTEST_BOOT_SEED_SIZE] = { 0xA5u };
    static const uint8_t bootSeedB[WT_ATTEST_BOOT_SEED_SIZE] = { 0x5Au };
    wt_boot_handoff_t handoff;
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_32];
    uint8_t tokenA[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t tokenB[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t payloadA[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t payloadB[WT_ATTEST_MAX_TOKEN_SIZE];
    word32 pubLen = (word32)sizeof(g_iak_pub);
    size_t sizeA = 0u;
    size_t sizeB = 0u;
    size_t payloadLenA = 0u;
    size_t payloadLenB = 0u;
    size_t i;
    int ret;

    if (wc_InitRng(&g_rng) != 0) {
        printf("FAIL: attestation_golden (RNG init)\n");
        return 1;
    }
    if (wc_ecc_init(&g_iak) != 0) {
        printf("FAIL: attestation_golden (ecc init)\n");
        return 1;
    }
    if (wc_ecc_import_raw(&g_iak, kIakQx, kIakQy, kIakD, "SECP256R1") != 0) {
        printf("FAIL: attestation_golden (fixed key import)\n");
        return 1;
    }
    if (wc_ecc_export_x963(&g_iak, g_iak_pub, &pubLen) != 0 ||
            pubLen != IAK_PUB_SIZE) {
        printf("FAIL: attestation_golden (pubkey export)\n");
        return 1;
    }

    (void)memset(&handoff, 0, sizeof(handoff));
    handoff.magic = WT_BOOT_HANDOFF_MAGIC;
    handoff.version = WT_BOOT_HANDOFF_VERSION;
    handoff.lifecycle = 0x3000u;
    handoff.hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    handoff.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    (void)memset(handoff.measurement, 0xAB, sizeof(handoff.measurement));
    (void)memset(challenge, 0x2A, sizeof(challenge));

    ret = wt_initial_attest_init(&handoff, bootSeedA);
    check(ret == WT_ATTEST_SUCCESS, "wt_initial_attest_init succeeds");

    ret = wt_initial_attest_get_token(0u, challenge, sizeof(challenge),
                                      tokenA, sizeof(tokenA), &sizeA);
    check(ret == WT_ATTEST_SUCCESS, "first get_token succeeds");
    ret = wt_initial_attest_init(&handoff, bootSeedA);
    check(ret == WT_ATTEST_SUCCESS, "restore accepts the current boot seed");
    ret = wt_initial_attest_get_token(0u, challenge, sizeof(challenge),
                                      tokenB, sizeof(tokenB), &sizeB);
    check(ret == WT_ATTEST_SUCCESS, "second get_token succeeds");

    check(sizeA == sizeB, "token size is deterministic");
    check((sizeA > ES256_RAW_SIG_SIZE) &&
          (memcmp(tokenA, tokenB, sizeA - ES256_RAW_SIG_SIZE) == 0),
          "token bytes are identical up to the ECDSA signature");

    ret = cose_recover(tokenA, sizeA, payloadA, sizeof(payloadA),
                       &payloadLenA);
    check(ret == 0, "first token verifies against the fixed IAK");
    ret = cose_recover(tokenB, sizeB, payloadB, sizeof(payloadB),
                       &payloadLenB);
    check(ret == 0, "second token verifies against the fixed IAK");
    check((payloadLenA == payloadLenB) &&
          (memcmp(payloadA, payloadB, payloadLenA) == 0),
          "claim set is byte-identical across tokens");

#if defined(WT_GOLDEN_GEN)
    printf("/* golden_payload.inc — %u bytes */\n", (unsigned)payloadLenA);
    for (i = 0u; i < payloadLenA; ++i) {
        printf("0x%02X,%s", payloadA[i], ((i + 1u) % 12u) ? " " : "\n");
    }
    printf("\n");
#else
    (void)i;
#endif

    check(payloadLenA == sizeof(g_golden_payload),
          "claim set length matches the golden vector");
    check((payloadLenA == sizeof(g_golden_payload)) &&
          (memcmp(payloadA, g_golden_payload, payloadLenA) == 0),
          "claim set bytes match the golden vector");

    check(has_claim(payloadA, payloadLenA, 10, challenge,
                    sizeof(challenge)) == 1, "nonce claim (10) matches");
    check(has_claim(payloadA, payloadLenA, WT_EAT_CLAIM_PROFILE,
                    NULL, 0u) == 1,
          "profile claim (265) present");
    check(has_claim(payloadA, payloadLenA, WT_EAT_CLAIM_BOOT_SEED,
                    bootSeedA, sizeof(bootSeedA)) == 1,
          "boot-seed claim (268) matches the retained value");

    ret = wt_initial_attest_init(&handoff, bootSeedB);
    check(ret == WT_ATTEST_SUCCESS, "same measured image accepts a new boot");
    ret = wt_initial_attest_get_token(0u, challenge, sizeof(challenge),
                                      tokenB, sizeof(tokenB), &sizeB);
    check(ret == WT_ATTEST_SUCCESS, "get_token succeeds on the new boot");
    ret = cose_recover(tokenB, sizeB, payloadB, sizeof(payloadB),
                       &payloadLenB);
    check(ret == 0 &&
          has_claim(payloadB, payloadLenB, WT_EAT_CLAIM_BOOT_SEED,
                    bootSeedB, sizeof(bootSeedB)) == 1,
          "same measured image emits the new boot seed");

    wc_ecc_free(&g_iak);
    wc_FreeRng(&g_rng);

    printf("attestation_golden host tests: %d checks, %d failures\n",
           g_checks, g_failures);
    if (g_failures == 0) {
        printf("PASS: attestation_golden\n");
        return 0;
    }
    printf("FAIL: attestation_golden\n");
    return 1;
}
