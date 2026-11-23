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
 * P5-S3 attestation negative evidence: the production token path must refuse
 * a garbage DICE handoff, refuse to attest before a valid handoff arrives,
 * reject every invalid challenge size at runtime, and a tampered or
 * misattributed measurement must fail verification. Ordering matters: the
 * not-ready and garbage-handoff checks run before the one good
 * wt_initial_attest_init arms the static handoff state.
 */

#include "wolftrust/services/initial_attestation.h"
#include "wolftrust/services/hsm.h"
#include "attestation_verify.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IAK_PUB_SIZE 65u
#define ES256_RAW_SIG_SIZE 64u

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

int main(void)
{
    wt_boot_handoff_t handoff;
    wt_boot_handoff_t bad;
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_64 + 1u];
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t tampered[WT_ATTEST_MAX_TOKEN_SIZE];
    char measHex[65];
    char wrongHex[65];
    word32 pubLen = (word32)sizeof(g_iak_pub);
    size_t tokenSize = 0u;
    size_t querySize = 0u;
    size_t run = 0u;
    size_t i;
    uint32_t verifiedLifecycle = 0u;
    int ret;

    if (wc_InitRng(&g_rng) != 0) {
        printf("FAIL: attestation_negatives (RNG init)\n");
        return 1;
    }
    if ((wc_ecc_init(&g_iak) != 0) ||
        (wc_ecc_make_key(&g_rng, 32, &g_iak) != 0) ||
        (wc_ecc_export_x963(&g_iak, g_iak_pub, &pubLen) != 0) ||
        (pubLen != IAK_PUB_SIZE)) {
        printf("FAIL: attestation_negatives (IAK setup)\n");
        return 1;
    }

    (void)memset(challenge, 0x2A, sizeof(challenge));

    /* No DICE handoff has arrived yet: attestation must refuse, not sign. */
    ret = wt_initial_attest_get_token(0u, challenge,
        WT_ATTEST_CHALLENGE_SIZE_32, token, sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_NOT_READY,
          "get_token before any handoff is refused (NOT_READY)");
    ret = wt_initial_attest_get_token_size(WT_ATTEST_CHALLENGE_SIZE_32,
                                           &querySize);
    check(ret == WT_ATTEST_ERROR_NOT_READY,
          "get_token_size before any handoff is refused (NOT_READY)");

    /* Garbage DICE handoffs are rejected and must not arm the state. */
    ret = wt_initial_attest_init(NULL);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "NULL handoff is rejected");

    (void)memset(&bad, 0, sizeof(bad));
    bad.magic = WT_BOOT_HANDOFF_MAGIC;
    bad.version = WT_BOOT_HANDOFF_VERSION;
    bad.lifecycle = 0x3000u;
    bad.hash_algorithm = 0xEEEEu;
    bad.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    ret = wt_initial_attest_init(&bad);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "handoff with an unknown hash algorithm is rejected");

    bad.hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    bad.measurement_size = 16u;
    ret = wt_initial_attest_init(&bad);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "handoff with a truncated measurement is rejected");

    bad.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    bad.lifecycle = 0x10000u;
    ret = wt_initial_attest_init(&bad);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "handoff with an out-of-range lifecycle is rejected");

    bad.lifecycle = 0x7000u;
    ret = wt_initial_attest_init(&bad);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "handoff with an unsupported lifecycle state is rejected");

    ret = wt_initial_attest_get_token(0u, challenge,
        WT_ATTEST_CHALLENGE_SIZE_32, token, sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_NOT_READY,
          "rejected handoffs leave attestation refusing (still NOT_READY)");

    /* One good handoff arms the path. */
    (void)memset(&handoff, 0, sizeof(handoff));
    handoff.magic = WT_BOOT_HANDOFF_MAGIC;
    handoff.version = WT_BOOT_HANDOFF_VERSION;
    handoff.lifecycle = 0x3000u;
    handoff.hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    handoff.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    (void)memset(handoff.measurement, 0xAB, sizeof(handoff.measurement));
    for (i = 0u; i < 32u; ++i) {
        measHex[i * 2u] = 'a';
        measHex[(i * 2u) + 1u] = 'b';
        wrongHex[i * 2u] = 'c';
        wrongHex[(i * 2u) + 1u] = 'd';
    }
    measHex[64] = '\0';
    wrongHex[64] = '\0';
    ret = wt_initial_attest_init(&handoff);
    check(ret == WT_ATTEST_SUCCESS, "valid handoff is accepted");

    /* Invalid challenge sizes are rejected at runtime, 65 (>64) included. */
    ret = wt_initial_attest_get_token(0u, challenge, 0u, token,
                                      sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "zero challenge is rejected");
    ret = wt_initial_attest_get_token(0u, challenge, 31u, token,
                                      sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "31-byte challenge is rejected");
    ret = wt_initial_attest_get_token(0u, challenge, 33u, token,
                                      sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "33-byte challenge is rejected");
    ret = wt_initial_attest_get_token(0u, challenge,
        WT_ATTEST_CHALLENGE_SIZE_64 + 1u, token, sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "oversized 65-byte challenge is rejected");
    ret = wt_initial_attest_get_token_size(WT_ATTEST_CHALLENGE_SIZE_64 + 1u,
                                           &querySize);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "get_token_size rejects the oversized challenge");
    ret = wt_initial_attest_get_token(0u, NULL, WT_ATTEST_CHALLENGE_SIZE_32,
                                      token, sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "NULL challenge is rejected");
    ret = wt_initial_attest_get_token(WT_MAX_GUESTS, challenge,
        WT_ATTEST_CHALLENGE_SIZE_32, token, sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_ERROR_INVALID_ARGUMENT,
          "out-of-range guest id is rejected");
    token[0] = 0xA5u;
    tokenSize = 1u;
    ret = wt_initial_attest_get_token(0u, challenge, WT_ATTEST_CHALLENGE_SIZE_32,
                                      token, 0u, &tokenSize);
    check(ret == WT_ATTEST_ERROR_BUFFER_TOO_SMALL && tokenSize == 0u &&
          token[0] == 0xA5u, "zero-capacity token buffer is too small");

    /* A good token binds the boot measurement. */
    ret = wt_initial_attest_get_token(0u, challenge,
        WT_ATTEST_CHALLENGE_SIZE_32, token, sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_SUCCESS, "token issues after the valid handoff");
    ret = wt_attestation_verify(token, tokenSize, g_iak_pub, IAK_PUB_SIZE,
                                challenge, WT_ATTEST_CHALLENGE_SIZE_32,
                                measHex, 0x3000u, &verifiedLifecycle);
    check((ret == 0) && (verifiedLifecycle == 0x3000u),
          "token verifies against the true measurement");

    /* Misattributed measurement: the same token must not pass as evidence of
     * different firmware. */
    ret = wt_attestation_verify(token, tokenSize, g_iak_pub, IAK_PUB_SIZE,
                                challenge, WT_ATTEST_CHALLENGE_SIZE_32,
                                wrongHex, 0x3000u, &verifiedLifecycle);
    check(ret != 0, "token is rejected against a different measurement");

    /* Lifecycle misattribution is also rejected. */
    ret = wt_attestation_verify(token, tokenSize, g_iak_pub, IAK_PUB_SIZE,
                                challenge, WT_ATTEST_CHALLENGE_SIZE_32,
                                measHex, 0x1000u, &verifiedLifecycle);
    check(ret != 0, "token is rejected against a different lifecycle");

    /* Tampered measurement inside the signed token: flip one byte of the
     * 32-byte 0xAB run carried in the payload; the ES256 signature must
     * catch it. */
    (void)memcpy(tampered, token, tokenSize);
    run = 0u;
    for (i = 0u; i < tokenSize; ++i) {
        run = (tampered[i] == 0xABu) ? (run + 1u) : 0u;
        if (run == 32u) {
            tampered[i] ^= 0x01u;
            break;
        }
    }
    check(run == 32u, "measurement bytes located inside the token");
    ret = wt_attestation_verify(tampered, tokenSize, g_iak_pub, IAK_PUB_SIZE,
                                challenge, WT_ATTEST_CHALLENGE_SIZE_32,
                                measHex, 0x3000u, &verifiedLifecycle);
    check(ret != 0, "tampered in-token measurement breaks the signature");

    wc_ecc_free(&g_iak);
    wc_FreeRng(&g_rng);

    printf("attestation_negatives host tests: %d checks, %d failures\n",
           g_checks, g_failures);
    if (g_failures == 0) {
        printf("PASS: attestation_negatives\n");
        return 0;
    }
    printf("FAIL: attestation_negatives\n");
    return 1;
}
