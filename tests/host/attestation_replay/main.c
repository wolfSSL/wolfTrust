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
 * P5-S5 replay + lifecycle: a token is bound to its challenge (a verifier's
 * fresh nonce defeats replay of an old token) and to the boot lifecycle
 * carried by the DICE handoff — including across a real lifecycle transition
 * (0x1000 development -> 0x3000 secured via a new handoff), not just the one
 * fixed value.
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

static int make_handoff(wt_boot_handoff_t* handoff, uint32_t lifecycle)
{
    (void)memset(handoff, 0, sizeof(*handoff));
    handoff->magic = WT_BOOT_HANDOFF_MAGIC;
    handoff->version = WT_BOOT_HANDOFF_VERSION;
    handoff->lifecycle = lifecycle;
    handoff->hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    handoff->measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    (void)memset(handoff->measurement, 0xAB, sizeof(handoff->measurement));
    return 0;
}

int main(void)
{
    uint8_t bootSeed[WT_ATTEST_BOOT_SEED_SIZE] = { 0xA5u };
    wt_boot_handoff_t handoff;
    uint8_t challengeA[WT_ATTEST_CHALLENGE_SIZE_32];
    uint8_t challengeB[WT_ATTEST_CHALLENGE_SIZE_32];
    uint8_t tokenA[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t tokenB[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t tokenC[WT_ATTEST_MAX_TOKEN_SIZE];
    char measHex[65];
    word32 pubLen = (word32)sizeof(g_iak_pub);
    size_t sizeA = 0u;
    size_t sizeB = 0u;
    size_t sizeC = 0u;
    size_t i;
    uint32_t verifiedLifecycle = 0u;
    int ret;

    if (wc_InitRng(&g_rng) != 0) {
        printf("FAIL: attestation_replay (RNG init)\n");
        return 1;
    }
    if ((wc_ecc_init(&g_iak) != 0) ||
        (wc_ecc_make_key(&g_rng, 32, &g_iak) != 0) ||
        (wc_ecc_export_x963(&g_iak, g_iak_pub, &pubLen) != 0) ||
        (pubLen != IAK_PUB_SIZE)) {
        printf("FAIL: attestation_replay (IAK setup)\n");
        return 1;
    }

    (void)memset(challengeA, 0x11, sizeof(challengeA));
    (void)memset(challengeB, 0x22, sizeof(challengeB));
    for (i = 0u; i < 32u; ++i) {
        measHex[i * 2u] = 'a';
        measHex[(i * 2u) + 1u] = 'b';
    }
    measHex[64] = '\0';

    /* Boot in the development lifecycle. */
    (void)make_handoff(&handoff, 0x1000u);
    ret = wt_initial_attest_init(&handoff, bootSeed);
    check(ret == WT_ATTEST_SUCCESS, "development-lifecycle handoff accepted");

    ret = wt_initial_attest_get_token(0u, challengeA, sizeof(challengeA),
                                      tokenA, sizeof(tokenA), &sizeA);
    check(ret == WT_ATTEST_SUCCESS, "token A issues for challenge A");
    ret = wt_initial_attest_get_token(0u, challengeB, sizeof(challengeB),
                                      tokenB, sizeof(tokenB), &sizeB);
    check(ret == WT_ATTEST_SUCCESS, "token B issues for challenge B");

    /* Different challenge -> different token bytes (not a canned response). */
    check((sizeA != sizeB) || (memcmp(tokenA, tokenB, sizeA) != 0),
          "different challenges produce different tokens");

    /* Each token verifies only under its own challenge. */
    ret = wt_attestation_verify(tokenA, sizeA, g_iak_pub, IAK_PUB_SIZE,
                                challengeA, sizeof(challengeA), measHex,
                                0x1000u, &verifiedLifecycle);
    check((ret == 0) && (verifiedLifecycle == 0x1000u),
          "token A verifies under challenge A (lifecycle 0x1000)");
    ret = wt_attestation_verify(tokenB, sizeB, g_iak_pub, IAK_PUB_SIZE,
                                challengeB, sizeof(challengeB), measHex,
                                0x1000u, &verifiedLifecycle);
    check(ret == 0, "token B verifies under challenge B");

    /* Replay refusal: an old token cannot answer a fresh nonce. */
    ret = wt_attestation_verify(tokenA, sizeA, g_iak_pub, IAK_PUB_SIZE,
                                challengeB, sizeof(challengeB), measHex,
                                0x1000u, &verifiedLifecycle);
    check(ret != 0, "replayed token A is rejected under fresh challenge B");
    ret = wt_attestation_verify(tokenB, sizeB, g_iak_pub, IAK_PUB_SIZE,
                                challengeA, sizeof(challengeA), measHex,
                                0x1000u, &verifiedLifecycle);
    check(ret != 0, "replayed token B is rejected under challenge A");

    /* Real lifecycle transition: a new handoff moves 0x1000 -> 0x3000. */
    (void)make_handoff(&handoff, 0x3000u);
    bootSeed[0] = 0x5Au;
    ret = wt_initial_attest_init(&handoff, bootSeed);
    check(ret == WT_ATTEST_SUCCESS, "secured-lifecycle handoff accepted");

    ret = wt_initial_attest_get_token(0u, challengeA, sizeof(challengeA),
                                      tokenC, sizeof(tokenC), &sizeC);
    check(ret == WT_ATTEST_SUCCESS, "token C issues after the transition");
    ret = wt_attestation_verify(tokenC, sizeC, g_iak_pub, IAK_PUB_SIZE,
                                challengeA, sizeof(challengeA), measHex,
                                0x3000u, &verifiedLifecycle);
    check((ret == 0) && (verifiedLifecycle == 0x3000u),
          "token C carries the secured lifecycle 0x3000");

    /* Lifecycle binding both directions across the transition. */
    ret = wt_attestation_verify(tokenC, sizeC, g_iak_pub, IAK_PUB_SIZE,
                                challengeA, sizeof(challengeA), measHex,
                                0x1000u, &verifiedLifecycle);
    check(ret != 0, "secured token C is rejected as a development token");
    ret = wt_attestation_verify(tokenA, sizeA, g_iak_pub, IAK_PUB_SIZE,
                                challengeA, sizeof(challengeA), measHex,
                                0x3000u, &verifiedLifecycle);
    check(ret != 0, "old development token A is rejected as secured");

    wc_ecc_free(&g_iak);
    wc_FreeRng(&g_rng);

    printf("attestation_replay host tests: %d checks, %d failures\n",
           g_checks, g_failures);
    if (g_failures == 0) {
        printf("PASS: attestation_replay\n");
        return 0;
    }
    printf("FAIL: attestation_replay\n");
    return 1;
}
