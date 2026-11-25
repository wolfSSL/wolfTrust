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
 * P5-CONF production token evidence: drive the real wt_initial_attest_get_token
 * encoder with a stub IAK signer and prove the emitted EAT still verifies. This
 * covers the two production changes ARM's dev_apis/initial_attestation test_a001
 * requires: the COSE_Sign1 is now tagged (tag 18) and the SW component carries a
 * profile-2 signer_id (label 5). The token is fed back through the production
 * guest verifier to prove tagging does not break wolfTrust's own path.
 */

#include "wolftrust/services/initial_attestation.h"
#include "wolftrust/services/hsm.h"
#include "attestation_verify.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <wolfcose/wolfcose.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IAK_PUB_SIZE 65u
#define ES256_RAW_SIG_SIZE 64u
#define WT_PSA_CLAIM_SW_COMPONENTS 2399
#define WT_PSA_SW_MEASUREMENT_SIGNER_ID 5

static int g_checks;
static int g_failures;
static ecc_key g_iak;
static ecc_key g_wrong;
static WC_RNG g_rng;
static uint8_t g_iak_pub[IAK_PUB_SIZE];
static uint8_t g_wrong_pub[IAK_PUB_SIZE];

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

/* HSM seam stubs: the production encoder signs the token digest and fetches the
 * IAK public key through these two calls; back them with a local P-256 key so
 * the whole get_token -> verify round trip runs on the host. */
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

/* Verify the tagged COSE_Sign1 against the IAK public key and copy the payload
 * out, so the claim walk below can read the recovered EAT bytes. */
static int cose_recover(const uint8_t* token, size_t tokenSize,
    uint8_t* payloadBuf, size_t payloadCap, size_t* payloadLen)
{
    uint8_t scratch[512];
    WOLFCOSE_HDR header;
    WOLFCOSE_KEY coseKey;
    ecc_key eccKey;
    const uint8_t* payload = NULL;
    size_t payloadSize = 0u;
    int coseInited = 0;
    int eccInited = 0;
    int ret;

    ret = wc_ecc_init(&eccKey);
    if (ret == 0) {
        eccInited = 1;
        ret = wc_ecc_import_unsigned(&eccKey, &g_iak_pub[1], &g_iak_pub[33],
                                     NULL, ECC_SECP256R1);
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&coseKey);
        if (ret == 0) {
            coseInited = 1;
            ret = wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &eccKey);
        }
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
    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    (void)memset(scratch, 0, sizeof(scratch));
    return ret;
}

/* Walk the EAT claims to the first SW component and copy out its signer_id
 * (label 5), proving the profile-2 claim is present in the encoded token. */
static int extract_signer_id(const uint8_t* payload, size_t payloadSize,
    uint8_t* out32)
{
    WOLFCOSE_CBOR_CTX cbor;
    const uint8_t* data;
    size_t dataSize;
    size_t mapCount;
    size_t arrCount;
    size_t swMap;
    size_t i;
    size_t j;
    int64_t label;
    int found = 0;
    int ret;

    (void)memset(&cbor, 0, sizeof(cbor));
    cbor.cbuf = payload;
    cbor.bufSz = payloadSize;
    ret = wc_CBOR_DecodeMapStart(&cbor, &mapCount);
    for (i = 0u; (ret == 0) && (i < mapCount); ++i) {
        ret = wc_CBOR_DecodeInt(&cbor, &label);
        if ((ret == 0) && (label == WT_PSA_CLAIM_SW_COMPONENTS)) {
            ret = wc_CBOR_DecodeArrayStart(&cbor, &arrCount);
            if ((ret == 0) && (arrCount == 1u)) {
                ret = wc_CBOR_DecodeMapStart(&cbor, &swMap);
            }
            else if (ret == 0) {
                ret = -1;
            }
            for (j = 0u; (ret == 0) && (j < swMap); ++j) {
                ret = wc_CBOR_DecodeInt(&cbor, &label);
                if ((ret == 0) && (label == WT_PSA_SW_MEASUREMENT_SIGNER_ID)) {
                    ret = wc_CBOR_DecodeBstr(&cbor, &data, &dataSize);
                    if ((ret == 0) && (dataSize == 32u)) {
                        (void)memcpy(out32, data, 32u);
                        found = 1;
                    }
                    else if (ret == 0) {
                        ret = -1;
                    }
                }
                else if (ret == 0) {
                    ret = wc_CBOR_Skip(&cbor);
                }
            }
        }
        else if (ret == 0) {
            ret = wc_CBOR_Skip(&cbor);
        }
    }
    return ((ret == 0) && (found != 0)) ? 0 : -1;
}

static int run_challenge(size_t challengeSize, const char* measHex,
    const uint8_t* expectedSigner)
{
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_64];
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t payload[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t signerId[32];
    size_t predicted = 0u;
    size_t tokenSize = 0u;
    size_t payloadLen = 0u;
    uint32_t verifiedLifecycle = 0u;
    char name[64];
    int ret;

    (void)memset(challenge, 0x2a, sizeof(challenge));

    ret = wt_initial_attest_get_token_size(challengeSize, &predicted);
    (void)snprintf(name, sizeof(name), "get_token_size(%u) succeeds",
                   (unsigned)challengeSize);
    check(ret == WT_ATTEST_SUCCESS, name);

    ret = wt_initial_attest_get_token(0u, challenge, challengeSize, token,
                                      sizeof(token), &tokenSize);
    (void)snprintf(name, sizeof(name), "get_token(%u) succeeds",
                   (unsigned)challengeSize);
    check(ret == WT_ATTEST_SUCCESS, name);

    (void)snprintf(name, sizeof(name),
                   "encoded token size matches get_token_size(%u)",
                   (unsigned)challengeSize);
    check((tokenSize > 0u) && (tokenSize == predicted), name);

    (void)snprintf(name, sizeof(name),
                   "token(%u) is a tagged COSE_Sign1 (tag 18, 0xD2)",
                   (unsigned)challengeSize);
    check((tokenSize > 0u) && (token[0] == 0xD2u), name);

    ret = cose_recover(token, tokenSize, payload, sizeof(payload),
                       &payloadLen);
    (void)snprintf(name, sizeof(name),
                   "tagged token(%u) verifies with wolfCOSE (ES256)",
                   (unsigned)challengeSize);
    check(ret == 0, name);

    ret = extract_signer_id(payload, payloadLen, signerId);
    (void)snprintf(name, sizeof(name),
                   "SW component(%u) carries signer_id (label 5)",
                   (unsigned)challengeSize);
    check((ret == 0) && (memcmp(signerId, expectedSigner, 32u) == 0), name);

    ret = wt_attestation_verify(token, tokenSize, g_iak_pub, IAK_PUB_SIZE,
                                challenge, challengeSize, measHex, 0x3000u,
                                &verifiedLifecycle);
    (void)snprintf(name, sizeof(name),
                   "production guest verifier accepts token(%u)",
                   (unsigned)challengeSize);
    check((ret == 0) && (verifiedLifecycle == 0x3000u), name);

    return 0;
}

int main(void)
{
    static const uint8_t bootSeed[WT_ATTEST_BOOT_SEED_SIZE] = { 0xA5u };
    wt_boot_handoff_t handoff;
    uint8_t expectedSigner[32];
    char measHex[65];
    word32 pubLen = (word32)sizeof(g_iak_pub);
    word32 wrongLen = (word32)sizeof(g_wrong_pub);
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_64];
    uint32_t verifiedLifecycle = 0u;
    size_t tokenSize = 0u;
    static const uint8_t signerName[] = "wolfBoot";
    int ret;
    int i;

    if (wc_InitRng(&g_rng) != 0) {
        printf("FAIL: attestation_token (RNG init)\n");
        return 1;
    }
    if ((wc_ecc_init(&g_iak) != 0) || (wc_ecc_init(&g_wrong) != 0)) {
        printf("FAIL: attestation_token (ecc init)\n");
        return 1;
    }
    if ((wc_ecc_make_key(&g_rng, 32, &g_iak) != 0) ||
        (wc_ecc_make_key(&g_rng, 32, &g_wrong) != 0)) {
        printf("FAIL: attestation_token (keygen)\n");
        return 1;
    }
    if ((wc_ecc_export_x963(&g_iak, g_iak_pub, &pubLen) != 0) ||
        (wc_ecc_export_x963(&g_wrong, g_wrong_pub, &wrongLen) != 0)) {
        printf("FAIL: attestation_token (pubkey export)\n");
        return 1;
    }
    check((pubLen == IAK_PUB_SIZE) && (g_iak_pub[0] == 0x04u),
          "IAK public key is a 65-byte uncompressed P-256 point");

    /* The production encoder derives signer_id = SHA-256("wolfBoot"). */
    if (wc_Sha256Hash(signerName, (word32)(sizeof(signerName) - 1u),
                      expectedSigner) != 0) {
        printf("FAIL: attestation_token (signer hash)\n");
        return 1;
    }

    (void)memset(&handoff, 0, sizeof(handoff));
    handoff.magic = WT_BOOT_HANDOFF_MAGIC;
    handoff.version = WT_BOOT_HANDOFF_VERSION;
    handoff.lifecycle = 0x3000u;
    handoff.hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    handoff.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    for (i = 0; i < (int)WT_BOOT_HANDOFF_DIGEST_SIZE; i++) {
        handoff.measurement[i] = 0xABu;
        measHex[i * 2] = 'a';
        measHex[(i * 2) + 1] = 'b';
    }
    measHex[64] = '\0';

    ret = wt_initial_attest_init(&handoff, bootSeed);
    check(ret == WT_ATTEST_SUCCESS, "wt_initial_attest_init succeeds");

    (void)run_challenge(WT_ATTEST_CHALLENGE_SIZE_32, measHex, expectedSigner);
    (void)run_challenge(WT_ATTEST_CHALLENGE_SIZE_48, measHex, expectedSigner);
    (void)run_challenge(WT_ATTEST_CHALLENGE_SIZE_64, measHex, expectedSigner);

    /* Negatives on the tagged token: tampered signature and wrong key. */
    (void)memset(challenge, 0x2a, sizeof(challenge));
    ret = wt_initial_attest_get_token(0u, challenge, WT_ATTEST_CHALLENGE_SIZE_32,
                                      token, sizeof(token), &tokenSize);
    check(ret == WT_ATTEST_SUCCESS, "get_token for negatives succeeds");

    token[tokenSize - 1u] ^= 0x01u;
    ret = wt_attestation_verify(token, tokenSize, g_iak_pub, IAK_PUB_SIZE,
                                challenge, WT_ATTEST_CHALLENGE_SIZE_32, measHex,
                                0x3000u, &verifiedLifecycle);
    check(ret != 0, "tampered tagged token is rejected");
    token[tokenSize - 1u] ^= 0x01u;

    ret = wt_attestation_verify(token, tokenSize, g_wrong_pub, IAK_PUB_SIZE,
                                challenge, WT_ATTEST_CHALLENGE_SIZE_32, measHex,
                                0x3000u, &verifiedLifecycle);
    check(ret != 0, "tagged token fails against the wrong public key");

    wc_ecc_free(&g_iak);
    wc_ecc_free(&g_wrong);
    wc_FreeRng(&g_rng);

    printf("attestation_token host tests: %d checks, %d failures\n", g_checks,
           g_failures);
    if (g_failures == 0) {
        printf("PASS: attestation_token\n");
        return 0;
    }
    printf("FAIL: attestation_token\n");
    return 1;
}
