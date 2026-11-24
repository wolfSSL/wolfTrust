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

/* HMAC attestation key (WT_ATTEST_KEY=hmac): drive the production token
 * encoder with the tiny profile's wolfCOSE configuration and check each
 * COSE_Mac0 with an HMAC computed here, first proven on the RFC 9783 example. */

#include "wolftrust/services/initial_attestation.h"

#include "mac0_check.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* RFC 9783 Appendix A.2: the COSE_Mac0 token and its 64-byte HS256 key. */
static const char g_rfc_token_hex[] =
    "d18443a10105a0590100a8190100582101c557bd4fadc83f756fca2cd5ea2dcc"
    "8b82159bb4e7453d6a744d4eecd6d0ac6019095c582000000000000000000000"
    "000000000000000000000000000000000000000000000a582001010101010101"
    "0101010101010101010101010101010101010101010101010119095a1a7fffff"
    "ff19095b19300019010978217461673a7073616365727469666965642e6f7267"
    "2c323032333a7073612374666d19010c48000000000000000019095f81a30558"
    "2004040404040404040404040404040404040404040404040404040404040404"
    "0402582003030303030303030303030303030303030303030303030303030303"
    "03030303016450526f545820cf88d330e7a5366a95cf744a4dbf0d50304d405e"
    "dd8b2530e243eddbd3177820";
static const char g_rfc_key_hex[] =
    "de038b34aca125768c5e3357ab8d06b367b9ab0d7e8be124edca47fe033a5bb7"
    "a93d307ff229aa36ff246c1295964facf71ab7aa6ec4fd6102b7b3983255ad92";

static int g_checks;
static int g_failures;
static uint8_t g_key[WT_ATTEST_HMAC_KEY_SIZE];
static int g_key_fail;
static int g_key_calls;

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

/* The port hook the Secure image calls for the device key. */
int wt_port_attest_hmac_key(uint8_t* key, size_t keySize)
{
    g_key_calls++;
    if ((g_key_fail != 0) || (key == NULL) || (keySize != sizeof(g_key))) {
        return -1;
    }
    (void)memcpy(key, g_key, sizeof(g_key));
    return 0;
}

static size_t unhex(const char* hex, uint8_t* out, size_t cap)
{
    size_t n = 0u;
    unsigned int byte;

    while ((hex[0] != '\0') && (hex[1] != '\0') && (n < cap)) {
        if (sscanf(hex, "%2x", &byte) != 1) {
            return 0u;
        }
        out[n++] = (uint8_t)byte;
        hex += 2;
    }
    return (hex[0] == '\0') ? n : 0u;
}

static void test_rfc_vector(void)
{
    uint8_t token[320];
    uint8_t key[64];
    uint8_t ueid[UEID_SIZE];
    const uint8_t* payload = NULL;
    const uint8_t* tag = NULL;
    size_t payloadSize = 0u;
    size_t tokenSize = unhex(g_rfc_token_hex, token, sizeof(token));
    size_t keySize = unhex(g_rfc_key_hex, key, sizeof(key));

    check((tokenSize == 300u) && (keySize == 64u),
          "RFC 9783 A.2 token and key decode");
    check(mac0_verify(key, keySize, token, tokenSize) == 0,
          "RFC 9783 A.2 token verifies with its key");
    check((mac0_split(token, tokenSize, &payload, &payloadSize, &tag) == 0) &&
          (instance_id(key, keySize, ueid) == 0) &&
          (contains(payload, payloadSize, ueid, sizeof(ueid)) != 0),
          "RFC 9783 A.2 Instance ID is 0x01 || SHA-256(SHA-256(key))");
    key[0] ^= 0x01u;
    check(mac0_verify(key, keySize, token, tokenSize) == 1,
          "RFC 9783 A.2 token fails under another key");
    key[0] ^= 0x01u;
    token[40] ^= 0x01u;
    check(mac0_verify(key, keySize, token, tokenSize) == 1,
          "RFC 9783 A.2 token fails with a changed payload");
}

static void run_challenge(size_t challengeSize, const uint8_t* otherKey)
{
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_64];
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t nonce[3u + WT_ATTEST_CHALLENGE_SIZE_64];
    uint8_t ueidClaim[5u + UEID_SIZE] = { 0x19, 0x01, 0x00, 0x58, 0x21 };
    uint8_t keyHash[WC_SHA256_DIGEST_SIZE];
    const uint8_t* payload = NULL;
    const uint8_t* tag = NULL;
    size_t payloadSize = 0u;
    size_t predicted = 0u;
    size_t tokenSize = 0u;
    char name[96];
    int ret;

    (void)memset(challenge, 0x2a, sizeof(challenge));
    (void)memset(token, 0, sizeof(token));

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
                   "token(%u) size matches get_token_size",
                   (unsigned)challengeSize);
    check((tokenSize > 0u) && (tokenSize == predicted), name);

    (void)snprintf(name, sizeof(name),
                   "token(%u) is a tagged COSE_Mac0 with HMAC 256/256",
                   (unsigned)challengeSize);
    check(mac0_split(token, tokenSize, &payload, &payloadSize, &tag) == 0,
          name);

    (void)snprintf(name, sizeof(name), "token(%u) verifies with the device key",
                   (unsigned)challengeSize);
    check(mac0_verify(g_key, sizeof(g_key), token, tokenSize) == 0, name);

    (void)snprintf(name, sizeof(name), "token(%u) fails under another key",
                   (unsigned)challengeSize);
    check(mac0_verify(otherKey, sizeof(g_key), token, tokenSize) == 1, name);

    if (payload != NULL) {
        (void)snprintf(name, sizeof(name),
                       "token(%u) carries the Instance ID of the key",
                       (unsigned)challengeSize);
        check((instance_id(g_key, sizeof(g_key), &ueidClaim[5]) == 0) &&
              (contains(payload, payloadSize, ueidClaim,
                        sizeof(ueidClaim)) != 0), name);

        nonce[0] = 0x0a;
        nonce[1] = 0x58;
        nonce[2] = (uint8_t)challengeSize;
        (void)memcpy(&nonce[3], challenge, challengeSize);
        (void)snprintf(name, sizeof(name),
                       "token(%u) carries the challenge as its nonce",
                       (unsigned)challengeSize);
        check(contains(payload, payloadSize, nonce, 3u + challengeSize) != 0,
              name);
    }

    (void)snprintf(name, sizeof(name),
                   "token(%u) holds neither the key nor its plain hash",
                   (unsigned)challengeSize);
    check((wc_Sha256Hash(g_key, (word32)sizeof(g_key), keyHash) == 0) &&
          (contains(token, tokenSize, g_key, sizeof(g_key)) == 0) &&
          (contains(token, tokenSize, keyHash, sizeof(keyHash)) == 0), name);

    token[tokenSize / 2u] ^= 0x01u;
    (void)snprintf(name, sizeof(name), "token(%u) fails once a byte changes",
                   (unsigned)challengeSize);
    check(mac0_verify(g_key, sizeof(g_key), token, tokenSize) != 0, name);
}

int main(void)
{
    static const size_t sizes[] = { WT_ATTEST_CHALLENGE_SIZE_32,
                                    WT_ATTEST_CHALLENGE_SIZE_48,
                                    WT_ATTEST_CHALLENGE_SIZE_64 };
    wt_boot_handoff_t handoff;
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_32];
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t firstKey[WT_ATTEST_HMAC_KEY_SIZE];
    size_t tokenSize = 7u;
    size_t i;
    int ret;

    test_rfc_vector();

    (void)memset(&handoff, 0, sizeof(handoff));
    handoff.magic = WT_BOOT_HANDOFF_MAGIC;
    handoff.version = WT_BOOT_HANDOFF_VERSION;
    handoff.lifecycle = 0x3000u;
    handoff.hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    handoff.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    (void)memset(handoff.measurement, 0xAB, WT_BOOT_HANDOFF_DIGEST_SIZE);
    (void)memset(challenge, 0x2a, sizeof(challenge));

    /* No key: the handoff is refused and every request fails closed. */
    g_key_fail = 1;
    ret = wt_initial_attest_init(&handoff);
    check((ret == WT_ATTEST_ERROR_CRYPTO) && (g_key_calls == 1),
          "init fails when the port has no key");
    ret = wt_initial_attest_get_token(0u, challenge, sizeof(challenge), token,
                                      sizeof(token), &tokenSize);
    check((ret == WT_ATTEST_ERROR_NOT_READY) && (tokenSize == 0u),
          "get_token is not ready without a key");
    ret = wt_initial_attest_get_token_size(sizeof(challenge), &tokenSize);
    check((ret == WT_ATTEST_ERROR_NOT_READY) && (tokenSize == 0u),
          "get_token_size is not ready without a key");

    g_key_fail = 0;
    for (i = 0u; i < sizeof(g_key); i++) {
        g_key[i] = (uint8_t)(0x10u + i);
        firstKey[i] = g_key[i];
    }
    ret = wt_initial_attest_init(&handoff);
    check((ret == WT_ATTEST_SUCCESS) && (g_key_calls == 2),
          "init loads the key through the port hook");
    (void)memset(token, 0x5a, sizeof(token));
    for (i = 0u; i < (sizeof(sizes) / sizeof(sizes[0])); i++) {
        run_challenge(sizes[i], token);
    }

    /* A later init takes the port's current key, and a failed one drops it. */
    (void)memset(g_key, 0xC3, sizeof(g_key));
    ret = wt_initial_attest_init(&handoff);
    check(ret == WT_ATTEST_SUCCESS, "a second init reloads the key");
    run_challenge(WT_ATTEST_CHALLENGE_SIZE_32, firstKey);
    g_key_fail = 1;
    ret = wt_initial_attest_init(&handoff);
    tokenSize = 7u;
    check((ret == WT_ATTEST_ERROR_CRYPTO) &&
          (wt_initial_attest_get_token(0u, challenge, sizeof(challenge), token,
               sizeof(token), &tokenSize) == WT_ATTEST_ERROR_NOT_READY) &&
          (tokenSize == 0u), "a failed init leaves no usable key");

    printf("attestation HMAC tests: %d checks, %d failures\n", g_checks,
           g_failures);
    if (g_failures != 0) {
        printf("FAIL: attestation_hmac\n");
        return 1;
    }
    printf("PASS: attestation_hmac\n");
    return 0;
}
