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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/wc_port.h"

static unsigned int failures;

static void check(int success, const char* description)
{
    printf("%s: %s\n", success != 0 ? "PASS" : "FAIL", description);
    if (success == 0) {
        failures++;
    }
}

static int decode_checked(const byte* der, word32 length,
                           byte* public_key, word32* public_length)
{
    ecc_key key;
    word32 index = 0U;
    int rc = wc_ecc_init(&key);

    if (rc != 0) {
        return rc;
    }
    rc = wc_EccPrivateKeyDecode(der, &index, &key, length);
    if (rc == 0 && index != length) {
        rc = -1;
    }
    if (rc == 0) {
        rc = wc_ecc_check_key(&key);
    }
    if (rc == 0 && public_key != NULL) {
        rc = wc_ecc_export_x963(&key, public_key, public_length);
    }
    wc_ecc_free(&key);
    return rc;
}

static void test_signature(ecc_key* key)
{
    static const byte message[] = "wolfTrust ASN codec regression";
    WC_RNG rng;
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte signature[80];
    word32 signature_length = (word32)sizeof(signature);
    int verified = 0;
    int rc = wc_InitRng(&rng);

    check(rc == 0, "RNG initialization");
    if (rc != 0) {
        return;
    }
    rc = wc_Sha256Hash(message, (word32)(sizeof(message) - 1U), digest);
    if (rc == 0) {
        rc = wc_ecc_sign_hash(digest, (word32)sizeof(digest), signature,
                              &signature_length, &rng, key);
    }
    check(rc == 0, "P256 DER signature encoding");
    if (rc == 0) {
        rc = wc_ecc_verify_hash(signature, signature_length, digest,
                                (word32)sizeof(digest), &verified, key);
        check(rc == 0 && verified == 1, "P256 DER signature verification");
        signature[0] ^= 1U;
        verified = 0;
        rc = wc_ecc_verify_hash(signature, signature_length, digest,
                                (word32)sizeof(digest), &verified, key);
        check(rc != 0 || verified == 0, "invalid DER signature tag rejected");
    }
    wc_FreeRng(&rng);
}

static int exchange_fixture(const char* mode, const char* path,
                            const byte* der, word32 length,
                            const byte* public_key, word32 public_length)
{
    FILE* file;
    byte input[512];
    byte actual_public[65];
    word32 actual_length = (word32)sizeof(actual_public);
    size_t transferred;
    int rc;

    if (strcmp(mode, "--write") == 0) {
        file = fopen(path, "wb");
        if (file == NULL) {
            return -1;
        }
        transferred = fwrite(der, 1U, length, file);
        rc = fclose(file);
        return transferred == length && rc == 0 ? 0 : -1;
    }
    if (strcmp(mode, "--read") != 0) {
        return -1;
    }
    file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }
    transferred = fread(input, 1U, sizeof(input), file);
    rc = fclose(file);
    if (transferred == 0U || transferred >= sizeof(input) || rc != 0) {
        return -1;
    }
    rc = decode_checked(input, (word32)transferred, actual_public,
                         &actual_length);
    return rc == 0 && actual_length == public_length &&
        memcmp(actual_public, public_key, public_length) == 0 ? 0 : -1;
}

int main(int argc, char** argv)
{
    ecc_key key;
    byte scalar[32] = { 0U };
    byte der[512];
    byte malformed[512];
    byte public_key[65];
    byte decoded_public[65];
    word32 public_length = (word32)sizeof(public_key);
    word32 decoded_length = (word32)sizeof(decoded_public);
    word32 i;
    int all_truncated_rejected = 1;
    int length;
    int rc;

    printf("WT-FFM-0059: original/template ECC ASN validation\n");
    if (argc != 3 || wolfCrypt_Init() != 0) {
        return 2;
    }
    rc = wc_ecc_init(&key);
    if (rc != 0) {
        return 1;
    }
    /* Scalar one is a public test fixture, shared by the two codec builds. */
    scalar[sizeof(scalar) - 1U] = 1U;
    rc = wc_ecc_import_private_key_ex(scalar, (word32)sizeof(scalar), NULL,
                                      0U, &key, ECC_SECP256R1);
    if (rc == 0) {
        rc = wc_ecc_make_pub(&key, NULL);
    }
    if (rc == 0) {
        rc = wc_ecc_export_x963(&key, public_key, &public_length);
    }
    check(rc == 0, "P256 private/public fixture setup");
    length = rc == 0 ? wc_EccKeyToDer(&key, der, (word32)sizeof(der)) : -1;
    check(length > 0, "private key DER encoding");
    if (length <= 0) {
        wc_ecc_free(&key);
        (void)wolfCrypt_Cleanup();
        return 1;
    }
    rc = decode_checked(der, (word32)length, decoded_public, &decoded_length);
    check(rc == 0 && decoded_length == public_length &&
        memcmp(decoded_public, public_key, public_length) == 0,
        "private key DER round trip preserves the public point");
    for (i = 0U; i < (word32)length; i++) {
        if (decode_checked(der, i, NULL, NULL) == 0) {
            all_truncated_rejected = 0;
        }
    }
    check(all_truncated_rejected, "every truncated private key rejected");
    (void)memcpy(malformed, der, (size_t)length);
    malformed[0] = 0x31U;
    check(decode_checked(malformed, (word32)length, NULL, NULL) != 0,
          "invalid private key sequence tag rejected");
    (void)memcpy(malformed, der, (size_t)length);
    malformed[1] = 0x84U;
    malformed[2] = 0x7fU;
    malformed[3] = 0xffU;
    malformed[4] = 0xffU;
    malformed[5] = 0xffU;
    check(decode_checked(malformed, (word32)length, NULL, NULL) != 0,
          "oversized ASN length rejected");
    test_signature(&key);
    check(exchange_fixture(argv[1], argv[2], der, (word32)length,
                            public_key, public_length) == 0,
          "cross-codec private key fixture exchange");
    wc_ecc_free(&key);
    (void)wolfCrypt_Cleanup();
    return failures == 0U ? 0 : 1;
}
