/* attestation_verify.c
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

#include "attestation_verify.h"

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <string.h>

#define WT_EAT_CLAIM_NONCE 10
#define WT_EAT_CLAIM_UEID 256
#define WT_EAT_CLAIM_PROFILE 265
#define WT_EAT_CLAIM_BOOT_SEED 268
#define WT_PSA_CLAIM_CLIENT_ID 2394
#define WT_PSA_CLAIM_LIFECYCLE 2395
#define WT_PSA_CLAIM_IMPLEMENTATION_ID 2396
#define WT_PSA_CLAIM_SW_COMPONENTS 2399
#define WT_PSA_SW_MEASUREMENT_TYPE 1
#define WT_PSA_SW_MEASUREMENT_VALUE 2
/* NSPE guest N attests as PSA client id -(N + 1); guest0 unless told otherwise. */
#ifndef WT_ATTEST_EXPECTED_CLIENT_ID
#define WT_ATTEST_EXPECTED_CLIENT_ID (-1)
#endif
#define WT_PSA_SW_MEASUREMENT_SIGNER_ID 5
#define WT_PSA_SW_MEASUREMENT_DESCRIPTION 6
#define WT_REQUIRED_CLAIMS 0xFFu
static const char g_expected_profile[] = "tag:psacertified.org,2023:psa#tfm";

static int wt_hex_nibble(char value)
{
    if ((value >= '0') && (value <= '9')) {
        return value - '0';
    }
    if ((value >= 'a') && (value <= 'f')) {
        return value - 'a' + 10;
    }
    if ((value >= 'A') && (value <= 'F')) {
        return value - 'A' + 10;
    }
    return -1;
}

static int wt_decode_measurement(const char* hex, uint8_t* measurement)
{
    size_t i;
    int high;
    int low;

    if ((hex == NULL) || (measurement == NULL) || (strlen(hex) != 64u)) {
        return -1;
    }
    for (i = 0u; i < 32u; ++i) {
        high = wt_hex_nibble(hex[i * 2u]);
        low = wt_hex_nibble(hex[(i * 2u) + 1u]);
        if ((high < 0) || (low < 0)) {
            return -1;
        }
        measurement[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

/* Component zero is the wolfTrust runtime and is verified strictly; later
 * components are the launch-verified guest measurements (WT-FFM-0049) and
 * must be well-formed measurement/signer pairs. When expectedMeasurement is
 * NULL the component-zero digest is reported, not compared, so the harness
 * can hold the reference value outside the image under test. */
static int wt_verify_software_component(WOLFCOSE_CBOR_CTX* cbor,
    const uint8_t* expectedMeasurement, uint8_t* tokenMeasurement)
{
    static const uint8_t type[] = "sha-256";
    static const uint8_t description[] = "wolftrust";
    const uint8_t* data;
    size_t dataSize;
    size_t arrayCount;
    size_t mapCount;
    size_t component;
    size_t i;
    int64_t label;
    uint32_t fields;
    int ret;

    ret = wc_CBOR_DecodeArrayStart(cbor, &arrayCount);
    if ((ret != 0) || (arrayCount < 1u)) {
        return -1;
    }
    for (component = 0u; (ret == 0) && (component < arrayCount);
         ++component) {
        fields = 0u;
        ret = wc_CBOR_DecodeMapStart(cbor, &mapCount);
        for (i = 0u; (ret == 0) && (i < mapCount); ++i) {
            ret = wc_CBOR_DecodeInt(cbor, &label);
            if ((ret == 0) && (component != 0u)) {
                if (label == WT_PSA_SW_MEASUREMENT_VALUE) {
                    ret = wc_CBOR_DecodeBstr(cbor, &data, &dataSize);
                    if ((ret == 0) && (dataSize == 32u)) {
                        fields |= 2u;
                    }
                    else {
                        ret = -1;
                    }
                }
                else if (label == WT_PSA_SW_MEASUREMENT_SIGNER_ID) {
                    ret = wc_CBOR_DecodeBstr(cbor, &data, &dataSize);
                    if ((ret == 0) && (dataSize == 32u)) {
                        fields |= 8u;
                    }
                    else {
                        ret = -1;
                    }
                }
                else {
                    ret = wc_CBOR_Skip(cbor);
                }
                continue;
            }
            if ((ret == 0) && (label == WT_PSA_SW_MEASUREMENT_TYPE)) {
                ret = wc_CBOR_DecodeTstr(cbor, &data, &dataSize);
                if ((ret == 0) && (dataSize == sizeof(type) - 1u) &&
                    (memcmp(data, type, dataSize) == 0)) {
                    fields |= 1u;
                }
                else {
                    ret = -1;
                }
            }
            else if ((ret == 0) && (label == WT_PSA_SW_MEASUREMENT_VALUE)) {
                ret = wc_CBOR_DecodeBstr(cbor, &data, &dataSize);
                if ((ret == 0) && (dataSize == 32u) &&
                    ((expectedMeasurement == NULL) ||
                     (memcmp(data, expectedMeasurement, dataSize) == 0))) {
                    if (tokenMeasurement != NULL) {
                        (void)memcpy(tokenMeasurement, data, dataSize);
                    }
                    fields |= 2u;
                }
                else {
                    ret = -1;
                }
            }
            else if ((ret == 0) &&
                     (label == WT_PSA_SW_MEASUREMENT_DESCRIPTION)) {
                ret = wc_CBOR_DecodeTstr(cbor, &data, &dataSize);
                if ((ret == 0) && (dataSize == sizeof(description) - 1u) &&
                    (memcmp(data, description, dataSize) == 0)) {
                    fields |= 4u;
                }
                else {
                    ret = -1;
                }
            }
            else if ((ret == 0) &&
                     (label == WT_PSA_SW_MEASUREMENT_SIGNER_ID)) {
                ret = wc_CBOR_DecodeBstr(cbor, &data, &dataSize);
                if ((ret == 0) && (dataSize == 32u)) {
                    fields |= 8u;
                }
                else {
                    ret = -1;
                }
            }
            else if (ret == 0) {
                ret = wc_CBOR_Skip(cbor);
            }
        }
        /* RFC 9783 4.4.1.4: every software component carries a Signer ID;
         * a token missing one must fail verification (WT-FFM-0064). */
        if (ret == 0) {
            if (component == 0u) {
                ret = (fields == 15u) ? 0 : -1;
            }
            else {
                ret = ((fields & 10u) == 10u) ? 0 : -1;
            }
        }
    }
    return (ret == 0) ? 0 : -1;
}

static int wt_verify_claims(const uint8_t* payload, size_t payloadSize,
    const uint8_t* challenge, size_t challengeSize,
    const uint8_t* expectedMeasurement, uint32_t expectedLifecycle,
    uint32_t* verifiedLifecycle, uint8_t* tokenMeasurement)
{
    WOLFCOSE_CBOR_CTX cbor;
    const uint8_t* data;
    size_t dataSize;
    size_t mapCount;
    size_t i;
    int64_t label;
    int64_t signedValue;
    uint64_t value;
    uint32_t claims = 0u;
    int ret;

    (void)memset(&cbor, 0, sizeof(cbor));
    cbor.cbuf = payload;
    cbor.bufSz = payloadSize;
    ret = wc_CBOR_DecodeMapStart(&cbor, &mapCount);
    for (i = 0u; (ret == 0) && (i < mapCount); ++i) {
        ret = wc_CBOR_DecodeInt(&cbor, &label);
        if ((ret == 0) && (label == WT_EAT_CLAIM_NONCE)) {
            ret = wc_CBOR_DecodeBstr(&cbor, &data, &dataSize);
            if ((ret == 0) && (dataSize == challengeSize) &&
                (memcmp(data, challenge, challengeSize) == 0)) {
                claims |= 1u;
            }
            else {
                ret = -1;
            }
        }
        else if ((ret == 0) && (label == WT_EAT_CLAIM_UEID)) {
            ret = wc_CBOR_DecodeBstr(&cbor, &data, &dataSize);
            if ((ret == 0) && (dataSize == 33u) && (data[0] == 0x01u)) {
                claims |= 2u;
            }
            else {
                ret = -1;
            }
        }
        else if ((ret == 0) && (label == WT_EAT_CLAIM_PROFILE)) {
            ret = wc_CBOR_DecodeTstr(&cbor, &data, &dataSize);
            if ((ret == 0) && (dataSize == sizeof(g_expected_profile) - 1u) &&
                (memcmp(data, g_expected_profile, dataSize) == 0)) {
                claims |= 64u;
            }
            else {
                ret = -1;
            }
        }
        else if ((ret == 0) && (label == WT_EAT_CLAIM_BOOT_SEED)) {
            ret = wc_CBOR_DecodeBstr(&cbor, &data, &dataSize);
            if ((ret == 0) && (dataSize == 32u)) {
                claims |= 128u;
            }
            else {
                ret = -1;
            }
        }
        else if ((ret == 0) && (label == WT_PSA_CLAIM_CLIENT_ID)) {
            ret = wc_CBOR_DecodeInt(&cbor, &signedValue);
            /* Any nonnegative id in the claim is a spoofed secure caller. */
            if ((ret == 0) && (signedValue == WT_ATTEST_EXPECTED_CLIENT_ID)) {
                claims |= 4u;
            }
            else {
                ret = -1;
            }
        }
        else if ((ret == 0) &&
                 (label == WT_PSA_CLAIM_IMPLEMENTATION_ID)) {
            ret = wc_CBOR_DecodeBstr(&cbor, &data, &dataSize);
            if ((ret == 0) && (dataSize == 32u)) {
                claims |= 8u;
            }
            else {
                ret = -1;
            }
        }
        else if ((ret == 0) && (label == WT_PSA_CLAIM_LIFECYCLE)) {
            ret = wc_CBOR_DecodeUint(&cbor, &value);
            if ((ret == 0) && (value <= UINT32_MAX)) {
                *verifiedLifecycle = (uint32_t)value;
            }
            if ((ret == 0) && (value == expectedLifecycle)) {
                claims |= 16u;
            }
            else {
                ret = -1;
            }
        }
        else if ((ret == 0) && (label == WT_PSA_CLAIM_SW_COMPONENTS)) {
            ret = wt_verify_software_component(&cbor, expectedMeasurement,
                                               tokenMeasurement);
            if (ret == 0) {
                claims |= 32u;
            }
        }
        else if (ret == 0) {
            ret = wc_CBOR_Skip(&cbor);
        }
    }
    if ((ret == 0) && (cbor.idx != payloadSize)) {
        ret = -1;
    }
    return ((ret == 0) && (claims == WT_REQUIRED_CLAIMS)) ? 0 : -1;
}

int wt_attestation_verify_ex(const uint8_t* token, size_t tokenSize,
    const uint8_t* publicKey, size_t publicKeySize,
    const uint8_t* challenge, size_t challengeSize,
    const char* expectedMeasurementHex, uint32_t expectedLifecycle,
    uint32_t* verifiedLifecycle, uint8_t* tokenMeasurement)
{
    uint8_t expectedMeasurement[32];
    const uint8_t* expected = NULL;
    uint8_t scratch[640];
    const uint8_t* payload = NULL;
    size_t payloadSize = 0u;
    WOLFCOSE_HDR header;
    WOLFCOSE_KEY coseKey;
    ecc_key eccKey;
    int coseKeyInited = 0;
    int eccKeyInited = 0;
    int ret;

    if ((token == NULL) || (publicKey == NULL) || (publicKeySize != 65u) ||
        (publicKey[0] != 0x04u) || (challenge == NULL) ||
        (verifiedLifecycle == NULL)) {
        return -1;
    }
    *verifiedLifecycle = 0u;
    /* An absent expected measurement selects report-only mode: the token
     * digest is returned for the caller (harness) to compare against a
     * reference held outside the image under test. */
    if ((expectedMeasurementHex != NULL) &&
        (expectedMeasurementHex[0] != '\0')) {
        ret = wt_decode_measurement(expectedMeasurementHex,
                                    expectedMeasurement);
        if (ret != 0) {
            return ret;
        }
        expected = expectedMeasurement;
    }

    ret = wc_ecc_init(&eccKey);
    if (ret == 0) {
        eccKeyInited = 1;
        ret = wc_ecc_import_unsigned(&eccKey, &publicKey[1], &publicKey[33],
                                     NULL, ECC_SECP256R1);
    }
    if (ret == 0) {
        ret = wc_CoseKey_Init(&coseKey);
        if (ret == 0) {
            coseKeyInited = 1;
            ret = wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &eccKey);
        }
    }
    if (ret == 0) {
        (void)memset(&header, 0, sizeof(header));
        ret = wc_CoseSign1_Verify(&coseKey, token, tokenSize, NULL, 0u,
            NULL, 0u, scratch, sizeof(scratch), &header, &payload,
            &payloadSize);
    }
    if ((ret == 0) && (header.alg != WOLFCOSE_ALG_ES256)) {
        ret = -1;
    }
    if (ret == 0) {
        ret = wt_verify_claims(payload, payloadSize, challenge, challengeSize,
                               expected, expectedLifecycle,
                               verifiedLifecycle, tokenMeasurement);
    }

    if (coseKeyInited != 0) {
        wc_CoseKey_Free(&coseKey);
    }
    if (eccKeyInited != 0) {
        wc_ecc_free(&eccKey);
    }
    (void)memset(expectedMeasurement, 0, sizeof(expectedMeasurement));
    (void)memset(scratch, 0, sizeof(scratch));
    return ret;
}

int wt_attestation_verify(const uint8_t* token, size_t tokenSize,
    const uint8_t* publicKey, size_t publicKeySize,
    const uint8_t* challenge, size_t challengeSize,
    const char* expectedMeasurementHex, uint32_t expectedLifecycle,
    uint32_t* verifiedLifecycle)
{
    return wt_attestation_verify_ex(token, tokenSize, publicKey,
        publicKeySize, challenge, challengeSize, expectedMeasurementHex,
        expectedLifecycle, verifiedLifecycle, NULL);
}
