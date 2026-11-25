/* mac0_check.h
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

/* An HMAC-SHA256 COSE_Mac0 check that shares no code with the encoder under
 * test, for the host suites that issue HMAC attestation tokens. */

#ifndef WT_TEST_MAC0_CHECK_H
#define WT_TEST_MAC0_CHECK_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <stdint.h>
#include <string.h>

#define MAC0_TAG_SIZE 32u
#define UEID_SIZE 33u

static size_t bstr_head(size_t len, uint8_t* head)
{
    size_t n;

    if (len < 24u) {
        head[0] = (uint8_t)(0x40u + len);
        n = 1u;
    }
    else if (len < 256u) {
        head[0] = 0x58u;
        head[1] = (uint8_t)len;
        n = 2u;
    }
    else {
        head[0] = 0x59u;
        head[1] = (uint8_t)(len >> 8);
        head[2] = (uint8_t)len;
        n = 3u;
    }
    return n;
}

/* Split a tagged COSE_Mac0 whose protected header is {1: 5} (HMAC 256/256)
 * and whose unprotected map is empty into its payload and tag. */
static int mac0_split(const uint8_t* token, size_t tokenSize,
    const uint8_t** payload, size_t* payloadSize, const uint8_t** tag)
{
    static const uint8_t head[] = { 0xD1, 0x84, 0x43, 0xA1, 0x01, 0x05, 0xA0 };
    size_t off = sizeof(head);
    size_t len;

    if ((tokenSize < (sizeof(head) + 3u)) ||
        (memcmp(token, head, sizeof(head)) != 0)) {
        return -1;
    }
    if ((token[off] >= 0x40u) && (token[off] <= 0x57u)) {
        len = (size_t)token[off] - 0x40u;
        off += 1u;
    }
    else if (token[off] == 0x58u) {
        len = token[off + 1u];
        off += 2u;
    }
    else if (token[off] == 0x59u) {
        len = ((size_t)token[off + 1u] << 8) | token[off + 2u];
        off += 3u;
    }
    else {
        return -1;
    }
    if ((tokenSize != (off + len + 2u + MAC0_TAG_SIZE)) ||
        (token[off + len] != 0x58u) || (token[off + len + 1u] != 0x20u)) {
        return -1;
    }
    *payload = token + off;
    *payloadSize = len;
    *tag = token + off + len + 2u;
    return 0;
}

/* 0 when the tag is HMAC-SHA256 over MAC_structure
 * ["MAC0", h'A10105', h'', payload]; 1 when it is not. */
static int mac0_verify(const uint8_t* key, size_t keySize,
    const uint8_t* token, size_t tokenSize)
{
    static const uint8_t context[] = { 0x84, 0x64, 'M', 'A', 'C', '0',
                                       0x43, 0xA1, 0x01, 0x05, 0x40 };
    const uint8_t* payload = NULL;
    const uint8_t* tag = NULL;
    uint8_t head[3];
    uint8_t mac[MAC0_TAG_SIZE];
    size_t payloadSize = 0u;
    size_t headSize;
    Hmac hmac;
    int ret;

    if (mac0_split(token, tokenSize, &payload, &payloadSize, &tag) != 0) {
        return -1;
    }
    headSize = bstr_head(payloadSize, head);
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return -1;
    }
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)keySize);
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, context, (word32)sizeof(context));
    }
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, head, (word32)headSize);
    }
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, payload, (word32)payloadSize);
    }
    if (ret == 0) {
        ret = wc_HmacFinal(&hmac, mac);
    }
    wc_HmacFree(&hmac);
    if (ret != 0) {
        return -1;
    }
    return (memcmp(mac, tag, sizeof(mac)) == 0) ? 0 : 1;
}

static int contains(const uint8_t* hay, size_t haySize, const uint8_t* needle,
    size_t needleSize)
{
    size_t i;

    for (i = 0u; (i + needleSize) <= haySize; i++) {
        if (memcmp(hay + i, needle, needleSize) == 0) {
            return 1;
        }
    }
    return 0;
}

/* The Instance ID of an HMAC key: 0x01 || SHA-256(SHA-256(key)). */
static int instance_id(const uint8_t* key, size_t keySize, uint8_t* ueid)
{
    uint8_t first[WC_SHA256_DIGEST_SIZE];
    int ret;

    ueid[0] = 0x01u;
    ret = wc_Sha256Hash(key, (word32)keySize, first);
    if (ret == 0) {
        ret = wc_Sha256Hash(first, (word32)sizeof(first), &ueid[1]);
    }
    return ret;
}

#endif /* WT_TEST_MAC0_CHECK_H */
