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
 * Prove the wolfCOSE-backed QCBOR shim parses a real COSE_Sign1 exactly the way
 * ARM's val_attestation.c does (tagged array-of-4, protected/unprotected/
 * payload/signature, then the EAT claims map), and that the encoder builds a
 * byte-exact Sig_structure. If this passes, test_a001's val/PAL reach wolfCOSE.
 */

#include "qcbor.h"
#include "wolftrust/services/attestation_cose.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfcose/wolfcose.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_checks;
static int g_failures;

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

typedef struct signer_ctx {
    ecc_key* key;
    WC_RNG*  rng;
} signer_ctx_t;

static int host_es256_sign(void* context, const uint8_t* digest,
    size_t digestSize, uint8_t* signature, size_t signatureSize,
    size_t* signatureLength)
{
    signer_ctx_t* ctx = (signer_ctx_t*)context;
    uint8_t der[80];
    uint8_t r[32];
    uint8_t s[32];
    word32 derLen = (word32)sizeof(der);
    word32 rLen = (word32)sizeof(r);
    word32 sLen = (word32)sizeof(s);
    int ret;

    if ((ctx == NULL) || (digestSize != 32u) || (signatureSize < 64u)) {
        return -1;
    }
    ret = wc_ecc_sign_hash(digest, (word32)digestSize, der, &derLen, ctx->rng,
                           ctx->key);
    if (ret == 0) {
        ret = wc_ecc_sig_to_rs(der, derLen, r, &rLen, s, &sLen);
    }
    if (ret == 0) {
        (void)memset(signature, 0, 64u);
        (void)memcpy(signature + (32u - rLen), r, rLen);
        (void)memcpy(signature + 32u + (32u - sLen), s, sLen);
        *signatureLength = 64u;
    }
    return ret == 0 ? 0 : -1;
}

/* Encode a tiny EAT-like claims map: {10: nonce, 2395: 0x3000}. */
static size_t build_payload(uint8_t* out, size_t cap, const uint8_t* nonce,
    size_t nonceLen)
{
    WOLFCOSE_CBOR_CTX c;

    (void)memset(&c, 0, sizeof(c));
    c.buf = out;
    c.bufSz = cap;
    if (wc_CBOR_EncodeMapStart(&c, 2u) != WOLFCOSE_SUCCESS) return 0;
    if (wc_CBOR_EncodeInt(&c, 10) != WOLFCOSE_SUCCESS) return 0;
    if (wc_CBOR_EncodeBstr(&c, nonce, nonceLen) != WOLFCOSE_SUCCESS) return 0;
    if (wc_CBOR_EncodeInt(&c, 2395) != WOLFCOSE_SUCCESS) return 0;
    if (wc_CBOR_EncodeUint(&c, 0x3000u) != WOLFCOSE_SUCCESS) return 0;
    return c.idx;
}

static int parse_cose_sign1(const uint8_t* token, size_t tokenLen,
    UsefulBufC* protectedOut, UsefulBufC* payloadOut, UsefulBufC* sigOut)
{
    QCBORDecodeContext dc;
    QCBORItem item;
    UsefulBufC tb;
    int tagged;

    tb.ptr = token;
    tb.len = tokenLen;

    /* Header: tagged array of 4 (COSE_Sign1). */
    QCBORDecode_Init(&dc, tb, QCBOR_DECODE_MODE_NORMAL);
    if (QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS) return -1;
    tagged = QCBORDecode_IsTagged(&dc, &item, CBOR_TAG_COSE_SIGN1);
    if ((item.uDataType != QCBOR_TYPE_ARRAY) || (item.val.uCount != 4u) ||
        (tagged == 0)) {
        return -2;
    }

    /* Protected headers (bstr). */
    if (QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS) return -3;
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) return -3;
    *protectedOut = item.val.string;

    /* Unprotected headers (map) — consume it and any entries. */
    if (QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS) return -4;
    if (item.uDataType != QCBOR_TYPE_MAP) return -4;

    /* Payload (bstr). */
    if (QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS) return -5;
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) return -5;
    *payloadOut = item.val.string;

    /* Signature (bstr). */
    if (QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS) return -6;
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) return -6;
    *sigOut = item.val.string;

    return 0;
}

int main(void)
{
    WC_RNG rng;
    ecc_key key;
    signer_ctx_t sctx;
    wt_attest_cose_signer_t signer;
    uint8_t nonce[8];
    uint8_t payload[64];
    uint8_t token[256];
    uint8_t scratch[512];
    uint8_t tbs[64];
    UsefulBufC prot;
    UsefulBufC pay;
    UsefulBufC sig;
    UsefulBufC tbsOut;
    QCBORDecodeContext dc;
    QCBORItem item;
    QCBOREncodeContext ec;
    UsefulBuf tbsBuf;
    UsefulBufC ub;
    UsefulBufC pb;
    UsefulBufC empty;
    UsefulBufC plen;
    size_t payloadLen;
    size_t tokenLen = 0u;
    int i;
    int ret;
    static const uint8_t expected_tbs[] = {
        0x84,
        0x6A, 'S','i','g','n','a','t','u','r','e','1',
        0x42, 0x01, 0x02,
        0x40,
        0x45
    };
    static const uint8_t two[] = { 0x01, 0x02 };

    if ((wc_InitRng(&rng) != 0) || (wc_ecc_init(&key) != 0) ||
        (wc_ecc_make_key(&rng, 32, &key) != 0)) {
        printf("FAIL: qcbor_shim (setup)\n");
        return 1;
    }
    for (i = 0; i < (int)sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0xA0 + i);
    }

    payloadLen = build_payload(payload, sizeof(payload), nonce, sizeof(nonce));
    check(payloadLen > 0u, "EAT claims payload encoded via wolfCOSE CBOR");

    (void)memset(&signer, 0, sizeof(signer));
    sctx.key = &key;
    sctx.rng = &rng;
    signer.sign = host_es256_sign;
    signer.context = &sctx;

    /* Tagged COSE_Sign1 (flags 0 = tagged, as ARM's val requires). */
    ret = wt_attest_cose_sign1_encode(&signer, payload, payloadLen, 0u,
        scratch, sizeof(scratch), token, sizeof(token), &tokenLen);
    check(ret == WT_ATTEST_COSE_OK, "produced a tagged COSE_Sign1 via wolfCOSE");

    /* Shim walks the COSE_Sign1 exactly like val_attestation.c. */
    (void)memset(&prot, 0, sizeof(prot));
    (void)memset(&pay, 0, sizeof(pay));
    (void)memset(&sig, 0, sizeof(sig));
    ret = parse_cose_sign1(token, tokenLen, &prot, &pay, &sig);
    check(ret == 0, "shim parses tagged array-of-4 + tag 18 (COSE_Sign1)");
    check((prot.len > 0u), "shim extracts protected headers bstr");
    check((pay.len == payloadLen) &&
          (memcmp(pay.ptr, payload, payloadLen) == 0),
          "shim extracts the exact payload bstr");
    check(sig.len == 64u, "shim extracts the 64-byte ES256 signature bstr");

    /* Shim walks the EAT claims map inside the payload. */
    ub.ptr = pay.ptr;
    ub.len = pay.len;
    QCBORDecode_Init(&dc, ub, QCBOR_DECODE_MODE_NORMAL);
    ret = QCBORDecode_GetNext(&dc, &item);
    check((ret == QCBOR_SUCCESS) && (item.uDataType == QCBOR_TYPE_MAP) &&
          (item.val.uCount == 2u), "shim opens the claims map (2 entries)");
    ret = QCBORDecode_GetNext(&dc, &item);
    check((ret == QCBOR_SUCCESS) && (item.uLabelType == QCBOR_TYPE_INT64) &&
          (item.label.int64 == 10) &&
          (item.uDataType == QCBOR_TYPE_BYTE_STRING) &&
          (item.val.string.len == sizeof(nonce)) &&
          (memcmp(item.val.string.ptr, nonce, sizeof(nonce)) == 0),
          "shim reads claim 10 (nonce) with its label and value");
    ret = QCBORDecode_GetNext(&dc, &item);
    check((ret == QCBOR_SUCCESS) && (item.uLabelType == QCBOR_TYPE_INT64) &&
          (item.label.int64 == 2395) &&
          (item.uDataType == QCBOR_TYPE_INT64) &&
          (item.val.int64 == 0x3000), "shim reads claim 2395 (lifecycle)");

    /* Encoder: byte-exact Sig_structure the PAL builds for the hash. */
    tbsBuf.ptr = tbs;
    tbsBuf.len = sizeof(tbs);
    QCBOREncode_Init(&ec, tbsBuf);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddSZString(&ec, "Signature1");
    pb.ptr = two; pb.len = sizeof(two);
    empty.ptr = NULL; empty.len = 0u;
    plen.ptr = NULL; plen.len = 5u;
    QCBOREncode_AddBytes(&ec, pb);
    QCBOREncode_AddBytes(&ec, empty);
    QCBOREncode_AddBytesLenOnly(&ec, plen);
    QCBOREncode_CloseArray(&ec);
    ret = QCBOREncode_Finish(&ec, &tbsOut);
    check((ret == QCBOR_SUCCESS) && (tbsOut.len == sizeof(expected_tbs)) &&
          (memcmp(tbsOut.ptr, expected_tbs, sizeof(expected_tbs)) == 0),
          "encoder builds a byte-exact Sig_structure (TBS)");

    wc_ecc_free(&key);
    wc_FreeRng(&rng);

    printf("qcbor_shim host tests: %d checks, %d failures\n", g_checks,
           g_failures);
    if (g_failures == 0) {
        printf("PASS: qcbor_shim\n");
        return 0;
    }
    printf("FAIL: qcbor_shim\n");
    return 1;
}
