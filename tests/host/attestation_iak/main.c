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
 * P5-S4 IAK key-isolation, the attestation beat-TF-M proof. TF-M holds the
 * attestation key in the Crypto partition's own RAM; wolfTrust holds it in
 * the wolfHSM vault and only ever hands out signatures. This suite
 * provisions the IAK exactly as production wt_hsm_attest_generate_key does —
 * same wolfHSM server configuration, same keygen message, same
 * SENSITIVE|NONEXPORTABLE|LOCAL|NONMODIFIABLE|NONDESTROYABLE|USAGE_SIGN
 * flags, same commit under the WH_CLIENT_ID_MAX attest identity — against a
 * ramsim-backed NVM, then proves at the real wolfHSM enforcement layers:
 *
 *   I1  the IAK signs, and only its 65-byte public point is exportable
 *   I2  a raw WH_KEY_EXPORT of the IAK is refused (NONEXPORTABLE)
 *   I3  the Checked NVM face cannot read the IAK object (NONEXPORTABLE)
 *   I4  the IAK cannot be destroyed or overwritten (NONDESTROYABLE,
 *       NONMODIFIABLE)
 *   I5  any other authenticated client identity resolves a different key
 *       namespace: the same sign/export messages fail — the IAK does not
 *       exist outside the attest identity
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/signature.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_transport_mem.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WT_HSM_ATTEST_KEY_ID 0xF0u
#define WT_GUEST_CLIENT_ID   1u
#define RAMSIM_SIZE   (64u * 1024u)
#define RAMSIM_SECTOR (4u * 1024u)
#define RAMSIM_PAGE   WOLFHSM_CFG_FLASH_UNIT_SIZE

typedef union {
    uint64_t align;
    uint8_t bytes[WOLFHSM_CFG_COMM_DATA_LEN];
} packet_t;

static int g_checks;
static int g_failures;

static uint8_t g_flash_memory[RAMSIM_SIZE];
static whNvmContext g_nvm_ctx;
static whNvmConfig g_nvm_cfg;
static whNvmCb g_nvm_cb[1] = {WH_NVM_FLASH_CB};
static whNvmFlashContext g_nvm_flash_ctx;
static whNvmFlashConfig g_nvm_flash_cfg;
static whServerContext g_server;
static whServerConfig g_server_cfg;
static whServerCryptoContext g_crypto;
static whCommServerConfig g_comm_cfg;
static whTransportMemConfig g_tm_cfg;
static whTransportMemServerContext g_tm_ctx;
static whTransportServerCb g_tm_cb[1] = {WH_TRANSPORT_MEM_SERVER_CB};
static uint8_t g_req_buf[WOLFHSM_CFG_COMM_DATA_LEN];
static uint8_t g_resp_buf[WOLFHSM_CFG_COMM_DATA_LEN];

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

/* Provision the IAK exactly as wt_hsm_attest_generate_key does: production
 * keygen message, production flags, production commit id. */
static int iak_generate(void)
{
    packet_t request;
    packet_t response;
    whMessageCrypto_GenericRequestHeader* header;
    whMessageCrypto_GenericResponseHeader* rheader;
    whMessageCrypto_EccKeyGenRequest* keygen;
    whMessageCrypto_EccKeyGenResponse* result;
    static const uint8_t label[] = "wolfTrust IAK";
    whKeyId serverKeyId;
    uint16_t requestSize;
    uint16_t responseSize = 0u;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    header = (whMessageCrypto_GenericRequestHeader*)request.bytes;
    keygen = (whMessageCrypto_EccKeyGenRequest*)(header + 1);
    header->algoType = WC_PK_TYPE_EC_KEYGEN;
    header->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    header->affinity = WH_CRYPTO_AFFINITY_SW;
    keygen->sz = 32u;
    keygen->curveId = ECC_SECP256R1;
    keygen->keyId = WT_HSM_ATTEST_KEY_ID;
    keygen->flags = WH_NVM_FLAGS_SENSITIVE |
        WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_LOCAL |
        WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE |
        WH_NVM_FLAGS_USAGE_SIGN;
    (void)memcpy(keygen->label, label, sizeof(label) - 1u);
    requestSize = (uint16_t)(sizeof(*header) + sizeof(*keygen));

    ret = wh_Server_HandleCryptoRequest(&g_server, WH_COMM_MAGIC_NATIVE,
        WC_ALGO_TYPE_PK, 0u, requestSize, request.bytes, &responseSize,
        response.bytes);
    rheader = (whMessageCrypto_GenericResponseHeader*)response.bytes;
    if ((ret == WH_ERROR_OK) && (rheader->rc != WH_ERROR_OK)) {
        ret = (int)rheader->rc;
    }
    if (ret == WH_ERROR_OK) {
        result = (whMessageCrypto_EccKeyGenResponse*)(rheader + 1);
        if (result->keyId != WT_HSM_ATTEST_KEY_ID) {
            ret = WH_ERROR_ABORTED;
        }
    }
    if (ret == WH_ERROR_OK) {
        serverKeyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_CLIENT_ID_MAX,
                                    WT_HSM_ATTEST_KEY_ID);
        ret = wh_Server_KeystoreCommitKey(&g_server, serverKeyId);
    }
    return ret;
}

/* Sign a digest through the production ECDSA message; raw 64-byte r||s. */
static int iak_sign(const uint8_t* digest, uint8_t* signature)
{
    packet_t request;
    packet_t response;
    whMessageCrypto_GenericRequestHeader* header;
    whMessageCrypto_GenericResponseHeader* rheader;
    whMessageCrypto_EccSignRequest* sign;
    whMessageCrypto_EccSignResponse* result;
    const uint8_t* der;
    uint8_t r[32];
    uint8_t s[32];
    word32 rSize = (word32)sizeof(r);
    word32 sSize = (word32)sizeof(s);
    uint16_t requestSize;
    uint16_t responseSize = 0u;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    header = (whMessageCrypto_GenericRequestHeader*)request.bytes;
    sign = (whMessageCrypto_EccSignRequest*)(header + 1);
    header->algoType = WC_PK_TYPE_ECDSA_SIGN;
    header->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    header->affinity = WH_CRYPTO_AFFINITY_SW;
    sign->keyId = WT_HSM_ATTEST_KEY_ID;
    sign->sz = 32u;
    (void)memcpy(sign + 1, digest, 32u);
    requestSize = (uint16_t)(sizeof(*header) + sizeof(*sign) + 32u);

    ret = wh_Server_HandleCryptoRequest(&g_server, WH_COMM_MAGIC_NATIVE,
        WC_ALGO_TYPE_PK, 0u, requestSize, request.bytes, &responseSize,
        response.bytes);
    rheader = (whMessageCrypto_GenericResponseHeader*)response.bytes;
    if ((ret == WH_ERROR_OK) && (rheader->rc != WH_ERROR_OK)) {
        ret = (int)rheader->rc;
    }
    if (ret == WH_ERROR_OK) {
        result = (whMessageCrypto_EccSignResponse*)(rheader + 1);
        der = (const uint8_t*)(result + 1);
        ret = wc_ecc_sig_to_rs(der, (word32)result->sz, r, &rSize, s, &sSize);
    }
    if ((ret == 0) && ((rSize > 32u) || (sSize > 32u))) {
        ret = WH_ERROR_ABORTED;
    }
    if (ret == 0) {
        (void)memset(signature, 0, 64u);
        (void)memcpy(&signature[32u - rSize], r, rSize);
        (void)memcpy(&signature[64u - sSize], s, sSize);
    }
    return ret;
}

/* Export only the public half, as production wt_hsm_attest_export_public. */
static int iak_export_public(uint8_t* point65)
{
    packet_t response;
    whMessageKeystore_ExportPublicRequest request;
    whMessageKeystore_ExportPublicResponse* result;
    ecc_key publicKey;
    const uint8_t* der;
    word32 xSize = 32u;
    word32 ySize = 32u;
    uint16_t responseSize = 0u;
    int keyInited = 0;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    request.id = WT_HSM_ATTEST_KEY_ID;
    request.algo = WH_KEY_ALGO_ECC;

    ret = wh_Server_HandleKeyRequest(&g_server, WH_COMM_MAGIC_NATIVE,
        WH_KEY_EXPORT_PUBLIC, (uint16_t)sizeof(request), &request,
        &responseSize, response.bytes);
    result = (whMessageKeystore_ExportPublicResponse*)response.bytes;
    if ((ret == WH_ERROR_OK) && (result->rc != WH_ERROR_OK)) {
        ret = (int)result->rc;
    }
    if (ret == WH_ERROR_OK) {
        der = response.bytes + sizeof(*result);
        ret = wc_ecc_init(&publicKey);
        if (ret == 0) {
            keyInited = 1;
            ret = wh_Crypto_EccDeserializeKeyDer(der, (uint16_t)result->len,
                                                 &publicKey);
        }
    }
    if (ret == WH_ERROR_OK) {
        point65[0] = 0x04u;
        ret = wc_ecc_export_public_raw(&publicKey, &point65[1], &xSize,
                                       &point65[33], &ySize);
        if ((ret == 0) && ((xSize != 32u) || (ySize != 32u))) {
            ret = WH_ERROR_ABORTED;
        }
    }
    if (keyInited != 0) {
        wc_ecc_free(&publicKey);
    }
    return ret;
}

/* Attempt the raw (private-material) keystore export. Must be refused. */
static int iak_export_raw(void)
{
    packet_t response;
    whMessageKeystore_ExportRequest request;
    whMessageKeystore_ExportResponse* result;
    uint16_t responseSize = 0u;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    request.id = WT_HSM_ATTEST_KEY_ID;

    ret = wh_Server_HandleKeyRequest(&g_server, WH_COMM_MAGIC_NATIVE,
        WH_KEY_EXPORT, (uint16_t)sizeof(request), &request, &responseSize,
        response.bytes);
    result = (whMessageKeystore_ExportResponse*)response.bytes;
    if ((ret == WH_ERROR_OK) && (result->rc != WH_ERROR_OK)) {
        ret = (int)result->rc;
    }
    return ret;
}

static whNvmId iak_nvm_id(void)
{
    whNvmId id;
    whNvmMetadata meta;
    whNvmId target = (whNvmId)WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                            WH_CLIENT_ID_MAX,
                                            WT_HSM_ATTEST_KEY_ID);

    (void)memset(&meta, 0, sizeof(meta));
    for (id = 1u; id != 0u; id++) {
        if ((wh_Nvm_GetMetadata(&g_nvm_ctx, id, &meta) == WH_ERROR_OK)) {
            if (id == target) {
                return id;
            }
        }
        if (id == 0xFFFFu) {
            break;
        }
    }
    return target;
}

int main(void)
{
    uint8_t digest[32];
    uint8_t signature[64];
    uint8_t point[65];
    uint8_t probe[32];
    uint8_t verifyDer[80];
    whNvmMetadata meta;
    whNvmId keyNvmId;
    ecc_key pub;
    word32 derLen = 0u;
    int verified = 0;
    int pubInited = 0;
    int ret;
    static whFlashRamsimCtx ramsim_ctx;
    static whFlashRamsimCfg ramsim_cfg;
    static const whFlashCb ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};

    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    (void)memset(&g_nvm_flash_cfg, 0, sizeof(g_nvm_flash_cfg));
    ramsim_cfg.memory = g_flash_memory;
    ramsim_cfg.size = RAMSIM_SIZE;
    ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    ramsim_cfg.pageSize = RAMSIM_PAGE;
    ramsim_cfg.erasedByte = 0xFF;
    g_nvm_flash_cfg.cb = ramsim_cb;
    g_nvm_flash_cfg.context = &ramsim_ctx;
    g_nvm_flash_cfg.config = &ramsim_cfg;
    g_nvm_cfg.cb = g_nvm_cb;
    g_nvm_cfg.context = &g_nvm_flash_ctx;
    g_nvm_cfg.config = &g_nvm_flash_cfg;
    if (wh_Nvm_Init(&g_nvm_ctx, &g_nvm_cfg) != WH_ERROR_OK) {
        printf("FAIL: attestation_iak (NVM init)\n");
        return 1;
    }

    /* Mirror wt_hsm_attest_init: server over the shared NVM, RNG crypto
     * context, attest identity WH_CLIENT_ID_MAX. */
    (void)memset(&g_crypto, 0, sizeof(g_crypto));
    if (wc_InitRng_ex(g_crypto.rng, NULL, INVALID_DEVID) != 0) {
        printf("FAIL: attestation_iak (RNG init)\n");
        return 1;
    }
    g_tm_cfg.req = (whTransportMemCsr*)g_req_buf;
    g_tm_cfg.req_size = sizeof(g_req_buf);
    g_tm_cfg.resp = (whTransportMemCsr*)g_resp_buf;
    g_tm_cfg.resp_size = sizeof(g_resp_buf);
    g_comm_cfg.transport_cb = g_tm_cb;
    g_comm_cfg.transport_context = &g_tm_ctx;
    g_comm_cfg.transport_config = &g_tm_cfg;
    g_comm_cfg.server_id = 0u;
    g_server_cfg.comm_config = &g_comm_cfg;
    g_server_cfg.nvm = &g_nvm_ctx;
    g_server_cfg.crypto = &g_crypto;
#if defined(WOLF_CRYPTO_CB)
    g_server_cfg.devId = INVALID_DEVID;
#endif
    if (wh_Server_Init(&g_server, &g_server_cfg) != WH_ERROR_OK) {
        printf("FAIL: attestation_iak (server init)\n");
        return 1;
    }
    g_server.comm->client_id = WH_CLIENT_ID_MAX;
    (void)wh_Server_SetConnected(&g_server, WH_COMM_CONNECTED);

    ret = iak_generate();
    check(ret == WH_ERROR_OK,
          "IAK provisions with the production lockdown flags");

    /* I1: the vault signs, and the signature verifies against the only
     * exportable artifact — the 65-byte public point. */
    (void)memset(digest, 0x5A, sizeof(digest));
    ret = iak_sign(digest, signature);
    check(ret == 0, "I1 vault signs a digest with the IAK");
    ret = iak_export_public(point);
    check((ret == 0) && (point[0] == 0x04u),
          "I1 public export yields the 65-byte point");
    if (ret == 0) {
        ret = wc_ecc_init(&pub);
        if (ret == 0) {
            pubInited = 1;
            ret = wc_ecc_import_unsigned(&pub, &point[1], &point[33], NULL,
                                         ECC_SECP256R1);
        }
        if (ret == 0) {
            derLen = (word32)sizeof(verifyDer);
            ret = wc_ecc_rs_raw_to_sig(signature, 32u, &signature[32], 32u,
                                       verifyDer, &derLen);
        }
        if (ret == 0) {
            ret = wc_ecc_verify_hash(verifyDer, derLen, digest,
                                     (word32)sizeof(digest), &verified, &pub);
        }
    }
    check((ret == 0) && (verified == 1),
          "I1 the signature verifies against the exported public point");

    /* I2: raw export of the IAK is refused. */
    ret = iak_export_raw();
    check(ret != WH_ERROR_OK,
          "I2 WT-FFM-0046 raw IAK export is refused (NONEXPORTABLE)");

    /* I3: the Checked NVM face cannot read the committed key object. */
    keyNvmId = iak_nvm_id();
    (void)memset(&meta, 0, sizeof(meta));
    ret = wh_Nvm_GetMetadata(&g_nvm_ctx, keyNvmId, &meta);
    check(ret == WH_ERROR_OK, "I3 the committed IAK object exists in NVM");
    check((meta.flags & WH_NVM_FLAGS_NONEXPORTABLE) != 0u,
          "I3 the stored object carries NONEXPORTABLE");
    ret = wh_Nvm_ReadChecked(&g_nvm_ctx, keyNvmId, 0u, (whNvmSize)sizeof(probe),
                             probe);
    check(ret != WH_ERROR_OK,
          "I3 WT-FFM-0046 Checked NVM read of the IAK is refused");

    /* I4: the IAK can be neither destroyed nor overwritten. */
    ret = wh_Nvm_DestroyObjectsChecked(&g_nvm_ctx, 1u, &keyNvmId);
    check(ret != WH_ERROR_OK,
          "I4 WT-FFM-0046 destroying the IAK is refused (NONDESTROYABLE)");
    ret = iak_generate();
    check(ret != WH_ERROR_OK,
          "I4 WT-FFM-0046 re-provisioning over the IAK is refused "
          "(NONMODIFIABLE)");
    ret = iak_sign(digest, signature);
    check(ret == 0, "I4 the original IAK still signs after the attempts");

    /* I5: a different authenticated client identity resolves its own key
     * namespace — the IAK does not exist there. */
    g_server.comm->client_id = WT_GUEST_CLIENT_ID;
    ret = iak_sign(digest, signature);
    check(ret != 0,
          "I5 WT-FFM-0046 a guest identity cannot sign with the IAK");
    ret = iak_export_public(point);
    check(ret != WH_ERROR_OK,
          "I5 the IAK public key is not even visible to a guest identity");
    g_server.comm->client_id = WH_CLIENT_ID_MAX;
    ret = iak_sign(digest, signature);
    check(ret == 0, "I5 the attest identity still signs (control)");

    if (pubInited != 0) {
        wc_ecc_free(&pub);
    }
    (void)wc_FreeRng(g_crypto.rng);

    printf("attestation_iak host tests: %d checks, %d failures\n",
           g_checks, g_failures);
    if (g_failures == 0) {
        printf("PASS: attestation_iak\n");
        return 0;
    }
    printf("FAIL: attestation_iak\n");
    return 1;
}
