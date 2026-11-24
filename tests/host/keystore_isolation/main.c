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

/* The key-isolation proof on the wolfHSM server keystore
 * (WT-FFM-0046 / WT-FFM-0044), the single crypto backend after the second
 * (vault) keystore was retired. Keys are namespaced by the wolfHSM client_id,
 * which the SERVER stamps from its own comm context — never a value the client
 * supplies. On target the SERVICE_HSM relay runs one server per guest with
 * server_id = guest + 1, so a key committed by guest-A's server is invisible
 * to guest-B's. Here two servers share one wolfHSM NVM at client_id 1 and 2,
 * modelling those two guests:
 *
 *   K1  a key committed under client 1's namespace is usable by client 1     0046
 *   K2  the same key id is NOT resolvable from client 2 (cross-client)       0044
 *   K3  each client's own key id 5 is a distinct, independent object         0044
 *   K4  NONEXPORTABLE blocks the Checked read of private key bytes           0046
 *
 * The keygen/commit/export message flow mirrors the on-target IAK provisioning
 * in src/services/wolfhsm/wt_hsm.c so the proof exercises the same server
 * keystore path the guests reach through the relay. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_keyid.h"

#include <stdio.h>
#include <string.h>

#define CLIENT_A 1u
#define CLIENT_B 2u
#define KEY_ID   5u

#define RAMSIM_SIZE   (256 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];
static whNvmContext g_nvm_ctx;

static int g_failures;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    } else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

typedef union crypto_packet {
    uint64_t align;
    uint8_t  bytes[WOLFHSM_CFG_COMM_DATA_LEN];
} crypto_packet_t;

/* Null transport: the servers here are driven directly through the request
 * handlers, never over the wire, so Recv/Send just report no traffic. */
static int null_init(void* c, const void* cfg, whCommSetConnectedCb cb,
                     void* cbctx)
{
    (void)c; (void)cfg; (void)cb; (void)cbctx;
    return WH_ERROR_OK;
}
static int null_recv(void* c, uint16_t* sz, void* d)
{
    (void)c; (void)sz; (void)d;
    return WH_ERROR_NOTREADY;
}
static int null_send(void* c, uint16_t sz, const void* d)
{
    (void)c; (void)sz; (void)d;
    return WH_ERROR_NOTREADY;
}
static int null_cleanup(void* c)
{
    (void)c;
    return WH_ERROR_OK;
}
static const whTransportServerCb g_null_transport = {
    .Init = null_init, .Recv = null_recv,
    .Send = null_send, .Cleanup = null_cleanup
};

static int nvm_up(void)
{
    static whFlashRamsimCtx ramsim_ctx;
    static const whFlashCb ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
    static whNvmFlashContext nvm_flash_ctx;
    static const whNvmCb nvm_cb[1] = {WH_NVM_FLASH_CB};
    static whFlashRamsimCfg ramsim_cfg;
    static whNvmFlashConfig nvm_flash_cfg;
    whNvmConfig nvm_cfg;

    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    (void)memset(&ramsim_cfg, 0, sizeof(ramsim_cfg));
    ramsim_cfg.memory = g_flash_memory;
    ramsim_cfg.size = RAMSIM_SIZE;
    ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    ramsim_cfg.pageSize = RAMSIM_PAGE;
    ramsim_cfg.erasedByte = 0xFF;
    (void)memset(&nvm_flash_ctx, 0, sizeof(nvm_flash_ctx));
    (void)memset(&nvm_flash_cfg, 0, sizeof(nvm_flash_cfg));
    nvm_flash_cfg.cb = ramsim_cb;
    nvm_flash_cfg.context = &ramsim_ctx;
    nvm_flash_cfg.config = &ramsim_cfg;
    (void)memset(&nvm_cfg, 0, sizeof(nvm_cfg));
    nvm_cfg.cb = (whNvmCb*)nvm_cb;
    nvm_cfg.context = &nvm_flash_ctx;
    nvm_cfg.config = &nvm_flash_cfg;
    return (wh_Nvm_Init(&g_nvm_ctx, &nvm_cfg) == WH_ERROR_OK) ? 0 : -1;
}

/* Bring up one server sharing the single NVM, stamped with client_id. */
static int server_up(whServerContext* server, whServerCryptoContext* crypto,
                     whCommServerConfig* comm_cfg, whServerConfig* cfg,
                     uint16_t client_id)
{
    (void)memset(crypto, 0, sizeof(*crypto));
    if (wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID) != 0) {
        return -1;
    }
    (void)memset(comm_cfg, 0, sizeof(*comm_cfg));
    comm_cfg->transport_cb = &g_null_transport;
    comm_cfg->server_id = (uint8_t)client_id;
    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->comm_config = comm_cfg;
    cfg->nvm = &g_nvm_ctx;
    cfg->crypto = crypto;
#if defined(WOLF_CRYPTO_CB)
    cfg->devId = INVALID_DEVID;
#endif
    if (wh_Server_Init(server, cfg) != WH_ERROR_OK) {
        return -1;
    }
    server->comm->client_id = client_id;
    return (wh_Server_SetConnected(server, WH_COMM_CONNECTED) == WH_ERROR_OK)
               ? 0 : -1;
}

/* Generate a P-256 key at `id` and commit it to shared NVM under the server's
 * stamped namespace, WH_MAKE_KEYID(CRYPTO, client_id, id). Two servers with
 * distinct client_ids land in disjoint NVM slots — the same isolation the
 * relay gives the guests on target. Mirrors wt_hsm_attest_generate_key. */
static int keygen_commit(whServerContext* server, uint16_t client_id,
                         uint16_t id)
{
    static const uint8_t label[] = "keystore-iso";
    crypto_packet_t request;
    crypto_packet_t response;
    whMessageCrypto_GenericRequestHeader* header;
    whMessageCrypto_EccKeyGenRequest* keygen_req;
    whMessageCrypto_GenericResponseHeader* resp_hdr;
    whMessageCrypto_EccKeyGenResponse* result;
    uint16_t request_size;
    uint16_t response_size = 0u;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    header = (whMessageCrypto_GenericRequestHeader*)request.bytes;
    keygen_req = (whMessageCrypto_EccKeyGenRequest*)(header + 1);
    header->algoType = WC_PK_TYPE_EC_KEYGEN;
    header->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    header->affinity = WH_CRYPTO_AFFINITY_SW;
    keygen_req->sz = 32u;
    keygen_req->curveId = ECC_SECP256R1;
    keygen_req->keyId = id;
    keygen_req->flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE |
                        WH_NVM_FLAGS_LOCAL | WH_NVM_FLAGS_USAGE_SIGN;
    (void)memcpy(keygen_req->label, label, sizeof(label) - 1u);
    request_size = (uint16_t)(sizeof(*header) + sizeof(*keygen_req));

    ret = wh_Server_HandleCryptoRequest(server, WH_COMM_MAGIC_NATIVE,
              WC_ALGO_TYPE_PK, 0u, request_size, request.bytes,
              &response_size, response.bytes);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    resp_hdr = (whMessageCrypto_GenericResponseHeader*)response.bytes;
    if (resp_hdr->rc != WH_ERROR_OK) {
        return resp_hdr->rc;
    }
    result = (whMessageCrypto_EccKeyGenResponse*)(resp_hdr + 1);
    if (result->keyId != id) {
        return WH_ERROR_ABORTED;
    }
    /* Keygen only caches; commit persists the cached key to shared NVM under
     * the server's stamped namespace. */
    return wh_Server_KeystoreCommitKey(server,
               WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, client_id, id));
}

/* Ask `server` to export the public half of key `id` in its own namespace.
 * Returns the keystore result code (WH_ERROR_OK, WH_ERROR_NOTFOUND, ...). */
static int export_public(whServerContext* server, uint16_t id,
                         uint8_t* pub, uint16_t* pub_len)
{
    crypto_packet_t response;
    whMessageKeystore_ExportPublicRequest request;
    whMessageKeystore_ExportPublicResponse* result;
    uint16_t response_size = 0u;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    request.id = id;
    request.algo = WH_KEY_ALGO_ECC;
    ret = wh_Server_HandleKeyRequest(server, WH_COMM_MAGIC_NATIVE,
              WH_KEY_EXPORT_PUBLIC, (uint16_t)sizeof(request), &request,
              &response_size, response.bytes);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    result = (whMessageKeystore_ExportPublicResponse*)response.bytes;
    if (result->rc != WH_ERROR_OK) {
        return result->rc;
    }
    if (pub != NULL && pub_len != NULL) {
        if (result->len > *pub_len) {
            return WH_ERROR_ABORTED;
        }
        (void)memcpy(pub, response.bytes + sizeof(*result), result->len);
        *pub_len = (uint16_t)result->len;
    }
    return WH_ERROR_OK;
}

int main(void)
{
    whServerContext server_a;
    whServerContext server_b;
    whServerCryptoContext crypto_a;
    whServerCryptoContext crypto_b;
    whCommServerConfig comm_a;
    whCommServerConfig comm_b;
    whServerConfig cfg_a;
    whServerConfig cfg_b;
    whNvmMetadata meta;
    uint8_t pub_a[128];
    uint8_t pub_b[128];
    uint8_t probe[128];
    uint16_t pub_a_len = (uint16_t)sizeof(pub_a);
    uint16_t pub_b_len = (uint16_t)sizeof(pub_b);
    uint16_t probe_pub_len = (uint16_t)sizeof(probe);
    uint32_t probe_len = (uint32_t)sizeof(probe);
    int rc;

    if (wolfCrypt_Init() != 0 || nvm_up() != 0) {
        (void)fprintf(stderr, "bring-up failed\n");
        return 1;
    }
    if (server_up(&server_a, &crypto_a, &comm_a, &cfg_a, CLIENT_A) != 0 ||
            server_up(&server_b, &crypto_b, &comm_b, &cfg_b, CLIENT_B) != 0) {
        (void)fprintf(stderr, "server bring-up failed\n");
        return 1;
    }

    /* K1: client 1 generates + commits key id 5 in its namespace, then uses it. */
    rc = keygen_commit(&server_a, CLIENT_A, KEY_ID);
    check(rc == WH_ERROR_OK,
          "WT-FFM-0046 client 1 commits a P-256 key to the server keystore");
    rc = export_public(&server_a, KEY_ID, pub_a, &pub_a_len);
    check(rc == WH_ERROR_OK && pub_a_len > 0u,
          "K1 client 1 exports the public half of its own key");

    /* K2a: at the shared NVM layer the object exists only under client 1's
     * stamped id, never client 2's — the namespace separation is persistent,
     * not just a per-server cache artifact. */
    check(wh_Nvm_GetMetadata(&g_nvm_ctx,
              WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, CLIENT_A, KEY_ID), &meta) ==
              WH_ERROR_OK,
          "K2 the key persists in shared NVM under client 1's namespace");
    check(wh_Nvm_GetMetadata(&g_nvm_ctx,
              WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, CLIENT_B, KEY_ID), &meta) ==
              WH_ERROR_NOTFOUND,
          "K2 client 2's namespace holds no such object in shared NVM");

    /* K2b: client 2 asks for id 5 — the server stamps client 2's namespace,
     * so client 1's key is not resolvable through the request path. */
    rc = export_public(&server_b, KEY_ID, pub_b, &pub_b_len);
    check(rc == WH_ERROR_NOTFOUND,
          "K2 WT-FFM-0044 client 1's key is invisible to client 2");

    /* K3: client 2 owns id 5 independently; both objects coexist, distinct. */
    rc = keygen_commit(&server_b, CLIENT_B, KEY_ID);
    check(rc == WH_ERROR_OK,
          "client 2 generates its own key at the same id");
    pub_b_len = (uint16_t)sizeof(pub_b);
    rc = export_public(&server_b, KEY_ID, pub_b, &pub_b_len);
    check(rc == WH_ERROR_OK && pub_b_len == pub_a_len &&
          memcmp(pub_a, pub_b, pub_a_len) != 0,
          "K3 WT-FFM-0044 each client's id 5 is a distinct, independent key");
    rc = export_public(&server_a, KEY_ID, probe, &probe_pub_len);
    check(rc == WH_ERROR_OK,
          "K3 client 1's key still resolves in its own namespace");

    /* K4: the private key is NONEXPORTABLE — the Checked read the client
     * message layer uses is refused for both clients' committed keys. */
    rc = wh_Server_KeystoreReadKeyChecked(&server_a,
             WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, CLIENT_A, KEY_ID), &meta,
             probe, &probe_len);
    check(rc == WH_ERROR_ACCESS,
          "K4 WT-FFM-0046 NONEXPORTABLE blocks the Checked read of private bytes");

    wh_Server_Cleanup(&server_a);
    wh_Server_Cleanup(&server_b);
    wc_FreeRng(crypto_a.rng);
    wc_FreeRng(crypto_b.rng);
    wh_Nvm_Cleanup(&g_nvm_ctx);
    wolfCrypt_Cleanup();

    if (g_failures != 0) {
        (void)printf("FAIL: keystore_isolation (%d failures)\n", g_failures);
        return 1;
    }
    (void)printf("PASS: server keystore cross-client isolation (WT-FFM-0046)\n");
    return 0;
}
