/* test_loopback.c
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
 * Host-side wolfHSM loopback smoke test.
 *
 * Uses wh_transport_mem (shared-memory transport) to drive a wolfHSM server
 * and client in the same process with no threads.  All HSM round-trips follow
 * the pattern:
 *
 *   1. Client sends request  (wh_Client_Xxx...Request)
 *   2. Server handles it     (pump_server)
 *   3. Client receives reply (wh_Client_Xxx...Response)
 *
 * The blocking "wh_Client_Xxx" wrappers must NOT be used because they spin on
 * WH_ERROR_NOTREADY and will deadlock in a single-threaded environment.
 *
 * Two tests:
 *   A. RNG round-trip — request 32 bytes and verify at least one is non-zero.
 *   B. ECC P-256 keygen + sign + verify.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Pick up WOLFSSL_USER_SETTINGS -> user_settings.h */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn_public.h"

/* wolfHSM public API */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_crypto.h"

/* -------------------------------------------------------------------------
 * Transport buffers — request + response, 4 KB each
 * ---------------------------------------------------------------------- */
#define TRANSPORT_BUF_SIZE 4096
static uint8_t req_buffer[TRANSPORT_BUF_SIZE];
static uint8_t resp_buffer[TRANSPORT_BUF_SIZE];

/* -------------------------------------------------------------------------
 * NVM flash simulator — 256 KB of simulated flash
 * ---------------------------------------------------------------------- */
#define RAMSIM_SIZE    (256 * 1024)
#define RAMSIM_SECTOR  4096
/* Page size must equal sizeof(whFlashUnit) = 8 bytes; wolfHSM programs one
 * unit at a time and the ramsim rejects writes not a multiple of pageSize. */
#define RAMSIM_PAGE    8
static uint8_t flash_memory[RAMSIM_SIZE];

/* -------------------------------------------------------------------------
 * Helper: pump the server until it processes one queued request.
 *
 * wh_Server_HandleRequestMessage is non-blocking:
 *   WH_ERROR_OK       — processed a request and wrote a response
 *   WH_ERROR_NOTREADY — no request in the buffer yet (should not happen here)
 *   other             — hard error
 * ---------------------------------------------------------------------- */
static int pump_server(whServerContext* server)
{
    int rc;
    int retries = 1000;

    while (retries-- > 0) {
        rc = wh_Server_HandleRequestMessage(server);
        if (rc == WH_ERROR_OK) {
            return 0;
        }
        if (rc == WH_ERROR_NOTREADY) {
            continue;
        }
        fprintf(stderr, "wh_Server_HandleRequestMessage: %d\n", rc);
        return rc;
    }
    fprintf(stderr, "pump_server: no request appeared after many retries\n");
    return -1;
}

/* -------------------------------------------------------------------------
 * Test A: RNG round-trip — 32 bytes from the server RNG
 * ---------------------------------------------------------------------- */
static int test_rng(whClientContext* client, whServerContext* server)
{
    int      rc;
    uint8_t  rng_out[32];
    uint32_t out_size = (uint32_t)sizeof(rng_out);
    int      all_zero;
    int      i;

    memset(rng_out, 0, sizeof(rng_out));

    /* 1. Send request */
    rc = wh_Client_RngGenerateRequest(client, (uint32_t)sizeof(rng_out));
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "RngGenerateRequest: %d\n", rc);
        return rc;
    }

    /* 2. Let the server handle it */
    rc = pump_server(server);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* 3. Receive the response */
    rc = wh_Client_RngGenerateResponse(client, rng_out, &out_size);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "RngGenerateResponse: %d\n", rc);
        return rc;
    }

    /* Sanity check: at least one byte must be non-zero */
    all_zero = 1;
    for (i = 0; i < (int)sizeof(rng_out); i++) {
        if (rng_out[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        fprintf(stderr, "RNG returned all-zero output\n");
        return -1;
    }

    printf("RNG OK\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test B: ECC P-256 keygen + sign + verify
 *
 * Every client send is followed immediately by pump_server + receive.
 * The blocking wrappers (wh_Client_EccMakeCacheKey, wh_Client_EccSign …)
 * must not be used — they spin on NOTREADY and deadlock single-threaded.
 * ---------------------------------------------------------------------- */
static int test_ecc(whClientContext* client, whServerContext* server)
{
    int      rc;
    whKeyId  key_id     = WH_KEYID_ERASED;

    /* Signature buffer — DER ECDSA signature, 72 bytes max for P-256 */
    uint8_t  sig[ECC_MAX_SIG_SIZE];
    uint16_t sig_len = (uint16_t)sizeof(sig);

    /* DER buffer for the exported public key */
    uint8_t  pub_der[ECC_BUFSIZE];
    uint16_t pub_der_len = (uint16_t)sizeof(pub_der);

    ecc_key  pub_key;
    word32   idx;
    int      verify_result = 0;

    /* Fixed 32-byte "hash" to sign (simulates a SHA-256 digest) */
    static const uint8_t digest[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    /* -------------------------------------------------------------------
     * Step 1: Generate ECC P-256 key pair in server cache
     * ---------------------------------------------------------------- */
    rc = wh_Client_EccMakeCacheKeyRequest(client,
                                          /*size_bytes*/ 32,
                                          ECC_SECP256R1,
                                          WH_KEYID_ERASED,
                                          WH_NVM_FLAGS_USAGE_SIGN,
                                          /*label_len*/ 0,
                                          /*label*/ NULL);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "EccMakeCacheKeyRequest: %d\n", rc);
        return rc;
    }

    rc = pump_server(server);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = wh_Client_EccMakeCacheKeyResponse(client, &key_id);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "EccMakeCacheKeyResponse: %d\n", rc);
        return rc;
    }

    if (WH_KEYID_ISERASED(key_id)) {
        fprintf(stderr, "server returned erased key_id\n");
        return -1;
    }

    /* -------------------------------------------------------------------
     * Step 2: Export the public key (DER) so we can verify locally.
     * Use the split KeyExportPublic request/response API.
     * ---------------------------------------------------------------- */
    rc = wh_Client_KeyExportPublicRequest(client, key_id,
                                         (uint16_t)WH_KEY_ALGO_ECC);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "KeyExportPublicRequest: %d\n", rc);
        return rc;
    }

    rc = pump_server(server);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = wh_Client_KeyExportPublicResponse(client,
                                           /*label*/ NULL, /*labelSz*/ 0,
                                           pub_der, &pub_der_len);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "KeyExportPublicResponse: %d\n", rc);
        return rc;
    }

    /* Decode the exported DER public key into a wolfCrypt ecc_key */
    rc = wc_ecc_init(&pub_key);
    if (rc != 0) {
        fprintf(stderr, "wc_ecc_init: %d\n", rc);
        return rc;
    }
    idx = 0;
    rc = wc_EccPublicKeyDecode(pub_der, &idx, &pub_key, (word32)pub_der_len);
    if (rc != 0) {
        fprintf(stderr, "wc_EccPublicKeyDecode: %d\n", rc);
        wc_ecc_free(&pub_key);
        return rc;
    }

    /* -------------------------------------------------------------------
     * Step 3: Sign the fixed digest using the cached key on the server.
     * Use the split EccSign request/response API.
     * ---------------------------------------------------------------- */
    rc = wh_Client_EccSignRequest(client, key_id,
                                  digest, (uint16_t)sizeof(digest));
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "EccSignRequest: %d\n", rc);
        wc_ecc_free(&pub_key);
        return rc;
    }

    rc = pump_server(server);
    if (rc != WH_ERROR_OK) {
        wc_ecc_free(&pub_key);
        return rc;
    }

    rc = wh_Client_EccSignResponse(client, sig, &sig_len);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "EccSignResponse: %d\n", rc);
        wc_ecc_free(&pub_key);
        return rc;
    }

    /* -------------------------------------------------------------------
     * Step 4: Verify signature locally using the exported public key.
     * ---------------------------------------------------------------- */
    rc = wc_ecc_verify_hash(sig, (word32)sig_len,
                            digest, (word32)sizeof(digest),
                            &verify_result, &pub_key);
    if (rc != 0 || verify_result != 1) {
        fprintf(stderr, "wc_ecc_verify_hash: rc=%d verify=%d\n",
                rc, verify_result);
        wc_ecc_free(&pub_key);
        return (rc != 0) ? rc : -1;
    }

    wc_ecc_free(&pub_key);

    printf("ECC SIGN OK\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(void)
{
    uint32_t client_id = 0;
    uint32_t server_id = 0;
    int rc;

    /* === Transport ======================================================== */
    whTransportMemConfig tmcfg = {
        .req       = req_buffer,
        .req_size  = TRANSPORT_BUF_SIZE,
        .resp      = resp_buffer,
        .resp_size = TRANSPORT_BUF_SIZE,
    };

    whTransportClientCb         tmccb[1] = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext  tmcc[1] = {{0}};

    whTransportServerCb         tmscb[1] = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext  tmsc[1] = {{0}};

    /* === Comm layer configs =============================================== */
    whCommClientConfig ccc = {
        .transport_cb      = tmccb,
        .transport_context = tmcc,
        .transport_config  = &tmcfg,
        .client_id         = 1,
    };

    whCommServerConfig csc = {
        .transport_cb      = tmscb,
        .transport_context = tmsc,
        .transport_config  = &tmcfg,
        .server_id         = 2,
    };

    /* === NVM flash-ramsim ================================================= */
    memset(flash_memory, 0xFF, sizeof(flash_memory)); /* 0xFF = erased state */

    whFlashRamsimCfg ramsim_cfg = {
        .memory     = flash_memory,
        .size       = RAMSIM_SIZE,
        .sectorSize = RAMSIM_SECTOR,
        .pageSize   = RAMSIM_PAGE,
        .erasedByte = 0xFF,
        .initData   = NULL,
    };

    whFlashRamsimCtx ramsim_ctx = {0};

    static const whFlashCb ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};

    whNvmFlashConfig nvm_flash_cfg = {
        .cb      = ramsim_cb,
        .context = &ramsim_ctx,
        .config  = &ramsim_cfg,
    };

    whNvmFlashContext nvm_flash_ctx = {0};

    static const whNvmCb nvm_cb[1] = {WH_NVM_FLASH_CB};

    whNvmConfig nvm_cfg = {
        .cb      = (whNvmCb*)nvm_cb,
        .context = &nvm_flash_ctx,
        .config  = &nvm_flash_cfg,
    };

    whNvmContext nvm_ctx = {0};

    /* === Server crypto context ============================================ */
    whServerCryptoContext crypto_ctx = {0};

    /* === Client and server contexts ======================================= */
    whClientContext client[1] = {{0}};
    whServerContext server[1] = {{0}};

    whClientConfig client_cfg = {
        .comm = &ccc,
    };

    whServerConfig server_cfg = {
        .comm_config = &csc,
        .nvm         = &nvm_ctx,
        .crypto      = &crypto_ctx,
        /* INVALID_DEVID: server uses software-only wolfCrypt; do not route
         * server-side crypto back through the HSM client callback. */
        .devId       = INVALID_DEVID,
    };

    /* === Init NVM ========================================================= */
    rc = wh_Nvm_Init(&nvm_ctx, &nvm_cfg);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "wh_Nvm_Init: %d\n", rc);
        return 1;
    }

    /* === Init wolfCrypt ==================================================== */
    rc = wolfCrypt_Init();
    if (rc != 0) {
        fprintf(stderr, "wolfCrypt_Init: %d\n", rc);
        return 1;
    }

    /* === Init server RNG (must be done before wh_Server_Init) ============= */
    /* The whServerCryptoContext contains a WC_RNG that the server's crypto
     * handlers use directly (wc_RNG_GenerateBlock, wc_ecc_make_key_ex, …).
     * wolfHSM does not initialise it internally; the platform layer must call
     * wc_InitRng_ex before starting the server.  Use INVALID_DEVID so the
     * server's RNG uses the local /dev/urandom entropy source rather than
     * routing back through the HSM client callback — the server IS the HSM. */
    rc = wc_InitRng_ex(crypto_ctx.rng, NULL, INVALID_DEVID);
    if (rc != 0) {
        fprintf(stderr, "wc_InitRng_ex: %d\n", rc);
        return 1;
    }

    /* === Init server ======================================================= */
    rc = wh_Server_Init(server, &server_cfg);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "wh_Server_Init: %d\n", rc);
        return 1;
    }

    rc = wh_Server_SetConnected(server, WH_COMM_CONNECTED);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "wh_Server_SetConnected: %d\n", rc);
        return 1;
    }

    /* === Init client ======================================================= */
    rc = wh_Client_Init(client, &client_cfg);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "wh_Client_Init: %d\n", rc);
        return 1;
    }

    /* Comm-layer handshake: CommInit tells the server about this client */
    rc = wh_Client_CommInitRequest(client);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "CommInitRequest: %d\n", rc);
        return 1;
    }
    rc = pump_server(server);
    if (rc != WH_ERROR_OK) {
        return 1;
    }
    rc = wh_Client_CommInitResponse(client, &client_id, &server_id);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "CommInitResponse: %d\n", rc);
        return 1;
    }

    /* === Run tests ========================================================= */
    rc = test_rng(client, server);
    if (rc != 0) {
        fprintf(stderr, "FAIL: test_rng\n");
        return 1;
    }

    rc = test_ecc(client, server);
    if (rc != 0) {
        fprintf(stderr, "FAIL: test_ecc\n");
        return 1;
    }

    /* === Cleanup =========================================================== */
    wh_Client_Cleanup(client);
    wh_Server_Cleanup(server);
    wc_FreeRng(crypto_ctx.rng);
    wh_Nvm_Cleanup(&nvm_ctx);
    wolfCrypt_Cleanup();

    return 0;
}
