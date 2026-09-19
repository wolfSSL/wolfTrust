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

/* Host proof of the wolfHSM-over-SPM relay (WT-FFM-0054): a real wolfHSM
 * client whose transport is the SPM-mediated psa_call path reaches a real
 * wolfHSM server pumped by SERVICE_HSM's dispatch, through a genuine
 * psa_connect/psa_call round trip on the in-process FF-M runtime. There is
 * no shared-RAM CSR handshake anywhere in the chain: Send performs the whole
 * mediated round trip, so the client's blocking wrappers complete on the
 * first Recv — the property that retires the multi-chunk hang class. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_keyid.h"

#include "wolftrust/ffm.h"
#include "wolftrust/ffm_veneer.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/hsm_psa_transport.h"
#include "psa/client.h"

#define TEST_HSM_PARTITION 2
#define TEST_HSM_SID       4102U
#define TEST_NS_CLIENT     (-1)

static int g_failures;
static int32_t g_connect_error;
static unsigned int g_connect_count;

extern int (*test_wolfhsm_sys_init)(void);
int wolfhsm_guest_init(void);
whClientContext* wolfhsm_guest_client(void);

static void check(int ok, const char* what)
{
    if (ok) {
        printf("PASS: %s\n", what);
    }
    else {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/* ---- in-process FF-M runtime fixture ---- */
static wt_ffm_runtime_t g_runtime;

static int test_check_read(void* context, psa_client_id_t caller,
                           const void* address, size_t size)
{
    (void)context;
    (void)caller;
    return size == 0U || address != NULL;
}

static int test_check_write(void* context, psa_client_id_t caller,
                            void* address, size_t size)
{
    (void)context;
    (void)caller;
    return size == 0U || address != NULL;
}

static void test_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
}

static int test_dispatch(void* context, wt_ffm_runtime_t* runtime,
                         int32_t partition_id)
{
    (void)context;
    return wt_hsm_relay_dispatch(NULL, runtime, partition_id);
}

static const wt_ffm_port_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    test_dispatch,
    test_panic
};

static const wt_service_descriptor_t g_services[] = {
    {
        "SERVICE_HSM", TEST_HSM_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_HSM", TEST_HSM_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "wolfhsm-relay-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

/* ---- host stubs for the NS->S veneers: route into the runtime ---- */
int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version)
{
    g_connect_count++;
    if (g_connect_error != PSA_SUCCESS) {
        return g_connect_error;
    }
    return (int32_t)wt_ffm_connect(&g_runtime, TEST_NS_CLIENT, sid, version);
}

void WolfTrust_FFM_Close(int32_t handle)
{
    (void)wt_ffm_close(&g_runtime, TEST_NS_CLIENT, handle);
}

int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                           wt_ffm_veneer_iovec_t* iv)
{
    psa_invec in[WT_FFM_VENEER_IOVEC_MAX];
    psa_outvec out[WT_FFM_VENEER_IOVEC_MAX];
    psa_status_t st;
    uint32_t i;

    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    for (i = 0u; i < iv->in_count; i++) {
        in[i].base = iv->in[i].base;
        in[i].len = iv->in[i].len;
    }
    for (i = 0u; i < iv->out_count; i++) {
        out[i].base = iv->out[i].base;
        out[i].len = iv->out[i].len;
    }
    st = wt_ffm_call(&g_runtime, TEST_NS_CLIENT, handle, type,
                     in, iv->in_count, out, iv->out_count);
    for (i = 0u; i < iv->out_count; i++) {
        iv->out[i].len = (uint32_t)out[i].len;
    }
    return (int32_t)st;
}

uint32_t WolfTrust_FFM_FrameworkVersion(void)
{
    return PSA_FRAMEWORK_VERSION;
}

uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid)
{
    (void)sid;
    return 1u;
}

/* ---- capture transport: the server's view of the relay. The submit hook
 * stashes one request here; the server's Recv consumes it and its Send
 * captures the response — exactly the shape the target's secure relay
 * buffer will have (no NS-RAM, no CSR words). ---- */
static uint8_t g_srv_req[WT_HSM_RELAY_MSG_MAX];
static uint16_t g_srv_req_len;
static int g_srv_req_pending;
static uint8_t g_srv_resp[WT_HSM_RELAY_MSG_MAX];
static uint16_t g_srv_resp_len;
static int g_srv_resp_ready;

static int srv_capture_init(void* ctx, const void* cfg,
                            whCommSetConnectedCb connectcb,
                            void* connectcb_arg)
{
    (void)ctx;
    (void)cfg;
    if (connectcb != NULL) {
        connectcb(connectcb_arg, WH_COMM_CONNECTED);
    }
    return WH_ERROR_OK;
}

static int srv_capture_cleanup(void* ctx)
{
    (void)ctx;
    return WH_ERROR_OK;
}

static int srv_capture_recv(void* ctx, uint16_t* inout_size, void* data)
{
    (void)ctx;
    if (g_srv_req_pending == 0) {
        return WH_ERROR_NOTREADY;
    }
    memcpy(data, g_srv_req, g_srv_req_len);
    *inout_size = g_srv_req_len;
    g_srv_req_pending = 0;
    return WH_ERROR_OK;
}

static int srv_capture_send(void* ctx, uint16_t size, const void* data)
{
    (void)ctx;
    if (size > sizeof(g_srv_resp)) {
        return WH_ERROR_BADARGS;
    }
    memcpy(g_srv_resp, data, size);
    g_srv_resp_len = size;
    g_srv_resp_ready = 1;
    return WH_ERROR_OK;
}

static const whTransportServerCb g_srv_capture_cb = {
    .Init    = srv_capture_init,
    .Send    = srv_capture_send,
    .Recv    = srv_capture_recv,
    .Cleanup = srv_capture_cleanup,
};

/* ---- the submit hook: hand one packet to the server, run it to
 * completion, return the response — the host stand-in for the monitor's
 * per-guest server tasklet. ---- */
static whServerContext g_server[1];

static int test_relay_submit(void* submit_ctx, int32_t client_id,
                             const uint8_t* req, size_t req_len,
                             uint8_t* resp, size_t resp_cap, size_t* resp_len)
{
    int rc;
    int retries = 1000;

    (void)submit_ctx;
    (void)client_id;
    if (req_len > sizeof(g_srv_req)) {
        return -1;
    }
    memcpy(g_srv_req, req, req_len);
    g_srv_req_len = (uint16_t)req_len;
    g_srv_req_pending = 1;
    g_srv_resp_ready = 0;

    while (retries-- > 0) {
        rc = wh_Server_HandleRequestMessage(g_server);
        if (rc == WH_ERROR_OK) {
            break;
        }
        if (rc != WH_ERROR_NOTREADY) {
            return -1;
        }
    }
    if (g_srv_resp_ready == 0 || g_srv_resp_len > resp_cap) {
        return -1;
    }
    memcpy(resp, g_srv_resp, g_srv_resp_len);
    *resp_len = g_srv_resp_len;
    return 0;
}

/* ---- NVM flash simulator for the server ---- */
#define RAMSIM_SIZE   (256 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8
static uint8_t flash_memory[RAMSIM_SIZE];

static int buf_is_zero(const uint8_t* buf, size_t len)
{
    size_t i;

    for (i = 0u; i < len; i++) {
        if (buf[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void test_guest_init_retry(void)
{
    WC_RNG rng;
    uint8_t output[32];
    unsigned int connected_count;

    (void)memset(&rng, 0, sizeof(rng));
    rng.devId = WH_DEV_ID;
    check(wc_CryptoCb_RandomBlock(&rng, output, sizeof(output)) == WC_HW_E,
          "WT-FFM-0054 unavailable HSM callback fails closed");
    check(wc_CryptoCb_IsDeviceRegistered(WH_DEV_ID) != 0,
          "failed HSM retry keeps the callback registered");
    check(wc_CryptoCb_RandomBlock(&rng, output, sizeof(output)) == WC_HW_E,
          "HSM callback remains retryable after repeated failures");
    g_connect_error = PSA_SUCCESS;
    (void)memset(output, 0, sizeof(output));
    check(wc_CryptoCb_RandomBlock(&rng, output, sizeof(output)) == 0 &&
              buf_is_zero(output, sizeof(output)) == 0,
          "WT-FFM-0054 callback reconnects after initial HSM failure");
    connected_count = g_connect_count;
    check(wc_CryptoCb_RandomBlock(&rng, output, sizeof(output)) == 0 &&
              g_connect_count == connected_count,
          "ready callback reuses its HSM connection");
    (void)wh_Client_Cleanup(wolfhsm_guest_client());
    check(test_wolfhsm_sys_init() == 0,
          "successful guest SYS_INIT does not duplicate callback registration");
    check(wc_CryptoCb_RandomBlock(&rng, output, sizeof(output)) == 0,
          "successful guest SYS_INIT serves crypto operations");
    (void)wh_Client_Cleanup(wolfhsm_guest_client());
}

int main(void)
{
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
    whServerCryptoContext crypto_ctx = {0};
    whCommServerConfig csc = {
        .transport_cb      = (whTransportServerCb*)&g_srv_capture_cb,
        .transport_context = NULL,
        .transport_config  = NULL,
        .server_id         = 2,
    };
    whServerConfig server_cfg = {
        .comm_config = &csc,
        .nvm         = &nvm_ctx,
        .crypto      = &crypto_ctx,
        .devId       = INVALID_DEVID,
    };

    wt_hsm_psa_transport_ctx_t tctx;
    wt_hsm_psa_transport_cfg_t tcfg = {
        .sid = TEST_HSM_SID,
        .version = 1U,
    };
    whCommClientConfig ccc = {
        .transport_cb      = (whTransportClientCb*)&wt_hsm_psa_transport_cb,
        .transport_context = &tctx,
        .transport_config  = &tcfg,
        .client_id         = 1,
    };
    whClientConfig client_cfg = {
        .comm = &ccc,
    };
    whClientContext client[1] = {{0}};

    uint32_t client_id = 0;
    uint32_t server_id = 0;
    uint8_t rng_small[32];
    uint8_t rng_large[1000];
    int rc;
    int guest_init_rc;

    /* ECC state for the sign/verify round trip */
    whKeyId key_id = WH_KEYID_ERASED;
    uint8_t sig[ECC_MAX_SIG_SIZE];
    uint16_t sig_len = (uint16_t)sizeof(sig);
    uint8_t pub_der[ECC_BUFSIZE];
    uint16_t pub_der_len = (uint16_t)sizeof(pub_der);
    ecc_key pub_key;
    word32 idx = 0;
    int verify_result = 0;
    static const uint8_t digest[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    /* Direct-psa_call state for the relay-side bound negative */
    psa_handle_t raw_handle;
    uint8_t oversize_req[WT_HSM_RELAY_MSG_MAX + 88U];
    uint8_t raw_out[16];
    psa_invec raw_in;
    psa_outvec raw_out_vec;
    psa_status_t raw_st;

    memset(&tctx, 0, sizeof(tctx));

    g_connect_error = PSA_ERROR_CONNECTION_REFUSED;
    guest_init_rc = wolfhsm_guest_init();
    check(guest_init_rc == WH_ERROR_ABORTED &&
              wc_CryptoCb_IsDeviceRegistered(WH_DEV_ID) == 0,
          "permanent HSM connect failure remains terminal");
    g_connect_error = PSA_ERROR_GENERIC_ERROR;
    guest_init_rc = wolfhsm_guest_init();
    check(guest_init_rc == 0,
          "FreeRTOS guest init installs retry after cold-start failure");

    /* === FF-M runtime up first: the client transport connects through it. */
    check(wt_ffm_init(&g_runtime, &g_manifest, &g_port_ops, NULL) ==
              WT_FFM_SUCCESS,
          "in-process FF-M runtime initializes");

    /* === Server (the host stand-in for the monitor tasklet). */
    memset(flash_memory, 0xFF, sizeof(flash_memory));
    rc = wh_Nvm_Init(&nvm_ctx, &nvm_cfg);
    check(rc == WH_ERROR_OK, "wolfHSM NVM (ramsim) initializes");
    rc = wolfCrypt_Init();
    check(rc == 0, "wolfCrypt initializes");
    rc = wc_InitRng_ex(crypto_ctx.rng, NULL, INVALID_DEVID);
    check(rc == 0, "server RNG initializes");
    rc = wh_Server_Init(g_server, &server_cfg);
    check(rc == WH_ERROR_OK, "wolfHSM server initializes");
    rc = wh_Server_SetConnected(g_server, WH_COMM_CONNECTED);
    check(rc == WH_ERROR_OK, "wolfHSM server marked connected");

    wt_hsm_relay_set_submit(test_relay_submit, NULL);
    test_guest_init_retry();

    /* === Client: wh_Client_Init runs the transport Init, which performs the
     * psa_connect to SERVICE_HSM through the SPM. */
    rc = wh_Client_Init(client, &client_cfg);
    check(rc == WH_ERROR_OK,
          "wolfHSM client initializes over the SPM transport");

    rc = wh_Client_CommInitRequest(client);
    check(rc == WH_ERROR_OK, "CommInit request crosses the SPM");
    rc = wh_Client_CommInitResponse(client, &client_id, &server_id);
    check(rc == WH_ERROR_OK && server_id == 2U,
          "CommInit response returns on the first Recv (no spin)");

    /* === RNG, single packet, via the BLOCKING wrapper on purpose: the
     * synchronous mediated transport must complete it without a NOTREADY
     * spin. */
    memset(rng_small, 0, sizeof(rng_small));
    rc = wh_Client_RngGenerate(client, rng_small, sizeof(rng_small));
    check(rc == WH_ERROR_OK && buf_is_zero(rng_small, sizeof(rng_small)) == 0,
          "32-byte RNG through the relay (blocking wrapper)");

    /* === RNG, multi-chunk (1000 > COMM_DATA_LEN): each chunk is one fully
     * completed psa_call — the sequencing that retires the multi-chunk hang
     * class (WT-FFM-0054 single mediated path). */
    memset(rng_large, 0, sizeof(rng_large));
    rc = wh_Client_RngGenerate(client, rng_large, sizeof(rng_large));
    check(rc == WH_ERROR_OK && buf_is_zero(rng_large, 64) == 0 &&
              buf_is_zero(rng_large + sizeof(rng_large) - 64, 64) == 0,
          "1000-byte multi-chunk RNG through the relay");

    /* === ECC P-256 keygen + sign on the server, verify locally. Split
     * request/response API; no server pump between — the relay already ran
     * the server to completion inside each Send. */
    rc = wh_Client_EccMakeCacheKeyRequest(client, 32, ECC_SECP256R1,
                                          WH_KEYID_ERASED,
                                          WH_NVM_FLAGS_USAGE_SIGN, 0, NULL);
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_EccMakeCacheKeyResponse(client, &key_id);
    }
    check(rc == WH_ERROR_OK && !WH_KEYID_ISERASED(key_id),
          "ECC P-256 keygen in the server keystore through the relay");

    rc = wh_Client_KeyExportPublicRequest(client, key_id,
                                          (uint16_t)WH_KEY_ALGO_ECC);
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_KeyExportPublicResponse(client, NULL, 0, pub_der,
                                               &pub_der_len);
    }
    check(rc == WH_ERROR_OK, "public key export through the relay");

    rc = wh_Client_EccSignRequest(client, key_id, digest,
                                  (uint16_t)sizeof(digest));
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_EccSignResponse(client, sig, &sig_len);
    }
    check(rc == WH_ERROR_OK, "ECC sign on the server through the relay");

    rc = wc_ecc_init(&pub_key);
    if (rc == 0) {
        rc = wc_EccPublicKeyDecode(pub_der, &idx, &pub_key,
                                   (word32)pub_der_len);
    }
    if (rc == 0) {
        rc = wc_ecc_verify_hash(sig, (word32)sig_len, digest,
                                (word32)sizeof(digest), &verify_result,
                                &pub_key);
    }
    wc_ecc_free(&pub_key);
    check(rc == 0 && verify_result == 1,
          "signature verifies against the exported public key");

    /* === Fail closed: with no submit hook the relay refuses the packet and
     * the client sees a transport error, never a hang. */
    wt_hsm_relay_set_submit(NULL, NULL);
    memset(rng_small, 0, sizeof(rng_small));
    rc = wh_Client_RngGenerate(client, rng_small, sizeof(rng_small));
    check(rc != WH_ERROR_OK, "relay with no submit hook fails closed");
    wt_hsm_relay_set_submit(test_relay_submit, NULL);
    rc = wh_Client_RngGenerate(client, rng_small, sizeof(rng_small));
    check(rc == WH_ERROR_OK, "relay serves again after the hook returns");

    /* === Client-side bound: a packet beyond WT_HSM_RELAY_MSG_MAX is refused
     * before any veneer call. */
    rc = wt_hsm_psa_transport_cb.Send(&tctx,
                                      (uint16_t)(WT_HSM_RELAY_MSG_MAX + 1U),
                                      oversize_req);
    check(rc == WH_ERROR_BADARGS,
          "oversized packet refused by the client transport");

    /* === Relay-side bound: an invec beyond WT_HSM_RELAY_MSG_MAX (but under
     * the FF-M copied-transfer limit) is refused by the relay itself. */
    raw_handle = psa_connect(TEST_HSM_SID, 1U);
    memset(oversize_req, 0xA5, sizeof(oversize_req));
    raw_in.base = oversize_req;
    raw_in.len = sizeof(oversize_req);
    raw_out_vec.base = raw_out;
    raw_out_vec.len = sizeof(raw_out);
    raw_st = psa_call(raw_handle, PSA_IPC_CALL, &raw_in, 1U, &raw_out_vec,
                      1U);
    psa_close(raw_handle);
    check(PSA_HANDLE_IS_VALID(raw_handle) && raw_st != PSA_SUCCESS,
          "oversized invec refused by the relay dispatch");

    wh_Client_Cleanup(client);
    wh_Server_Cleanup(g_server);
    wc_FreeRng(crypto_ctx.rng);
    wh_Nvm_Cleanup(&nvm_ctx);
    wolfCrypt_Cleanup();

    if (g_failures == 0) {
        printf("PASS: wolfhsm_relay (wolfHSM over the SPM, WT-FFM-0054)\n");
        return 0;
    }
    printf("FAIL: wolfhsm_relay (%d failures)\n", g_failures);
    return 1;
}
