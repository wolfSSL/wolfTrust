/* pkcs11_secure_client.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 */

#include "wolftrust/pkcs11_secure_client.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wolftrust/hsm_psa_transport.h"

#define WT_SERVICE_HSM_SID     4102U
#define WT_SERVICE_HSM_VERSION 1U

static wt_hsm_psa_transport_ctx_t g_transport;
static const wt_hsm_psa_transport_cfg_t g_transport_config = {
    WT_SERVICE_HSM_SID,
    WT_SERVICE_HSM_VERSION,
};
static whClientContext g_client;
static whClientConfig g_client_config;
static whCommClientConfig g_comm_config;
static uint8_t g_client_initialized;
static uint8_t g_hsm_restarted;

int wt_pkcs11_secure_client_init(void)
{
    int rc;

    g_comm_config.transport_cb = &wt_hsm_psa_transport_cb;
    g_comm_config.transport_context = &g_transport;
    g_comm_config.transport_config = &g_transport_config;
    g_comm_config.client_id = WT_PKCS11_HSM_CLIENT_ID;
    g_client_config.comm = &g_comm_config;

    rc = wh_Client_Init(&g_client, &g_client_config);
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_CommInitRequest(&g_client);
    }
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_CommInitResponse(&g_client, NULL, NULL);
    }
    if (rc != WH_ERROR_OK) {
        (void)wh_Client_Cleanup(&g_client);
    }
    else {
        g_client_initialized = 1U;
        g_hsm_restarted = 0U;
    }
    return rc;
}

void wt_pkcs11_secure_client_hsm_restarted(void)
{
    g_hsm_restarted = 1U;
}

int wt_pkcs11_secure_client_prepare(void)
{
    if (g_hsm_restarted != 0U) {
        if (g_client_initialized != 0U) {
            (void)wh_Client_Cleanup(&g_client);
            g_client_initialized = 0U;
        }
    }
    if (g_client_initialized == 0U) {
        return wt_pkcs11_secure_client_init();
    }
    return WH_ERROR_OK;
}
