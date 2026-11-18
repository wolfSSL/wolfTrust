/* provider_crypto.c
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

#include "wolftrust/provider_crypto.h"

#if defined(WT_ENGINE_HSM)
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
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

#if defined(CONFIG_TPM) && defined(WOLF_CRYPTO_CB_FIND)
/* fwTPM initializes keys without a device ID. */
static int wt_provider_find_device(int devId, int algoType)
{
    (void)algoType;
    return devId == INVALID_DEVID ? WH_DEV_ID : devId;
}
#endif

int wt_provider_crypto_init(void)
{
    int rc;

#if defined(CONFIG_TPM) && defined(WOLF_CRYPTO_CB_FIND)
    wc_CryptoCb_SetDeviceFindCb(wt_provider_find_device);
#endif
    g_comm_config.transport_cb = &wt_hsm_psa_transport_cb;
    g_comm_config.transport_context = &g_transport;
    g_comm_config.transport_config = &g_transport_config;
    g_comm_config.client_id = WT_PROVIDER_HSM_CLIENT_ID;
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

void wt_provider_crypto_hsm_restarted(void)
{
    g_hsm_restarted = 1U;
}

int wt_provider_crypto_prepare(void)
{
    if (g_hsm_restarted != 0U) {
        if (g_client_initialized != 0U) {
            (void)wh_Client_Cleanup(&g_client);
            g_client_initialized = 0U;
        }
    }
    if (g_client_initialized == 0U) {
        return wt_provider_crypto_init();
    }
    return WH_ERROR_OK;
}

#else
#include "wolfssl/wolfcrypt/wc_port.h"

int wt_provider_crypto_init(void)
{
    return wolfCrypt_Init();
}

int wt_provider_crypto_prepare(void)
{
    return 0;
}

void wt_provider_crypto_hsm_restarted(void)
{
}
#endif
