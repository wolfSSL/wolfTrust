/* wolfhsm_client_glue.c
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

/* wolfHSM client glue for the wolfTrust Zephyr non-secure guest.
 *
 * The transport is the SPM-mediated PSA path (WT-FFM-0054): every wolfHSM
 * wire packet is one synchronous psa_call to SERVICE_HSM through the
 * OS-neutral FF-M client core. The former shared-RAM CSR window and the raw
 * WolfTrust_HSM_Submit/Poll CMSE veneers are retired from this guest. */

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"

#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"

#include "wolftrust/hsm_psa_transport.h"

/* SERVICE_HSM from the platform manifest (port/stm32h563/manifest.json). */
#define WT_SERVICE_HSM_SID     4102u
#define WT_SERVICE_HSM_VERSION 1u

#ifndef WT_WOLFHSM_CLIENT_ID
#define WT_WOLFHSM_CLIENT_ID 1u
#endif

static wt_hsm_psa_transport_ctx_t g_guest_tx;

static const wt_hsm_psa_transport_cfg_t g_guest_tx_cfg = {
    .sid = WT_SERVICE_HSM_SID,
    .version = WT_SERVICE_HSM_VERSION,
};

static whClientContext    g_client_ctx;
static whClientConfig     g_client_cfg;
static whCommClientConfig g_comm_cfg;
static int                g_client_ready;
static int                g_retry_crypto_initialized;

static int wolfhsm_guest_register_retry(void);

static int wolfhsm_guest_connect(void)
{
    int rc;

    g_client_ready = 0;

    g_comm_cfg.transport_cb      = &wt_hsm_psa_transport_cb;
    g_comm_cfg.transport_context = &g_guest_tx;
    g_comm_cfg.transport_config  = &g_guest_tx_cfg;
    g_comm_cfg.client_id         = WT_WOLFHSM_CLIENT_ID;

    g_client_cfg.comm = &g_comm_cfg;

    rc = wh_Client_Init(&g_client_ctx, &g_client_cfg);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    g_client_ready = 1;
    if (g_retry_crypto_initialized != 0) {
        (void)wolfCrypt_Cleanup();
        g_retry_crypto_initialized = 0;
    }
    return WH_ERROR_OK;
}

static int wolfhsm_guest_retry(int devId, wc_CryptoInfo *info, void *ctx)
{
    int rc;

    (void)ctx;
#ifdef WOLF_CRYPTO_CB_CMD
    if (info != NULL && info->algo_type == WC_ALGO_TYPE_NONE) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif
    rc = wolfhsm_guest_connect();
    if (rc != WH_ERROR_OK) {
        if (rc == WH_ERROR_NOTREADY) {
            (void)wolfhsm_guest_register_retry();
        }
        return WC_HW_E;
    }
    return wh_Client_CryptoCb(devId, info, &g_client_ctx);
}

static int wolfhsm_guest_register_retry(void)
{
    int rc;
    int initialized = 0;

    if (g_retry_crypto_initialized == 0) {
        rc = wolfCrypt_Init();
        if (rc != 0) {
            return rc;
        }
        g_retry_crypto_initialized = 1;
        initialized = 1;
    }
    if (wc_CryptoCb_IsDeviceRegistered(WH_DEV_ID) != 0) {
        return WH_ERROR_OK;
    }
    rc = wc_CryptoCb_RegisterDevice(WH_DEV_ID, wolfhsm_guest_retry, NULL);
    if (rc != 0 && initialized != 0) {
        (void)wolfCrypt_Cleanup();
        g_retry_crypto_initialized = 0;
    }
    return rc;
}

int wolfhsm_guest_init(void)
{
    int rc;

    rc = wolfhsm_guest_connect();
    if (rc == WH_ERROR_OK) {
        return WH_ERROR_OK;
    }
    if (rc != WH_ERROR_NOTREADY) {
        return rc;
    }
    return wolfhsm_guest_register_retry();
}

whClientContext *wolfhsm_guest_client(void)
{
    return &g_client_ctx;
}

/* Retry initialization for the direct RNG hook if early initialization did
 * not complete. */
static int wolfhsm_guest_ensure_ready(void)
{
    if (g_client_ready != 0) {
        return WH_ERROR_OK;
    }
    return wolfhsm_guest_connect();
}

int wolftrust_guest_rng_stub(unsigned char *output, unsigned int sz)
{
    if (output == NULL && sz != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wolfhsm_guest_ensure_ready() != WH_ERROR_OK) {
        return -1;
    }
    return wh_Client_RngGenerate(&g_client_ctx, output, sz);
}
