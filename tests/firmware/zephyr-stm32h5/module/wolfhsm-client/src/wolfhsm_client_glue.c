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

int wolfhsm_guest_init(void)
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
    return WH_ERROR_OK;
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
    return wolfhsm_guest_init();
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
