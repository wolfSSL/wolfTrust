/* hsm_psa_transport.c
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

/* OS-neutral wolfHSM client transport over the FF-M SPM (WT-FFM-0054).
 * Built on the neutral PSA client core (psa_ffm_client.c), so every wolfHSM
 * wire packet is one mediated, synchronous psa_call to SERVICE_HSM. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "psa/client.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/hsm_psa_transport.h"
#include "wolftrust/zeroize.h"

static void wt_hsm_psa_clear_response(wt_hsm_psa_transport_ctx_t* ctx)
{
    wt_forceZero(ctx->resp, sizeof(ctx->resp));
    ctx->resp_len = 0U;
    ctx->has_resp = 0U;
}

static int wt_hsm_psa_init(void* ctx_v, const void* cfg_v,
                           whCommSetConnectedCb connectcb,
                           void* connectcb_arg)
{
    wt_hsm_psa_transport_ctx_t* ctx = (wt_hsm_psa_transport_ctx_t*)ctx_v;
    const wt_hsm_psa_transport_cfg_t* cfg =
        (const wt_hsm_psa_transport_cfg_t*)cfg_v;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    wt_hsm_psa_clear_response(ctx);
    ctx->handle = 0;
    if (cfg == NULL) {
        return WH_ERROR_BADARGS;
    }
    ctx->handle = (int32_t)psa_connect(cfg->sid, cfg->version);
    if (ctx->handle == (int32_t)PSA_ERROR_CONNECTION_BUSY ||
            ctx->handle == (int32_t)PSA_ERROR_GENERIC_ERROR) {
        return WH_ERROR_NOTREADY;
    }
    if (ctx->handle <= 0) {
        return WH_ERROR_ABORTED;
    }
    if (connectcb != NULL) {
        connectcb(connectcb_arg, WH_COMM_CONNECTED);
    }
    return WH_ERROR_OK;
}

static int wt_hsm_psa_cleanup(void* ctx_v)
{
    wt_hsm_psa_transport_ctx_t* ctx = (wt_hsm_psa_transport_ctx_t*)ctx_v;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->handle > 0) {
        psa_close((psa_handle_t)ctx->handle);
    }
    ctx->handle = 0;
    wt_hsm_psa_clear_response(ctx);
    return WH_ERROR_OK;
}

/* One packet, one mediated round trip: the SPM copies the request in, the
 * relay runs the server to completion, and the response lands in resp before
 * psa_call returns — each chunk of a multi-packet operation fully completes
 * before the client can send the next. */
static int wt_hsm_psa_send(void* ctx_v, uint16_t data_size, const void* data)
{
    wt_hsm_psa_transport_ctx_t* ctx = (wt_hsm_psa_transport_ctx_t*)ctx_v;
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t status;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (data == NULL || ctx->handle <= 0 || data_size == 0U ||
            data_size > WT_HSM_RELAY_MSG_MAX) {
        wt_hsm_psa_clear_response(ctx);
        return WH_ERROR_BADARGS;
    }
    wt_hsm_psa_clear_response(ctx);
    in_vec.base = data;
    in_vec.len = data_size;
    out_vec.base = ctx->resp;
    out_vec.len = sizeof(ctx->resp);
    status = psa_call((psa_handle_t)ctx->handle, PSA_IPC_CALL, &in_vec, 1U,
                      &out_vec, 1U);
    if (status != PSA_SUCCESS || out_vec.len == 0U ||
            out_vec.len > sizeof(ctx->resp)) {
        wt_hsm_psa_clear_response(ctx);
        return WH_ERROR_ABORTED;
    }
    ctx->resp_len = (uint16_t)out_vec.len;
    ctx->has_resp = 1U;
    return WH_ERROR_OK;
}

static int wt_hsm_psa_recv(void* ctx_v, uint16_t* out_size, void* data)
{
    wt_hsm_psa_transport_ctx_t* ctx = (wt_hsm_psa_transport_ctx_t*)ctx_v;

    if (ctx == NULL || out_size == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->has_resp == 0U) {
        return WH_ERROR_NOTREADY;
    }
    (void)memcpy(data, ctx->resp, ctx->resp_len);
    *out_size = ctx->resp_len;
    wt_hsm_psa_clear_response(ctx);
    return WH_ERROR_OK;
}

const whTransportClientCb wt_hsm_psa_transport_cb = {
    .Init    = wt_hsm_psa_init,
    .Send    = wt_hsm_psa_send,
    .Recv    = wt_hsm_psa_recv,
    .Cleanup = wt_hsm_psa_cleanup,
};
