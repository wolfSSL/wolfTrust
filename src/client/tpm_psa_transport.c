/* tpm_psa_transport.c
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

#include "wolftrust/tpm_psa_transport.h"
#include "psa/client.h"

static psa_handle_t g_tpm_handle = PSA_NULL_HANDLE;

static int wt_tpm_psa_connect(void)
{
    psa_handle_t handle;

    if (PSA_HANDLE_IS_VALID(g_tpm_handle)) {
        return 0;
    }
    handle = psa_connect(WT_TPM_SERVICE_SID, WT_TPM_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return (int)handle;
    }
    g_tpm_handle = handle;
    return 0;
}

void wt_tpm_psa_close(void)
{
    if (PSA_HANDLE_IS_VALID(g_tpm_handle)) {
        psa_close(g_tpm_handle);
    }
    g_tpm_handle = PSA_NULL_HANDLE;
}

/* Statuses that mean the cached connection is dead: service recovery marks
 * every connection to the failed partition as errored, so close the handle on
 * the first such status and let the next call reconnect, keeping the public
 * header's promise that a lost connection reopens on the next call. */
static int wt_tpm_psa_conn_dead(psa_status_t st)
{
    return st == PSA_ERROR_PROGRAMMER_ERROR ||
           st == PSA_ERROR_CONNECTION_BUSY ||
           st == PSA_ERROR_COMMUNICATION_FAILURE ||
           st == PSA_ERROR_BAD_STATE;
}

/* One frame inbound to the relay: SUBMIT or RESPOND. */
static int wt_tpm_psa_send(int32_t op, const uint8_t* frame, size_t len)
{
    psa_invec in;
    psa_status_t st;
    int rc;

    if (frame == NULL || len == 0U || len > WT_TPM_FRAME_MAX) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    rc = wt_tpm_psa_connect();
    if (rc != 0) {
        return rc;
    }
    in.base = frame;
    in.len = len;
    st = psa_call(g_tpm_handle, op, &in, 1U, NULL, 0U);
    if (wt_tpm_psa_conn_dead(st)) {
        wt_tpm_psa_close();
    }
    return (int)st;
}

/* One frame outbound from the relay: POLL or FETCH. */
static int wt_tpm_psa_recv(int32_t op, uint8_t* frame, size_t cap,
                           size_t* out_len)
{
    psa_outvec out;
    psa_status_t st;
    int rc;

    if (frame == NULL || cap == 0U || out_len == NULL) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    rc = wt_tpm_psa_connect();
    if (rc != 0) {
        return rc;
    }
    if (cap > WT_TPM_FRAME_MAX) {
        cap = WT_TPM_FRAME_MAX;
    }
    out.base = frame;
    out.len = cap;
    st = psa_call(g_tpm_handle, op, NULL, 0U, &out, 1U);
    if (st == PSA_SUCCESS) {
        *out_len = out.len;
    }
    else if (wt_tpm_psa_conn_dead(st)) {
        wt_tpm_psa_close();
    }
    return (int)st;
}

int wt_tpm_psa_submit(const uint8_t* cmd, size_t cmd_len)
{
    return wt_tpm_psa_send(WT_TPM_OP_SUBMIT, cmd, cmd_len);
}

int wt_tpm_psa_poll(uint8_t* resp, size_t resp_cap, size_t* resp_len)
{
    return wt_tpm_psa_recv(WT_TPM_OP_POLL, resp, resp_cap, resp_len);
}

int wt_tpm_psa_fetch(uint8_t* cmd, size_t cmd_cap, size_t* cmd_len)
{
    return wt_tpm_psa_recv(WT_TPM_OP_FETCH, cmd, cmd_cap, cmd_len);
}

int wt_tpm_psa_respond(const uint8_t* resp, size_t resp_len)
{
    return wt_tpm_psa_send(WT_TPM_OP_RESPOND, resp, resp_len);
}

#if defined(WOLFTPM_SWTPM)
/* wolfTPM client transport: built with WOLFTPM_SWTPM so the core routes
 * every command through TPM2_SWTPM_SendCommand, which this file provides in
 * place of the socket client. The whole command rides SUBMIT, then the
 * caller spins on POLL until the fwTPM partition has posted the response. */
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_tis.h>
#include <wolftpm/tpm2_swtpm.h>

#ifndef WT_TPM_POLL_LIMIT
#define WT_TPM_POLL_LIMIT 2000000U
#endif

/* The core still runs its TIS chip-startup sequence; the mediated door has
 * no TIS registers, so startup wait, locality, and device info are no-ops. */
int TPM2_TIS_StartupWait(TPM2_CTX* ctx, int timeout)
{
    (void)ctx;
    (void)timeout;
    return TPM_RC_SUCCESS;
}

int TPM2_TIS_RequestLocality(TPM2_CTX* ctx, int timeout)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    (void)timeout;
    ctx->locality = WOLFTPM_LOCALITY_DEFAULT;
    return TPM_RC_SUCCESS;
}

int TPM2_TIS_GetInfo(TPM2_CTX* ctx)
{
    (void)ctx;
    return TPM_RC_SUCCESS;
}

void TPM2_SwtpmClose(TPM2_CTX* ctx)
{
    (void)ctx;
    wt_tpm_psa_close();
}

int TPM2_SWTPM_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    size_t rsp_len = 0U;
    uint32_t declared;
    uint32_t tries;
    int rc;

    (void)ctx;
    if (packet == NULL || packet->buf == NULL || packet->pos <= 0 ||
            packet->size <= 0 || packet->pos > packet->size) {
        return BAD_FUNC_ARG;
    }
    rc = wt_tpm_psa_submit(packet->buf, (size_t)packet->pos);
    if (rc != 0) {
        return TPM_RC_FAILURE;
    }
    for (tries = 0U; tries < WT_TPM_POLL_LIMIT; tries++) {
        rc = wt_tpm_psa_poll(packet->buf, (size_t)packet->size, &rsp_len);
        if (rc != WT_TPM_E_BUSY) {
            break;
        }
    }
    if (rc != 0 || rsp_len < (size_t)TPM2_HEADER_SIZE ||
            rsp_len > (size_t)packet->size) {
        return TPM_RC_FAILURE;
    }
    /* The response header declares its own total length; reject a mediated
     * frame whose body length disagrees rather than let the core parse stale
     * buffer tail past the bytes actually received. */
    declared = ((uint32_t)packet->buf[2] << 24) |
               ((uint32_t)packet->buf[3] << 16) |
               ((uint32_t)packet->buf[4] << 8)  |
               (uint32_t)packet->buf[5];
    if (declared != (uint32_t)rsp_len) {
        return TPM_RC_FAILURE;
    }
    /* Bind the parser to the bytes actually received. */
    packet->size = (int)rsp_len;
    return TPM_RC_SUCCESS;
}
#endif /* WOLFTPM_SWTPM */
