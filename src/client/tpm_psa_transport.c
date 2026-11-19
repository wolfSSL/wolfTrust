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
#include "wolftrust/msg_client.h"

static wt_msg_client_t g_tpm_client = WT_MSG_CLIENT_INIT(WT_TPM_SERVICE_SID,
    WT_TPM_SERVICE_VERSION, WT_TPM_FRAME_MAX);

void wt_tpm_psa_close(void)
{
    wt_msg_client_close(&g_tpm_client);
}

int wt_tpm_psa_transact(const uint8_t* command, size_t command_len,
                        uint8_t* response, size_t response_cap,
                        size_t* response_len)
{
    return wt_msg_client_call(&g_tpm_client, command, command_len, response,
                              response_cap, response_len);
}

#if defined(WOLFTPM_SWTPM)
/* wolfTPM client transport: built with WOLFTPM_SWTPM so the core routes
 * every command through TPM2_SWTPM_SendCommand, which this file provides in
 * place of the socket client. One synchronous call returns the response. */
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_tis.h>
#include <wolftpm/tpm2_swtpm.h>

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
    int rc;

    (void)ctx;
    if (packet == NULL || packet->buf == NULL || packet->pos <= 0 ||
            packet->size <= 0 || packet->pos > packet->size) {
        return BAD_FUNC_ARG;
    }
    rc = wt_tpm_psa_transact(packet->buf, (size_t)packet->pos, packet->buf,
                            (size_t)packet->size, &rsp_len);
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
