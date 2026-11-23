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
#include "wolftrust/zeroize.h"

#include <string.h>

/* Stay within a SHA-256 digest, the smallest GetRandom limit fwTPM may set. */
#define WT_TPM_RNG_CHUNK    32U
#define WT_TPM_RNG_CMD_SZ   12U
#define WT_TPM_RNG_RSP_HDR  12U

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

static uint32_t wt_tpm_be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int wt_tpm_psa_random(uint8_t* out, size_t len)
{
    uint8_t cmd[WT_TPM_RNG_CMD_SZ] = {
        0x80U, 0x01U, 0x00U, 0x00U, 0x00U, (uint8_t)WT_TPM_RNG_CMD_SZ,
        0x00U, 0x00U, 0x01U, 0x7BU, 0x00U, 0x00U
    };
    uint8_t rsp[WT_TPM_RNG_RSP_HDR + WT_TPM_RNG_CHUNK];
    size_t done = 0U;
    size_t chunk;
    size_t got;
    size_t n;
    int rc = 0;

    if (out == NULL || len == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    while (rc == 0 && done < len) {
        chunk = len - done;
        if (chunk > WT_TPM_RNG_CHUNK) {
            chunk = WT_TPM_RNG_CHUNK;
        }
        cmd[11] = (uint8_t)chunk;
        got = 0U;
        rc = wt_tpm_psa_transact(cmd, sizeof(cmd), rsp, sizeof(rsp), &got);
        if (rc == 0) {
            n = (got >= WT_TPM_RNG_RSP_HDR) ?
                (((size_t)rsp[10] << 8) | (size_t)rsp[11]) : 0U;
            if (n == 0U || n > chunk || got != WT_TPM_RNG_RSP_HDR + n ||
                    rsp[0] != 0x80U || rsp[1] != 0x01U ||
                    wt_tpm_be32(rsp + 2) != (uint32_t)got ||
                    wt_tpm_be32(rsp + 6) != 0U) {
                rc = PSA_ERROR_COMMUNICATION_FAILURE;
            }
        }
        if (rc == 0) {
            (void)memcpy(out + done, rsp + WT_TPM_RNG_RSP_HDR, n);
            done += n;
        }
    }
    wt_forceZero(rsp, sizeof(rsp));
    if (rc != 0) {
        wt_forceZero(out, len);
    }
    return rc;
}

#if defined(WOLFTPM_USER_TRANSPORT)
#include <wolftpm/tpm2.h>

static int wt_tpm_user_send(TPM2_CTX* ctx, const BYTE* cmd, UINT32 cmd_sz,
                            BYTE* rsp, UINT32 rsp_max, UINT32* rsp_sz,
                            void* user_ctx)
{
    size_t got = 0U;
    int rc;

    (void)ctx;
    (void)user_ctx;
    rc = wt_tpm_psa_transact(cmd, (size_t)cmd_sz, rsp, (size_t)rsp_max,
                             &got);
    if (rc == 0) {
        *rsp_sz = (UINT32)got;
    }
    return rc;
}

static void wt_tpm_user_close(TPM2_CTX* ctx, void* user_ctx)
{
    (void)ctx;
    (void)user_ctx;
    wt_tpm_psa_close();
}

int wt_tpm_psa_register(void)
{
    return (int)TPM2_SetUserTransport(wt_tpm_user_send, wt_tpm_user_close,
                                      NULL);
}
#endif /* WOLFTPM_USER_TRANSPORT */
