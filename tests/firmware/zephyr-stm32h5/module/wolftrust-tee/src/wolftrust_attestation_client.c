/* wolftrust_attestation_client.c
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

#include <string.h>

#include <psa/initial_attestation.h>
#include <wolftrust/attestation.h>
#include <wolftrust/ffm_veneer.h>

#define WT_SERVICE_ATTEST_SID     4096u
#define WT_SERVICE_ATTEST_VERSION 1u
#define WT_FFM_IPC_CALL           0     /* PSA_IPC_CALL */
/* psa_call types — must match wolftrust/services/attestation_service.h. */
#define WT_ATTEST_OP_TOKEN_SIZE   1
#define WT_ATTEST_OP_PUBLIC_KEY   2

extern int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version);
extern int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                                  wt_ffm_veneer_iovec_t* ns_iovec);
extern void WolfTrust_FFM_Close(int32_t handle);

/* One mediated query round trip (WT-SYS-0014): the retired direct
 * WolfTrust_Attest_* veneers are gone; every attestation request rides
 * psa_connect/psa_call to SERVICE_ATTEST. */
static psa_status_t wt_attest_ipc_query(int32_t type, const void* in,
    size_t in_len, void* out, size_t out_len, size_t* out_got)
{
    wt_ffm_veneer_iovec_t iovec;
    int32_t handle;
    int32_t status;

    handle = WolfTrust_FFM_Connect(WT_SERVICE_ATTEST_SID,
                                   WT_SERVICE_ATTEST_VERSION);
    if (handle < 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    memset(&iovec, 0, sizeof(iovec));
    iovec.in[0].base = in;
    iovec.in[0].len = (uint32_t)in_len;
    iovec.out[0].base = out;
    iovec.out[0].len = (uint32_t)out_len;
    iovec.in_count = (in != NULL) ? 1u : 0u;
    iovec.out_count = 1u;
    status = WolfTrust_FFM_Call(handle, type, &iovec);
    WolfTrust_FFM_Close(handle);
    if (status != 0) {
        return (psa_status_t)status;
    }
    if (out_got != NULL) {
        *out_got = iovec.out[0].len;
    }
    return PSA_SUCCESS;
}

psa_status_t psa_initial_attest_get_token(const uint8_t* authChallenge,
    size_t challengeSize, uint8_t* token, size_t tokenCapacity,
    size_t* tokenSize)
{
    wt_ffm_veneer_iovec_t iovec;
    size_t exactSize = 0u;
    int32_t handle;
    int32_t status;
    int rc;

    if ((authChallenge == NULL) || (tokenSize == NULL) || (token == NULL)) {
        if (tokenSize != NULL) {
            *tokenSize = 0u;
        }
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *tokenSize = 0u;

    /* The COSE_Sign1 token length is deterministic, so the mediated size
     * query gives the exact transfer size for the output vector. */
    rc = (int)psa_initial_attest_get_token_size(challengeSize, &exactSize);
    if (rc != 0) {
        return (psa_status_t)rc;
    }
    if (exactSize > tokenCapacity) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    handle = WolfTrust_FFM_Connect(WT_SERVICE_ATTEST_SID,
                                   WT_SERVICE_ATTEST_VERSION);
    if (handle < 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    memset(&iovec, 0, sizeof(iovec));
    iovec.in[0].base = authChallenge;
    iovec.in[0].len = (uint32_t)challengeSize;
    iovec.out[0].base = token;
    iovec.out[0].len = (uint32_t)exactSize;
    iovec.in_count = 1u;
    iovec.out_count = 1u;
    status = WolfTrust_FFM_Call(handle, WT_FFM_IPC_CALL, &iovec);
    WolfTrust_FFM_Close(handle);
    if (status != 0) {
        return (psa_status_t)status;
    }

    *tokenSize = exactSize;
    return PSA_SUCCESS;
}

psa_status_t psa_initial_attest_get_token_size(size_t challengeSize,
    size_t* tokenSize)
{
    uint32_t challenge32 = (uint32_t)challengeSize;
    uint32_t token32 = 0u;
    psa_status_t st;

    if (tokenSize == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    st = wt_attest_ipc_query(WT_ATTEST_OP_TOKEN_SIZE, &challenge32,
                             sizeof(challenge32), &token32, sizeof(token32),
                             NULL);
    if (st != PSA_SUCCESS) {
        return st;
    }
    *tokenSize = token32;
    return PSA_SUCCESS;
}

psa_status_t wolftrust_attestation_get_iak_public_key(uint8_t* publicKey,
    size_t publicKeyCapacity, size_t* publicKeySize)
{
    size_t got = 0u;
    psa_status_t st;

    if (publicKey == NULL || publicKeySize == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    st = wt_attest_ipc_query(WT_ATTEST_OP_PUBLIC_KEY, NULL, 0u, publicKey,
                             publicKeyCapacity, &got);
    if (st != PSA_SUCCESS) {
        return st;
    }
    *publicKeySize = got;
    return PSA_SUCCESS;
}
