/* pkcs11_psa_transport.c
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

#include "wolftrust/pkcs11_psa_transport.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/zeroize.h"

#include "psa/client.h"

#include <string.h>

#ifndef WT_PKCS11_POLL_LIMIT
#define WT_PKCS11_POLL_LIMIT 2000000U
#endif

static psa_handle_t g_pkcs11_handle = PSA_NULL_HANDLE;

static int wt_pkcs11_conn_dead(psa_status_t status)
{
    return status == PSA_ERROR_PROGRAMMER_ERROR ||
           status == PSA_ERROR_CONNECTION_BUSY ||
           status == PSA_ERROR_COMMUNICATION_FAILURE ||
           status == PSA_ERROR_BAD_STATE;
}

static int wt_pkcs11_connect(void)
{
    psa_handle_t handle;

    if (PSA_HANDLE_IS_VALID(g_pkcs11_handle)) {
        return 0;
    }
    handle = psa_connect(WT_PKCS11_SERVICE_SID,
                         WT_PKCS11_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return (int)handle;
    }
    g_pkcs11_handle = handle;
    return 0;
}

void wt_pkcs11_psa_close(void)
{
    if (PSA_HANDLE_IS_VALID(g_pkcs11_handle)) {
        psa_close(g_pkcs11_handle);
    }
    g_pkcs11_handle = PSA_NULL_HANDLE;
}

static int wt_pkcs11_call(int32_t op, const void* in, size_t in_len,
                          void* out, size_t out_len, size_t* actual)
{
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t status;
    int rc;

    rc = wt_pkcs11_connect();
    if (rc != 0) {
        return rc;
    }
    in_vec.base = in;
    in_vec.len = in_len;
    out_vec.base = out;
    out_vec.len = out_len;
    status = psa_call(g_pkcs11_handle, op,
                      (in != NULL) ? &in_vec : NULL,
                      (in != NULL) ? 1U : 0U,
                      (out != NULL) ? &out_vec : NULL,
                      (out != NULL) ? 1U : 0U);
    if (status == PSA_SUCCESS && actual != NULL) {
        *actual = out_vec.len;
    }
    else if (wt_pkcs11_conn_dead(status)) {
        wt_pkcs11_psa_close();
    }
    return (int)status;
}

static int wt_pkcs11_begin(int32_t op, size_t length)
{
    wt_pkcs11_length_t message;

    if (length == 0U || length > WT_PKCS11_MESSAGE_MAX) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    message.length = (uint32_t)length;
    return wt_pkcs11_call(op, &message, sizeof(message), NULL, 0U, NULL);
}

static int wt_pkcs11_push(int32_t op, const uint8_t* message, size_t length)
{
    wt_pkcs11_chunk_t chunk;
    size_t offset = 0U;
    size_t amount;
    int rc;

    while (offset < length) {
        amount = length - offset;
        if (amount > WT_PKCS11_CHUNK_MAX) {
            amount = WT_PKCS11_CHUNK_MAX;
        }
        chunk.offset = (uint32_t)offset;
        chunk.length = (uint32_t)amount;
        (void)memcpy(chunk.data, message + offset, amount);
        rc = wt_pkcs11_call(op, &chunk,
                            sizeof(chunk.offset) + sizeof(chunk.length) +
                                amount,
                            NULL, 0U, NULL);
        wt_forceZero(&chunk, sizeof(chunk));
        if (rc != 0) {
            return rc;
        }
        offset += amount;
    }
    return 0;
}

static int wt_pkcs11_pull(int32_t op, uint8_t* message, size_t length)
{
    wt_pkcs11_range_t range;
    size_t offset = 0U;
    size_t amount;
    size_t actual;
    int rc;

    while (offset < length) {
        amount = length - offset;
        if (amount > WT_PKCS11_CHUNK_MAX) {
            amount = WT_PKCS11_CHUNK_MAX;
        }
        range.offset = (uint32_t)offset;
        range.length = (uint32_t)amount;
        actual = 0U;
        rc = wt_pkcs11_call(op, &range, sizeof(range), message + offset,
                            amount, &actual);
        if (rc != 0) {
            return rc;
        }
        if (actual != amount) {
            return (int)PSA_ERROR_COMMUNICATION_FAILURE;
        }
        offset += amount;
    }
    return 0;
}

static void wt_pkcs11_abort(void)
{
    (void)wt_pkcs11_call(WT_PKCS11_OP_APP_ABORT, NULL, 0U, NULL, 0U, NULL);
}

static int wt_pkcs11_provider_abort(void)
{
    uint32_t tries;
    int rc = (int)PSA_ERROR_COMMUNICATION_FAILURE;

    for (tries = 0U; tries < 2U; tries++) {
        rc = wt_pkcs11_call(WT_PKCS11_OP_PROVIDER_ABORT, NULL, 0U, NULL, 0U,
                            NULL);
        if (rc == 0 || wt_pkcs11_conn_dead((psa_status_t)rc) == 0) {
            break;
        }
    }
    return rc;
}

int wt_pkcs11_psa_call(const uint8_t* request, size_t request_len,
                       uint8_t* response, size_t response_cap,
                       size_t* response_len)
{
    wt_pkcs11_length_t length;
    size_t actual = 0U;
    uint32_t tries;
    int rc;

    if (request == NULL || request_len == 0U || response == NULL ||
            response_cap == 0U || response_len == NULL) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    *response_len = 0U;
    rc = wt_pkcs11_begin(WT_PKCS11_OP_APP_BEGIN, request_len);
    if (rc != 0) {
        return rc;
    }
    rc = wt_pkcs11_push(WT_PKCS11_OP_APP_WRITE, request, request_len);
    if (rc == 0) {
        rc = wt_pkcs11_call(WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL, 0U,
                            NULL);
    }
    if (rc != 0) {
        wt_pkcs11_abort();
        return rc;
    }
    /* Each PSA call enters the SPM scheduler, allowing the provider guest to
     * advance before the next bounded poll. No client-side delay is needed;
     * the limit is a liveness backstop for a wedged provider, not a latency
     * tuning parameter. */
    for (tries = 0U; tries < WT_PKCS11_POLL_LIMIT; tries++) {
        actual = 0U;
        rc = wt_pkcs11_call(WT_PKCS11_OP_APP_POLL, NULL, 0U, &length,
                            sizeof(length), &actual);
        if (rc != WT_PKCS11_E_BUSY) {
            break;
        }
    }
    if (rc != 0 || actual != sizeof(length)) {
        wt_pkcs11_abort();
        return (rc != 0) ? rc : (int)PSA_ERROR_COMMUNICATION_FAILURE;
    }
    if (length.length == 0U || length.length > WT_PKCS11_MESSAGE_MAX ||
            length.length > response_cap) {
        wt_pkcs11_abort();
        return (int)PSA_ERROR_BUFFER_TOO_SMALL;
    }
    rc = wt_pkcs11_pull(WT_PKCS11_OP_APP_READ, response, length.length);
    if (rc == 0) {
        *response_len = length.length;
    }
    else {
        wt_pkcs11_abort();
    }
    return rc;
}

int wt_pkcs11_psa_provider_step(uint8_t* request, size_t request_cap,
                                uint8_t* response, size_t response_cap,
                                wt_pkcs11_dispatch_fn dispatch,
                                void* context)
{
    wt_pkcs11_length_t length;
    size_t response_len = 0U;
    size_t actual = 0U;
    int rc;

    if (request == NULL || request_cap == 0U || response == NULL ||
            response_cap == 0U || dispatch == NULL) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_forceZero(request, request_cap);
    wt_forceZero(response, response_cap);
    rc = wt_pkcs11_call(WT_PKCS11_OP_PROVIDER_FETCH, NULL, 0U, &length,
                        sizeof(length), &actual);
    if (rc == (int)PSA_ERROR_BAD_STATE) {
        int abort_rc = wt_pkcs11_provider_abort();

        return abort_rc != 0 ? abort_rc : rc;
    }
    if (rc != 0) {
        return rc;
    }
    if (actual != sizeof(length) || length.length == 0U ||
            length.length > WT_PKCS11_MESSAGE_MAX ||
            length.length > request_cap) {
        rc = (int)PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (rc == 0) {
        rc = wt_pkcs11_pull(WT_PKCS11_OP_PROVIDER_READ, request,
                            length.length);
    }
    if (rc == 0) {
        rc = dispatch(request, length.length, response, response_cap,
                      &response_len, context);
    }
    if (rc == 0 && (response_len == 0U ||
            response_len > WT_PKCS11_MESSAGE_MAX ||
            response_len > response_cap)) {
        rc = (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_forceZero(request, request_cap);
    if (rc == 0) {
        rc = wt_pkcs11_begin(WT_PKCS11_OP_PROVIDER_BEGIN, response_len);
    }
    if (rc == 0) {
        rc = wt_pkcs11_push(WT_PKCS11_OP_PROVIDER_WRITE, response,
                            response_len);
    }
    if (rc == 0) {
        rc = wt_pkcs11_call(WT_PKCS11_OP_PROVIDER_COMMIT, NULL, 0U, NULL,
                            0U, NULL);
    }
    if (rc != 0) {
        int abort_rc = wt_pkcs11_provider_abort();

        if (abort_rc != 0) {
            rc = abort_rc;
        }
    }
    wt_forceZero(response, response_cap);
    return rc;
}
