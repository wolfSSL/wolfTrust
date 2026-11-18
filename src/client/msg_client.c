/* msg_client.c
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

#include "wolftrust/msg_client.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* A build compiles only the transfer modes its interface uses. */
#if !defined(WT_MSG_RELAY_ONESHOT) && !defined(WT_MSG_RELAY_CHUNKED)
#define WT_MSG_RELAY_ONESHOT 1
#define WT_MSG_RELAY_CHUNKED 1
#endif

static int wt_msg_client_connect(wt_msg_client_t* client)
{
    psa_handle_t handle;

    if (PSA_HANDLE_IS_VALID(client->handle)) {
        return 0;
    }
    handle = psa_connect(client->sid, client->version);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return (int)handle;
    }
    client->handle = handle;
    return 0;
}

void wt_msg_client_close(wt_msg_client_t* client)
{
    if (PSA_HANDLE_IS_VALID(client->handle)) {
        psa_close(client->handle);
    }
    client->handle = PSA_NULL_HANDLE;
}

/* Service recovery errors every connection to a failed partition, so drop the
 * cached handle on these statuses and let the next call reconnect. */
static int wt_msg_client_conn_dead(psa_status_t status)
{
    return status == PSA_ERROR_PROGRAMMER_ERROR ||
           status == PSA_ERROR_CONNECTION_BUSY ||
           status == PSA_ERROR_COMMUNICATION_FAILURE ||
           status == PSA_ERROR_BAD_STATE;
}

static int wt_msg_client_op(wt_msg_client_t* client, int32_t op,
                            const void* in, size_t in_len, void* out,
                            size_t out_len, size_t* actual)
{
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t status;
    int rc;

    rc = wt_msg_client_connect(client);
    if (rc != 0) {
        return rc;
    }
    in_vec.base = in;
    in_vec.len = in_len;
    out_vec.base = out;
    out_vec.len = out_len;
    status = psa_call(client->handle, op,
                      (in != NULL) ? &in_vec : NULL, (in != NULL) ? 1U : 0U,
                      (out != NULL) ? &out_vec : NULL, (out != NULL) ? 1U : 0U);
    if (status == PSA_SUCCESS && actual != NULL) {
        *actual = out_vec.len;
    }
    else if (wt_msg_client_conn_dead(status)) {
        wt_msg_client_close(client);
    }
    return (int)status;
}

#if defined(WT_MSG_RELAY_ONESHOT)
static int wt_msg_client_transact(wt_msg_client_t* client,
                                  const uint8_t* request, size_t request_len,
                                  uint8_t* response, size_t response_cap,
                                  size_t* response_len)
{
    size_t out_len = response_cap;
    size_t actual = 0U;
    int rc;

    if (request_len > client->message_max) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    if (out_len > client->message_max) {
        out_len = client->message_max;
    }
    rc = wt_msg_client_op(client, WT_MSG_OP_TRANSACT, request, request_len,
                          response, out_len, &actual);
    if (rc == 0) {
        if (actual == 0U || actual > out_len) {
            return (int)PSA_ERROR_COMMUNICATION_FAILURE;
        }
        *response_len = actual;
    }
    return rc;
}
#endif

#if defined(WT_MSG_RELAY_CHUNKED)
static int wt_msg_client_push(wt_msg_client_t* client, const uint8_t* message,
                              size_t length)
{
    wt_msg_chunk_t chunk;
    size_t offset = 0U;
    size_t amount;
    int rc;

    while (offset < length) {
        amount = length - offset;
        if (amount > WT_MSG_CHUNK_MAX) {
            amount = WT_MSG_CHUNK_MAX;
        }
        chunk.offset = (uint32_t)offset;
        chunk.length = (uint32_t)amount;
        (void)memcpy(chunk.data, message + offset, amount);
        rc = wt_msg_client_op(client, WT_MSG_OP_WRITE, &chunk,
                              sizeof(chunk.offset) + sizeof(chunk.length) +
                                  amount, NULL, 0U, NULL);
        wt_forceZero(&chunk, sizeof(chunk));
        if (rc != 0) {
            return rc;
        }
        offset += amount;
    }
    return 0;
}

static int wt_msg_client_pull(wt_msg_client_t* client, uint8_t* message,
                              size_t length)
{
    wt_msg_range_t range;
    size_t offset = 0U;
    size_t amount;
    size_t actual;
    int rc;

    while (offset < length) {
        amount = length - offset;
        if (amount > WT_MSG_CHUNK_MAX) {
            amount = WT_MSG_CHUNK_MAX;
        }
        range.offset = (uint32_t)offset;
        range.length = (uint32_t)amount;
        actual = 0U;
        rc = wt_msg_client_op(client, WT_MSG_OP_READ, &range, sizeof(range),
                              message + offset, amount, &actual);
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

static void wt_msg_client_abort(wt_msg_client_t* client)
{
    (void)wt_msg_client_op(client, WT_MSG_OP_ABORT, NULL, 0U, NULL, 0U, NULL);
}

static int wt_msg_client_staged(wt_msg_client_t* client,
                                const uint8_t* request, size_t request_len,
                                uint8_t* response, size_t response_cap,
                                size_t* response_len)
{
    wt_msg_length_t length;
    size_t actual = 0U;
    int rc;

    if (request_len > client->message_max) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    length.length = (uint32_t)request_len;
    rc = wt_msg_client_op(client, WT_MSG_OP_BEGIN, &length, sizeof(length),
                          NULL, 0U, NULL);
    if (rc != 0) {
        return rc;
    }
    rc = wt_msg_client_push(client, request, request_len);
    if (rc == 0) {
        rc = wt_msg_client_op(client, WT_MSG_OP_EXECUTE, NULL, 0U, &length,
                              sizeof(length), &actual);
    }
    if (rc != 0 || actual != sizeof(length)) {
        wt_msg_client_abort(client);
        return (rc != 0) ? rc : (int)PSA_ERROR_COMMUNICATION_FAILURE;
    }
    if (length.length == 0U || length.length > client->message_max ||
            length.length > response_cap) {
        wt_msg_client_abort(client);
        return (int)PSA_ERROR_BUFFER_TOO_SMALL;
    }
    rc = wt_msg_client_pull(client, response, length.length);
    if (rc == 0) {
        *response_len = length.length;
    }
    else {
        wt_msg_client_abort(client);
    }
    return rc;
}
#endif

int wt_msg_client_call(wt_msg_client_t* client, const uint8_t* request,
                       size_t request_len, uint8_t* response,
                       size_t response_cap, size_t* response_len)
{
    if (client == NULL || request == NULL || request_len == 0U ||
            response == NULL || response_cap == 0U || response_len == NULL) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }
    *response_len = 0U;
#if defined(WT_MSG_RELAY_ONESHOT) && defined(WT_MSG_RELAY_CHUNKED)
    if (2U * client->message_max <= WT_MSG_TRANSFER_MAX) {
        return wt_msg_client_transact(client, request, request_len, response,
                                      response_cap, response_len);
    }
    return wt_msg_client_staged(client, request, request_len, response,
                                response_cap, response_len);
#elif defined(WT_MSG_RELAY_ONESHOT)
    return wt_msg_client_transact(client, request, request_len, response,
                                  response_cap, response_len);
#else
    return wt_msg_client_staged(client, request, request_len, response,
                                response_cap, response_len);
#endif
}
