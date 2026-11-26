/* msg_relay.c
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

#include "wolftrust/services/msg_relay.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* A build compiles only the transfer modes its interface uses. */
#if !defined(WT_MSG_RELAY_ONESHOT) && !defined(WT_MSG_RELAY_CHUNKED)
#define WT_MSG_RELAY_ONESHOT 1
#define WT_MSG_RELAY_CHUNKED 1
#endif

#define WT_MSG_SLOT_IDLE       0U
#define WT_MSG_SLOT_RECEIVING  1U
#define WT_MSG_SLOT_PROCESSING 3U
#define WT_MSG_SLOT_DONE       5U

#if defined(WT_MSG_RELAY_TEST_HOOKS)
void wt_msg_relay_test_chunk_zeroized(const void* memory, size_t size,
                                      psa_status_t status);
#endif

static void wt_msg_relay_clear(wt_msg_relay_t* relay)
{
    wt_forceZero(relay->request, relay->capacity);
    wt_forceZero(relay->response, relay->capacity);
    relay->request_len = 0U;
    relay->request_used = 0U;
    relay->response_len = 0U;
    relay->state = WT_MSG_SLOT_IDLE;
}

void wt_msg_relay_set_client(wt_msg_relay_t* relay, int32_t app_client_id)
{
    relay->app_client = app_client_id;
    wt_msg_relay_clear(relay);
}

void wt_msg_relay_set_transport(wt_msg_relay_t* relay, wt_spm_transport_fn fn)
{
    relay->transport = (fn != NULL) ? fn : WT_SPM_TRANSPORT_DEFAULT;
}

void wt_msg_relay_set_provider(wt_msg_relay_t* relay,
                               wt_msg_provider_fn provider, void* context)
{
    relay->provider = provider;
    relay->provider_context = context;
}

/* Drain invec[0] into a bounded private buffer (copied transfers). */
static int wt_msg_relay_read(const wt_msg_relay_t* relay,
                             wt_ffm_runtime_t* runtime, int32_t partition_id,
                             psa_handle_t msg_handle, void* buffer,
                             size_t capacity, size_t* out_len)
{
    wt_spm_call_t call;
    size_t len = 0U;

    for (;;) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_READ;
        call.partition_id = partition_id;
        call.msg_handle = msg_handle;
        call.vec_idx = 0U;
        call.buffer = (uint8_t*)buffer + len;
        call.num_bytes = capacity - len;
        if (relay->transport(runtime, &call) != WT_FFM_SUCCESS) {
            return WT_FFM_ERROR_STATE;
        }
        if (call.ret_size == 0U) {
            break;
        }
        len += call.ret_size;
        if (len >= capacity) {
            break;
        }
    }
    *out_len = len;
    return WT_FFM_SUCCESS;
}

static int wt_msg_relay_write(const wt_msg_relay_t* relay,
                              wt_ffm_runtime_t* runtime, int32_t partition_id,
                              psa_handle_t msg_handle, const void* data,
                              size_t len)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WRITE;
    call.partition_id = partition_id;
    call.msg_handle = msg_handle;
    call.vec_idx = 0U;
    call.buffer = (void*)(uintptr_t)data;
    call.num_bytes = len;
    if (relay->transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

/* Runs the staged request; fails closed on any provider or length error. */
static int wt_msg_relay_run(wt_msg_relay_t* relay, size_t* response_len)
{
    int rc;

    *response_len = 0U;
    rc = relay->provider(relay->request, relay->request_len, relay->response,
                         relay->capacity, response_len,
                         relay->provider_context);
    if (rc != 0 || *response_len == 0U || *response_len > relay->capacity) {
        return -1;
    }
    return 0;
}

#if defined(WT_MSG_RELAY_ONESHOT)
/* invec[0] holds the whole request; outvec[0] must hold the whole response. */
static psa_status_t wt_msg_relay_transact(wt_msg_relay_t* relay,
                                          wt_ffm_runtime_t* runtime,
                                          int32_t partition_id,
                                          const psa_msg_t* msg)
{
    psa_status_t status = PSA_SUCCESS;
    size_t len = 0U;

    if (msg->out_size[0] == 0U || msg->out_size[0] > relay->capacity ||
            msg->in_size[0] == 0U || msg->in_size[0] > relay->capacity) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_msg_relay_read(relay, runtime, partition_id, msg->handle,
                          relay->request, relay->capacity, &len) !=
                WT_FFM_SUCCESS || len != msg->in_size[0]) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (status == PSA_SUCCESS) {
        relay->request_len = (uint32_t)len;
        if (wt_msg_relay_run(relay, &len) != 0) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
    }
    if (status == PSA_SUCCESS && msg->out_size[0] < len) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (status == PSA_SUCCESS &&
            wt_msg_relay_write(relay, runtime, partition_id, msg->handle,
                               relay->response, len) != WT_FFM_SUCCESS) {
        status = PSA_ERROR_GENERIC_ERROR;
    }
    wt_msg_relay_clear(relay);
    return status;
}
#endif

#if defined(WT_MSG_RELAY_CHUNKED)
static psa_status_t wt_msg_relay_read_exact(const wt_msg_relay_t* relay,
                                            wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg, void* data,
                                            size_t len)
{
    size_t got = 0U;

    if (msg->in_size[0] != len ||
            wt_msg_relay_read(relay, runtime, partition_id, msg->handle, data,
                              len, &got) != WT_FFM_SUCCESS || got != len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_msg_relay_write_exact(const wt_msg_relay_t* relay,
                                             wt_ffm_runtime_t* runtime,
                                             int32_t partition_id,
                                             const psa_msg_t* msg,
                                             const void* data, size_t len)
{
    if (msg->out_size[0] < len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (wt_msg_relay_write(relay, runtime, partition_id, msg->handle, data,
                           len) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_msg_relay_begin(wt_msg_relay_t* relay,
                                       wt_ffm_runtime_t* runtime,
                                       int32_t partition_id,
                                       const psa_msg_t* msg)
{
    wt_msg_length_t length;
    psa_status_t status;

    status = wt_msg_relay_read_exact(relay, runtime, partition_id, msg,
                                     &length, sizeof(length));
    if (status != PSA_SUCCESS || length.length == 0U ||
            length.length > relay->capacity) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (relay->state == WT_MSG_SLOT_PROCESSING) {
        return PSA_ERROR_BAD_STATE;
    }
    wt_msg_relay_clear(relay);
    relay->request_len = length.length;
    relay->state = WT_MSG_SLOT_RECEIVING;
    return PSA_SUCCESS;
}

static psa_status_t wt_msg_relay_write_chunk(wt_msg_relay_t* relay,
                                             wt_ffm_runtime_t* runtime,
                                             int32_t partition_id,
                                             const psa_msg_t* msg)
{
    wt_msg_chunk_t chunk;
    size_t frame_len;
    psa_status_t status;

    if (msg->in_size[0] < sizeof(chunk.offset) + sizeof(chunk.length) ||
            msg->in_size[0] > sizeof(chunk)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_forceZero(&chunk, sizeof(chunk));
    status = wt_msg_relay_read_exact(relay, runtime, partition_id, msg,
                                     &chunk, msg->in_size[0]);
    if (status == PSA_SUCCESS) {
        frame_len = sizeof(chunk.offset) + sizeof(chunk.length) + chunk.length;
        if (chunk.length == 0U || chunk.length > WT_MSG_CHUNK_MAX ||
                frame_len != msg->in_size[0]) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    if (status == PSA_SUCCESS && relay->state != WT_MSG_SLOT_RECEIVING) {
        status = PSA_ERROR_BAD_STATE;
    }
    if (status == PSA_SUCCESS &&
            (relay->request_used > relay->request_len ||
             chunk.offset != relay->request_used ||
             chunk.length > relay->request_len - relay->request_used)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (status == PSA_SUCCESS) {
        (void)memcpy(relay->request + relay->request_used, chunk.data,
                     chunk.length);
        relay->request_used += chunk.length;
    }
    wt_forceZero(&chunk, sizeof(chunk));
#if defined(WT_MSG_RELAY_TEST_HOOKS)
    wt_msg_relay_test_chunk_zeroized(&chunk, sizeof(chunk), status);
#endif
    return status;
}

static psa_status_t wt_msg_relay_execute(wt_msg_relay_t* relay,
                                         wt_ffm_runtime_t* runtime,
                                         int32_t partition_id,
                                         const psa_msg_t* msg)
{
    wt_msg_length_t length;
    size_t response_len = 0U;
    psa_status_t status;

    if (msg->in_size[0] != 0U || msg->out_size[0] != sizeof(length)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (relay->state != WT_MSG_SLOT_RECEIVING ||
            relay->request_used != relay->request_len) {
        return PSA_ERROR_BAD_STATE;
    }
    relay->state = WT_MSG_SLOT_PROCESSING;
    if (wt_msg_relay_run(relay, &response_len) != 0) {
        wt_msg_relay_clear(relay);
        return PSA_ERROR_GENERIC_ERROR;
    }
    wt_forceZero(relay->request, relay->capacity);
    relay->request_len = 0U;
    relay->request_used = 0U;
    relay->response_len = (uint32_t)response_len;
    relay->state = WT_MSG_SLOT_DONE;
    length.length = (uint32_t)response_len;
    status = wt_msg_relay_write_exact(relay, runtime, partition_id, msg,
                                      &length, sizeof(length));
    if (status != PSA_SUCCESS) {
        wt_msg_relay_clear(relay);
    }
    return status;
}

static psa_status_t wt_msg_relay_read_chunk(wt_msg_relay_t* relay,
                                            wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg)
{
    wt_msg_range_t range;
    uint32_t total;
    psa_status_t status;

    status = wt_msg_relay_read_exact(relay, runtime, partition_id, msg,
                                     &range, sizeof(range));
    if (status != PSA_SUCCESS || range.length == 0U ||
            range.length > WT_MSG_CHUNK_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (relay->state != WT_MSG_SLOT_DONE) {
        return PSA_ERROR_BAD_STATE;
    }
    total = relay->response_len;
    if (range.offset > total || range.length > total - range.offset) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_msg_relay_write_exact(relay, runtime, partition_id, msg,
                                      relay->response + range.offset,
                                      range.length);
    if (status == PSA_SUCCESS && range.offset + range.length == total) {
        wt_msg_relay_clear(relay);
    }
    return status;
}
#endif

static psa_status_t wt_msg_relay_call(wt_msg_relay_t* relay,
                                      wt_ffm_runtime_t* runtime,
                                      int32_t partition_id,
                                      const psa_msg_t* msg)
{
    if (relay->app_client >= 0 || relay->provider == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (msg->client_id != relay->app_client) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (msg->type == WT_MSG_OP_TRANSACT) {
        if (relay->mode != WT_MSG_RELAY_MODE_ONESHOT) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (relay->mode != WT_MSG_RELAY_MODE_CHUNKED) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    switch (msg->type) {
#if defined(WT_MSG_RELAY_ONESHOT)
        case WT_MSG_OP_TRANSACT:
            return wt_msg_relay_transact(relay, runtime, partition_id, msg);
#endif
#if defined(WT_MSG_RELAY_CHUNKED)
        case WT_MSG_OP_BEGIN:
            return wt_msg_relay_begin(relay, runtime, partition_id, msg);
        case WT_MSG_OP_WRITE:
            return wt_msg_relay_write_chunk(relay, runtime, partition_id, msg);
        case WT_MSG_OP_EXECUTE:
            return wt_msg_relay_execute(relay, runtime, partition_id, msg);
        case WT_MSG_OP_READ:
            return wt_msg_relay_read_chunk(relay, runtime, partition_id, msg);
        case WT_MSG_OP_ABORT:
            if (relay->state == WT_MSG_SLOT_PROCESSING) {
                return PSA_ERROR_BAD_STATE;
            }
            wt_msg_relay_clear(relay);
            return PSA_SUCCESS;
#endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

int wt_msg_relay_dispatch(wt_msg_relay_t* relay, wt_ffm_runtime_t* runtime,
                          int32_t partition_id)
{
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;

    if (wt_spm_wait_service_signal(relay->transport, runtime, partition_id,
                                   &asserted, NULL) != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (asserted == 0U) {
        return WT_FFM_SUCCESS;
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = partition_id;
    call.signal = asserted;
    call.msg = &msg;
    if (relay->transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_status != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (msg.type == PSA_IPC_CONNECT || msg.type == PSA_IPC_DISCONNECT) {
        reply_status = PSA_SUCCESS;
    }
    else {
        reply_status = wt_msg_relay_call(relay, runtime, partition_id, &msg);
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = msg.handle;
    call.status = reply_status;
    if (relay->transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
