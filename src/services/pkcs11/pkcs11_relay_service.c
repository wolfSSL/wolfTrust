/* pkcs11_relay_service.c
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

#include "wolftrust/services/pkcs11_relay.h"
#include "wolftrust/zeroize.h"

#include <string.h>

#define WT_PKCS11_SLOT_IDLE       0U
#define WT_PKCS11_SLOT_RECEIVING  1U
#define WT_PKCS11_SLOT_READY      2U
#define WT_PKCS11_SLOT_PROCESSING 3U
#define WT_PKCS11_SLOT_RESPONDING 4U
#define WT_PKCS11_SLOT_DONE       5U

static int32_t g_relay_app_client;
static int32_t g_relay_provider_client;
static wt_spm_transport_fn g_relay_transport = wt_spm_transport_direct;
static wt_pkcs11_local_provider_fn g_local_provider;
static void* g_local_provider_context;

#if defined(WT_PKCS11_TEST_HOOKS)
void wt_pkcs11_test_relay_chunk_zeroized(const void* memory, size_t size,
                                         psa_status_t status);
#endif

static struct {
    uint8_t request[WT_PKCS11_MESSAGE_MAX];
    uint8_t response[WT_PKCS11_MESSAGE_MAX];
    uint32_t request_len;
    uint32_t request_used;
    uint32_t response_len;
    uint32_t response_used;
    uint8_t state;
} g_relay_slot;

#if defined(WT_PKCS11_NEG_PROBE) && (WT_PKCS11_NEG_PROBE == 1)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_pkcs11_relay_restart_probe)
#endif

void wt_pkcs11_relay_set_roles(int32_t app_client_id,
                               int32_t provider_client_id)
{
    g_relay_app_client = app_client_id;
    g_relay_provider_client = provider_client_id;
    wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
}

void wt_pkcs11_relay_set_transport(wt_spm_transport_fn fn)
{
    g_relay_transport = (fn != NULL) ? fn : wt_spm_transport_direct;
}

void wt_pkcs11_relay_set_local_provider(
    wt_pkcs11_local_provider_fn provider, void* context)
{
    g_local_provider = provider;
    g_local_provider_context = context;
}

static int wt_pkcs11_read(wt_ffm_runtime_t* runtime, int32_t partition_id,
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
        if (g_relay_transport(runtime, &call) != WT_FFM_SUCCESS) {
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

static int wt_pkcs11_write(wt_ffm_runtime_t* runtime, int32_t partition_id,
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
    if (g_relay_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static psa_status_t wt_pkcs11_read_exact(wt_ffm_runtime_t* runtime,
                                         int32_t partition_id,
                                         const psa_msg_t* msg, void* data,
                                         size_t len)
{
    size_t got = 0U;

    if (msg->in_size[0] != len ||
            wt_pkcs11_read(runtime, partition_id, msg->handle, data, len,
                           &got) != WT_FFM_SUCCESS || got != len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_pkcs11_write_exact(wt_ffm_runtime_t* runtime,
                                          int32_t partition_id,
                                          const psa_msg_t* msg,
                                          const void* data, size_t len)
{
    if (msg->out_size[0] < len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (wt_pkcs11_write(runtime, partition_id, msg->handle, data, len) !=
            WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_pkcs11_begin(wt_ffm_runtime_t* runtime,
                                    int32_t partition_id,
                                    const psa_msg_t* msg, int provider)
{
    wt_pkcs11_length_t length;
    psa_status_t status;

    status = wt_pkcs11_read_exact(runtime, partition_id, msg, &length,
                                  sizeof(length));
    if (status != PSA_SUCCESS || length.length == 0U ||
            length.length > WT_PKCS11_MESSAGE_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (provider != 0) {
        if (g_relay_slot.state != WT_PKCS11_SLOT_PROCESSING) {
            return PSA_ERROR_BAD_STATE;
        }
        wt_forceZero(g_relay_slot.response, sizeof(g_relay_slot.response));
        g_relay_slot.response_len = length.length;
        g_relay_slot.response_used = 0U;
        g_relay_slot.state = WT_PKCS11_SLOT_RESPONDING;
    }
    else {
        if (g_relay_slot.state == WT_PKCS11_SLOT_PROCESSING ||
                g_relay_slot.state == WT_PKCS11_SLOT_RESPONDING) {
            return (psa_status_t)WT_PKCS11_E_BUSY;
        }
        wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
        g_relay_slot.request_len = length.length;
        g_relay_slot.state = WT_PKCS11_SLOT_RECEIVING;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_pkcs11_write_chunk(wt_ffm_runtime_t* runtime,
                                          int32_t partition_id,
                                          const psa_msg_t* msg, int provider)
{
    wt_pkcs11_chunk_t chunk;
    uint8_t* dst;
    uint32_t* used;
    uint32_t total;
    size_t frame_len;
    psa_status_t status;

    if (msg->in_size[0] < sizeof(chunk.offset) + sizeof(chunk.length) ||
            msg->in_size[0] > sizeof(chunk)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_forceZero(&chunk, sizeof(chunk));
    status = wt_pkcs11_read_exact(runtime, partition_id, msg, &chunk,
                                  msg->in_size[0]);
    if (status == PSA_SUCCESS) {
        frame_len = sizeof(chunk.offset) + sizeof(chunk.length) + chunk.length;
        if (chunk.length == 0U || chunk.length > WT_PKCS11_CHUNK_MAX ||
                frame_len != msg->in_size[0]) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    if (status == PSA_SUCCESS) {
        if (provider != 0) {
            if (g_relay_slot.state != WT_PKCS11_SLOT_RESPONDING) {
                status = PSA_ERROR_BAD_STATE;
            }
            else {
                dst = g_relay_slot.response;
                used = &g_relay_slot.response_used;
                total = g_relay_slot.response_len;
            }
        }
        else if (g_relay_slot.state != WT_PKCS11_SLOT_RECEIVING) {
            status = PSA_ERROR_BAD_STATE;
        }
        else {
            dst = g_relay_slot.request;
            used = &g_relay_slot.request_used;
            total = g_relay_slot.request_len;
        }
    }
    if (status == PSA_SUCCESS) {
        if (*used > total || chunk.offset != *used ||
                chunk.length > total - *used) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    if (status == PSA_SUCCESS) {
        (void)memcpy(dst + *used, chunk.data, chunk.length);
        *used += chunk.length;
    }

    wt_forceZero(&chunk, sizeof(chunk));
#if defined(WT_PKCS11_TEST_HOOKS)
    wt_pkcs11_test_relay_chunk_zeroized(&chunk, sizeof(chunk), status);
#endif
    return status;
}

static psa_status_t wt_pkcs11_commit(int provider)
{
    if (provider != 0) {
        if (g_relay_slot.state != WT_PKCS11_SLOT_RESPONDING ||
                g_relay_slot.response_used != g_relay_slot.response_len) {
            return PSA_ERROR_BAD_STATE;
        }
        wt_forceZero(g_relay_slot.request, sizeof(g_relay_slot.request));
        g_relay_slot.request_len = 0U;
        g_relay_slot.request_used = 0U;
        g_relay_slot.state = WT_PKCS11_SLOT_DONE;
    }
    else {
        if (g_relay_slot.state != WT_PKCS11_SLOT_RECEIVING ||
                g_relay_slot.request_used != g_relay_slot.request_len) {
            return PSA_ERROR_BAD_STATE;
        }
        g_relay_slot.state = WT_PKCS11_SLOT_READY;
        if (g_local_provider != NULL) {
            size_t response_len = 0U;
            int rc;

            g_relay_slot.state = WT_PKCS11_SLOT_PROCESSING;
            rc = g_local_provider(g_relay_slot.request,
                g_relay_slot.request_len, g_relay_slot.response,
                sizeof(g_relay_slot.response), &response_len,
                g_local_provider_context);
            if (rc != 0 || response_len == 0U ||
                    response_len > sizeof(g_relay_slot.response)) {
                wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
                return PSA_ERROR_GENERIC_ERROR;
            }
            g_relay_slot.response_len = (uint32_t)response_len;
            g_relay_slot.response_used = (uint32_t)response_len;
            wt_forceZero(g_relay_slot.request,
                         sizeof(g_relay_slot.request));
            g_relay_slot.request_len = 0U;
            g_relay_slot.request_used = 0U;
            g_relay_slot.state = WT_PKCS11_SLOT_DONE;
        }
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_pkcs11_report_length(wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg,
                                            int provider)
{
    wt_pkcs11_length_t length;

    if (provider != 0) {
        /* Once a provider has fetched a request, replay could repeat a
         * state-changing PKCS11 operation. Report the indeterminate state so
         * the reconnected provider aborts it instead of dispatching twice. */
        if (g_relay_slot.state == WT_PKCS11_SLOT_PROCESSING ||
                g_relay_slot.state == WT_PKCS11_SLOT_RESPONDING) {
            return PSA_ERROR_BAD_STATE;
        }
        if (g_relay_slot.state != WT_PKCS11_SLOT_READY) {
            return (psa_status_t)WT_PKCS11_E_EMPTY;
        }
        length.length = g_relay_slot.request_len;
        g_relay_slot.state = WT_PKCS11_SLOT_PROCESSING;
    }
    else {
        if (g_relay_slot.state == WT_PKCS11_SLOT_IDLE) {
            return (psa_status_t)WT_PKCS11_E_EMPTY;
        }
        if (g_relay_slot.state != WT_PKCS11_SLOT_DONE) {
            return (psa_status_t)WT_PKCS11_E_BUSY;
        }
        length.length = g_relay_slot.response_len;
    }
    return wt_pkcs11_write_exact(runtime, partition_id, msg, &length,
                                 sizeof(length));
}

static psa_status_t wt_pkcs11_read_chunk(wt_ffm_runtime_t* runtime,
                                         int32_t partition_id,
                                         const psa_msg_t* msg, int provider)
{
    wt_pkcs11_range_t range;
    const uint8_t* src;
    uint32_t total;
    psa_status_t status;

    status = wt_pkcs11_read_exact(runtime, partition_id, msg, &range,
                                  sizeof(range));
    if (status != PSA_SUCCESS || range.length == 0U ||
            range.length > WT_PKCS11_CHUNK_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (provider != 0) {
        if (g_relay_slot.state != WT_PKCS11_SLOT_PROCESSING) {
            return PSA_ERROR_BAD_STATE;
        }
        src = g_relay_slot.request;
        total = g_relay_slot.request_len;
    }
    else {
        if (g_relay_slot.state != WT_PKCS11_SLOT_DONE) {
            return PSA_ERROR_BAD_STATE;
        }
        src = g_relay_slot.response;
        total = g_relay_slot.response_len;
    }
    if (range.offset > total || range.length > total - range.offset) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_pkcs11_write_exact(runtime, partition_id, msg,
                                    src + range.offset, range.length);
    if (status == PSA_SUCCESS && provider == 0 &&
            range.offset + range.length == total) {
        wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
    }
    return status;
}

static psa_status_t wt_pkcs11_app_call(wt_ffm_runtime_t* runtime,
                                       int32_t partition_id,
                                       const psa_msg_t* msg)
{
    switch (msg->type) {
        case WT_PKCS11_OP_APP_BEGIN:
            return wt_pkcs11_begin(runtime, partition_id, msg, 0);
        case WT_PKCS11_OP_APP_WRITE:
            return wt_pkcs11_write_chunk(runtime, partition_id, msg, 0);
        case WT_PKCS11_OP_APP_COMMIT:
            return wt_pkcs11_commit(0);
        case WT_PKCS11_OP_APP_POLL:
            return wt_pkcs11_report_length(runtime, partition_id, msg, 0);
        case WT_PKCS11_OP_APP_READ:
            return wt_pkcs11_read_chunk(runtime, partition_id, msg, 0);
        case WT_PKCS11_OP_APP_ABORT:
            if (g_relay_slot.state == WT_PKCS11_SLOT_PROCESSING ||
                    g_relay_slot.state == WT_PKCS11_SLOT_RESPONDING) {
                return (psa_status_t)WT_PKCS11_E_BUSY;
            }
            wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
            return PSA_SUCCESS;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

static psa_status_t wt_pkcs11_provider_call(wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg)
{
    switch (msg->type) {
        case WT_PKCS11_OP_PROVIDER_FETCH:
            return wt_pkcs11_report_length(runtime, partition_id, msg, 1);
        case WT_PKCS11_OP_PROVIDER_READ:
            return wt_pkcs11_read_chunk(runtime, partition_id, msg, 1);
        case WT_PKCS11_OP_PROVIDER_BEGIN:
            return wt_pkcs11_begin(runtime, partition_id, msg, 1);
        case WT_PKCS11_OP_PROVIDER_WRITE:
            return wt_pkcs11_write_chunk(runtime, partition_id, msg, 1);
        case WT_PKCS11_OP_PROVIDER_COMMIT:
            return wt_pkcs11_commit(1);
        case WT_PKCS11_OP_PROVIDER_ABORT:
            if (g_relay_slot.state != WT_PKCS11_SLOT_PROCESSING &&
                    g_relay_slot.state != WT_PKCS11_SLOT_RESPONDING) {
                return PSA_ERROR_BAD_STATE;
            }
            wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
            return PSA_SUCCESS;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

static psa_status_t wt_pkcs11_relay_call(wt_ffm_runtime_t* runtime,
                                         int32_t partition_id,
                                         const psa_msg_t* msg)
{
    if (g_relay_app_client == 0 ||
            (g_relay_provider_client == 0 && g_local_provider == NULL)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (msg->client_id >= 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (msg->client_id == g_relay_app_client) {
        if (msg->type >= WT_PKCS11_OP_PROVIDER_FETCH &&
                msg->type <= WT_PKCS11_OP_PROVIDER_ABORT) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        return wt_pkcs11_app_call(runtime, partition_id, msg);
    }
    if (msg->client_id == g_relay_provider_client) {
        if (g_local_provider != NULL) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        if (msg->type >= WT_PKCS11_OP_APP_BEGIN &&
                msg->type <= WT_PKCS11_OP_APP_ABORT) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        return wt_pkcs11_provider_call(runtime, partition_id, msg);
    }
    return PSA_ERROR_NOT_PERMITTED;
}

int wt_pkcs11_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                             int32_t partition_id)
{
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;

    (void)context;
    if (wt_spm_wait_service_signal(g_relay_transport, runtime, partition_id,
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
    if (g_relay_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_status != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (msg.type == PSA_IPC_CONNECT || msg.type == PSA_IPC_DISCONNECT) {
        reply_status = PSA_SUCCESS;
    }
    else {
        reply_status = wt_pkcs11_relay_call(runtime, partition_id, &msg);
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = msg.handle;
    call.status = reply_status;
    if (g_relay_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
