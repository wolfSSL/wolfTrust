/* attestation_service.c
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

#include "wolftrust/services/attestation_service.h"
#include "wolftrust/services/initial_attestation.h"

#include <string.h>

static wt_spm_transport_fn g_attest_transport = WT_SPM_TRANSPORT_DEFAULT;

#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_attestation_restart_probe)
#endif

void wt_attestation_service_set_transport(wt_spm_transport_fn fn)
{
    g_attest_transport = (fn != NULL) ? fn : WT_SPM_TRANSPORT_DEFAULT;
}

static int wt_attest_vec(wt_ffm_runtime_t* runtime, int32_t partition_id,
                         psa_handle_t msg_handle, int32_t op, void* data,
                         size_t len, size_t* done)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = op;
    call.partition_id = partition_id;
    call.msg_handle = msg_handle;
    call.buffer = data;
    call.num_bytes = len;
    if (g_attest_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    *done = call.ret_size;
    return WT_FFM_SUCCESS;
}

/* One read drains the copied input vector; each op fills out[] and the
 * shared tail checks the caller's capacity before the single write, since a
 * short out-vec would fault the write into a partition restart. */
static psa_status_t wt_attest_op(wt_ffm_runtime_t* runtime,
                                 int32_t partition_id, const psa_msg_t* msg,
                                 uint8_t* out, size_t* out_len)
{
    uint8_t in[WT_ATTEST_CHALLENGE_SIZE_64];
    uint32_t size32 = 0U;
    size_t in_len = 0U;
    size_t size = 0U;
    int ret;

    if (msg->type == PSA_IPC_CONNECT || msg->type == PSA_IPC_DISCONNECT) {
        return PSA_SUCCESS;
    }
    if (msg->type == WT_ATTEST_OP_PUBLIC_KEY) {
        ret = wt_initial_attest_get_iak_public_key(out,
                  WT_ATTEST_IAK_PUBLIC_KEY_SIZE, out_len);
    }
    else if (msg->type == PSA_IPC_CALL ||
             msg->type == WT_ATTEST_OP_TOKEN_SIZE) {
        /* The token binds the caller's guest, so only Non-secure clients. */
        if (msg->type == PSA_IPC_CALL && msg->client_id >= 0) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        if (msg->in_size[0] > sizeof(in) ||
                (msg->type == WT_ATTEST_OP_TOKEN_SIZE &&
                 (msg->in_size[0] != sizeof(size32) ||
                  msg->out_size[0] < sizeof(size32)))) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (wt_attest_vec(runtime, partition_id, msg->handle, WT_SPM_OP_READ,
                          in, msg->in_size[0], &in_len) != WT_FFM_SUCCESS) {
            return PSA_ERROR_GENERIC_ERROR;
        }
        if (msg->type == PSA_IPC_CALL) {
            ret = wt_initial_attest_get_token(
                (wt_guest_id_t)(-msg->client_id - 1), in, in_len, out,
                WT_ATTEST_MAX_TOKEN_SIZE, out_len);
        }
        else {
            (void)memcpy(&size32, in, sizeof(size32));
            ret = wt_initial_attest_get_token_size((size_t)size32, &size);
            size32 = (uint32_t)size;
            (void)memcpy(out, &size32, sizeof(size32));
            *out_len = sizeof(size32);
        }
    }
    else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (ret == WT_ATTEST_ERROR_INVALID_ARGUMENT) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ret == WT_ATTEST_ERROR_BUFFER_TOO_SMALL) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (ret == WT_ATTEST_ERROR_NOT_READY) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ret != WT_ATTEST_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (msg->out_size[0] < *out_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (wt_attest_vec(runtime, partition_id, msg->handle, WT_SPM_OP_WRITE,
                      out, *out_len, &size) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

int wt_attestation_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                    int32_t partition_id)
{
    uint8_t out[WT_ATTEST_MAX_TOKEN_SIZE];
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;
    size_t out_len = 0U;

    (void)context;
    if (wt_spm_wait_service_signal(g_attest_transport, runtime, partition_id,
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
    if (g_attest_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_status != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }

    reply_status = wt_attest_op(runtime, partition_id, &msg, out, &out_len);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = msg.handle;
    call.status = reply_status;
    if (g_attest_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
