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

static wt_spm_transport_fn g_attest_transport = wt_spm_transport_direct;

#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_attestation_restart_probe)
#endif

void wt_attestation_service_set_transport(wt_spm_transport_fn fn)
{
    g_attest_transport = (fn != NULL) ? fn : wt_spm_transport_direct;
}

/* Drain invec[idx] into a bounded private buffer (WT-FFM-0041 copied
 * transfers). Returns the byte count via out_len or a negative WT_FFM error. */
static int wt_attest_read_vec(wt_ffm_runtime_t* runtime, int32_t partition_id,
                              psa_handle_t msg_handle, uint32_t idx,
                              uint8_t* buffer, size_t capacity,
                              size_t* out_len)
{
    wt_spm_call_t call;
    size_t len = 0U;

    for (;;) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_READ;
        call.partition_id = partition_id;
        call.msg_handle = msg_handle;
        call.vec_idx = idx;
        call.buffer = buffer + len;
        call.num_bytes = capacity - len;
        if (g_attest_transport(runtime, &call) != WT_FFM_SUCCESS) {
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

static int wt_attest_write_vec(wt_ffm_runtime_t* runtime, int32_t partition_id,
                               psa_handle_t msg_handle, uint32_t idx,
                               const void* data, size_t len)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WRITE;
    call.partition_id = partition_id;
    call.msg_handle = msg_handle;
    call.vec_idx = idx;
    call.buffer = (void*)(uintptr_t)data;
    call.num_bytes = len;
    if (g_attest_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static psa_status_t wt_attestation_map_status(int ret);

static psa_status_t wt_attestation_service_token(wt_ffm_runtime_t* runtime,
                                                 int32_t partition_id,
                                                 const psa_msg_t* msg)
{
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_64];
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    size_t challenge_len = 0U;
    size_t token_len = 0U;
    wt_guest_id_t guest_id;
    int ret;

    /* Initial Attestation is a Non-secure client service; the token binds the
     * caller's guest identity, derived from the PSA client id. */
    if (msg->client_id >= 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    guest_id = (wt_guest_id_t)(-msg->client_id - 1);

    if (msg->in_size[0] > sizeof(challenge)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_attest_read_vec(runtime, partition_id, msg->handle, 0U, challenge,
                           sizeof(challenge), &challenge_len) !=
            WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    ret = wt_initial_attest_get_token(guest_id, challenge, challenge_len,
                                      token, sizeof(token), &token_len);
    if (ret != WT_ATTEST_SUCCESS) {
        return wt_attestation_map_status(ret);
    }
    /* Check the caller's output capacity before writing: a short out-vec
     * faults the FF-M write, which the gate maps to must_panic, turning a
     * client sizing mistake into an attestation-partition restart. */
    if (msg->out_size[0] < token_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (wt_attest_write_vec(runtime, partition_id, msg->handle, 0U, token,
                            token_len) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_attestation_map_status(int ret)
{
    psa_status_t st;

    switch (ret) {
        case WT_ATTEST_SUCCESS:
            st = PSA_SUCCESS;
            break;
        case WT_ATTEST_ERROR_INVALID_ARGUMENT:
            st = PSA_ERROR_INVALID_ARGUMENT;
            break;
        case WT_ATTEST_ERROR_BUFFER_TOO_SMALL:
            st = PSA_ERROR_BUFFER_TOO_SMALL;
            break;
        case WT_ATTEST_ERROR_NOT_READY:
            st = PSA_ERROR_SERVICE_FAILURE;
            break;
        default:
            st = PSA_ERROR_GENERIC_ERROR;
            break;
    }
    return st;
}

/* Token-size query (WT_ATTEST_OP_TOKEN_SIZE): a 32-bit challenge size in,
 * the exact token size out. Carries the same PSA status mapping the retired
 * direct veneer's client produced, so ARM's test_a001 semantics hold. */
static psa_status_t wt_attestation_service_token_size(
    wt_ffm_runtime_t* runtime, int32_t partition_id, const psa_msg_t* msg)
{
    uint32_t challenge_size = 0U;
    uint32_t token_size_out;
    size_t token_size = 0U;
    size_t got_len = 0U;
    int ret;

    if (msg->in_size[0] != sizeof(challenge_size) ||
            msg->out_size[0] < sizeof(token_size_out)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_attest_read_vec(runtime, partition_id, msg->handle, 0U,
                           (uint8_t*)&challenge_size, sizeof(challenge_size),
                           &got_len) != WT_FFM_SUCCESS ||
            got_len != sizeof(challenge_size)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ret = wt_initial_attest_get_token_size((size_t)challenge_size,
                                           &token_size);
    if (ret != WT_ATTEST_SUCCESS) {
        return wt_attestation_map_status(ret);
    }
    token_size_out = (uint32_t)token_size;
    if (wt_attest_write_vec(runtime, partition_id, msg->handle, 0U,
                            &token_size_out,
                            sizeof(token_size_out)) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

/* IAK public-key query (WT_ATTEST_OP_PUBLIC_KEY): the uncompressed P-256
 * public point out. Public data only — the private IAK never leaves the
 * secure side. */
static psa_status_t wt_attestation_service_public_key(
    wt_ffm_runtime_t* runtime, int32_t partition_id, const psa_msg_t* msg)
{
    uint8_t public_key[WT_ATTEST_IAK_PUBLIC_KEY_SIZE];
    size_t public_key_len = 0U;
    int ret;

    ret = wt_initial_attest_get_iak_public_key(public_key,
                                               sizeof(public_key),
                                               &public_key_len);
    if (ret != WT_ATTEST_SUCCESS) {
        return wt_attestation_map_status(ret);
    }
    if (msg->out_size[0] < public_key_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (wt_attest_write_vec(runtime, partition_id, msg->handle, 0U, public_key,
                            public_key_len) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

int wt_attestation_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                    int32_t partition_id)
{
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;

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

    if (msg.type == PSA_IPC_CONNECT || msg.type == PSA_IPC_DISCONNECT) {
        reply_status = PSA_SUCCESS;
    } else if (msg.type == PSA_IPC_CALL) {
        reply_status = wt_attestation_service_token(runtime, partition_id,
                                                    &msg);
    } else if (msg.type == WT_ATTEST_OP_TOKEN_SIZE) {
        reply_status = wt_attestation_service_token_size(runtime,
                           partition_id, &msg);
    } else if (msg.type == WT_ATTEST_OP_PUBLIC_KEY) {
        reply_status = wt_attestation_service_public_key(runtime,
                           partition_id, &msg);
    } else {
        reply_status = PSA_ERROR_NOT_SUPPORTED;
    }

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
