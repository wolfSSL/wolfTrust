/* tpm_relay_service.c
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

#include "wolftrust/services/tpm_relay.h"
#include "wolftrust/zeroize.h"

#include <string.h>

#define WT_TPM_SLOT_IDLE        0U
#define WT_TPM_SLOT_PENDING     1U
#define WT_TPM_SLOT_IN_SERVICE  2U
#define WT_TPM_SLOT_DONE        3U
#define WT_TPM_SLOT_ABORTED     4U

static int32_t g_relay_app_client = 0;
static int32_t g_relay_ftpm_client = 0;
static wt_spm_transport_fn g_relay_transport = wt_spm_transport_direct;
static wt_tpm_local_provider_fn g_local_provider;
static void* g_local_provider_context;

/* The one in-flight slot, kept off the partition stack in its own band. */
static struct {
    uint8_t cmd[WT_TPM_FRAME_MAX];
    uint8_t resp[WT_TPM_FRAME_MAX];
    uint16_t cmd_len;
    uint16_t resp_len;
    uint8_t state;
} g_relay_slot;

#if defined(WT_TPM_NEG_PROBE) && (WT_TPM_NEG_PROBE == 1)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_tpm_relay_restart_probe)
#endif

void wt_tpm_relay_set_roles(int32_t app_client_id, int32_t ftpm_client_id)
{
    g_relay_app_client = app_client_id;
    g_relay_ftpm_client = ftpm_client_id;
    wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
}

void wt_tpm_relay_set_transport(wt_spm_transport_fn fn)
{
    g_relay_transport = (fn != NULL) ? fn : wt_spm_transport_direct;
}

void wt_tpm_relay_set_local_provider(wt_tpm_local_provider_fn provider,
                                     void* context)
{
    g_local_provider = provider;
    g_local_provider_context = context;
}

/* Drain invec[0] into a bounded private buffer (copied transfers). */
static int wt_tpm_relay_read_req(wt_ffm_runtime_t* runtime,
                                 int32_t partition_id,
                                 psa_handle_t msg_handle, uint8_t* buffer,
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
        call.buffer = buffer + len;
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

static int wt_tpm_relay_write_resp(wt_ffm_runtime_t* runtime,
                                   int32_t partition_id,
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

/* Copy one inbound frame into dst; the frame must be 1..WT_TPM_FRAME_MAX. */
static psa_status_t wt_tpm_relay_take_frame(wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg,
                                            uint8_t* dst, uint16_t* dst_len)
{
    size_t len = 0U;

    if (msg->in_size[0] == 0U || msg->in_size[0] > WT_TPM_FRAME_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_tpm_relay_read_req(runtime, partition_id, msg->handle, dst,
                              WT_TPM_FRAME_MAX, &len) != WT_FFM_SUCCESS ||
            len != msg->in_size[0]) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *dst_len = (uint16_t)len;
    return PSA_SUCCESS;
}

/* Deliver one outbound frame into outvec[0], which must hold it whole. */
static psa_status_t wt_tpm_relay_give_frame(wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg,
                                            const uint8_t* src,
                                            uint16_t src_len)
{
    if (msg->out_size[0] < (size_t)src_len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_tpm_relay_write_resp(runtime, partition_id, msg->handle, src,
                                src_len) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_tpm_relay_app_op(wt_ffm_runtime_t* runtime,
                                        int32_t partition_id,
                                        const psa_msg_t* msg)
{
    psa_status_t status;

    if (msg->type == WT_TPM_OP_SUBMIT) {
        /* A command the responder has taken IN_SERVICE is left alone so a
         * stray submit cannot erase it mid-process; the responder finishes it
         * (slot -> DONE) or loses it to a restart (slot -> ABORTED). */
        if (g_relay_slot.state == WT_TPM_SLOT_IN_SERVICE) {
            return (psa_status_t)WT_TPM_E_BUSY;
        }
        /* A fresh submit owns a new transaction, so reclaim a slot the
         * application abandoned without the responder touching it (it
         * restarted after SUBMIT, or its poll limit expired on a DONE
         * response). This keeps a guest restart from wedging the relay and
         * scrubs the stale command or response before the new one lands. */
        if (g_relay_slot.state != WT_TPM_SLOT_IDLE) {
            wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
        }
        status = wt_tpm_relay_take_frame(runtime, partition_id, msg,
                                         g_relay_slot.cmd,
                                         &g_relay_slot.cmd_len);
        if (status == PSA_SUCCESS) {
            g_relay_slot.state = WT_TPM_SLOT_PENDING;
            if (g_local_provider != NULL) {
                size_t response_len = 0U;
                int rc = g_local_provider(g_relay_slot.cmd,
                    g_relay_slot.cmd_len, g_relay_slot.resp,
                    sizeof(g_relay_slot.resp), &response_len,
                    g_local_provider_context);

                if (rc != 0 || response_len == 0U ||
                        response_len > sizeof(g_relay_slot.resp)) {
                    wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
                    return PSA_ERROR_GENERIC_ERROR;
                }
                g_relay_slot.resp_len = (uint16_t)response_len;
                wt_forceZero(g_relay_slot.cmd, sizeof(g_relay_slot.cmd));
                g_relay_slot.cmd_len = 0U;
                g_relay_slot.state = WT_TPM_SLOT_DONE;
            }
        }
        return status;
    }
    if (g_relay_slot.state == WT_TPM_SLOT_IDLE) {
        return (psa_status_t)WT_TPM_E_EMPTY;
    }
    if (g_relay_slot.state == WT_TPM_SLOT_ABORTED) {
        wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
        return (psa_status_t)WT_TPM_E_ABORTED;
    }
    if (g_relay_slot.state != WT_TPM_SLOT_DONE) {
        return (psa_status_t)WT_TPM_E_BUSY;
    }
    status = wt_tpm_relay_give_frame(runtime, partition_id, msg,
                                     g_relay_slot.resp,
                                     g_relay_slot.resp_len);
    if (status == PSA_SUCCESS) {
        /* The exchange is complete: scrub the slot before it is reused. */
        wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
    }
    return status;
}

static psa_status_t wt_tpm_relay_ftpm_op(wt_ffm_runtime_t* runtime,
                                         int32_t partition_id,
                                         const psa_msg_t* msg)
{
    psa_status_t status;

    if (msg->type == WT_TPM_OP_FETCH) {
        /* A FETCH while IN_SERVICE means the responder lost a command it may
         * already have run. Never replay it: fail the exchange so a
         * state-changing command executes at most once. */
        if (g_relay_slot.state == WT_TPM_SLOT_IN_SERVICE) {
            wt_forceZero(&g_relay_slot, sizeof(g_relay_slot));
            g_relay_slot.state = WT_TPM_SLOT_ABORTED;
            return (psa_status_t)WT_TPM_E_EMPTY;
        }
        if (g_relay_slot.state != WT_TPM_SLOT_PENDING) {
            return (psa_status_t)WT_TPM_E_EMPTY;
        }
        status = wt_tpm_relay_give_frame(runtime, partition_id, msg,
                                         g_relay_slot.cmd,
                                         g_relay_slot.cmd_len);
        if (status == PSA_SUCCESS) {
            g_relay_slot.state = WT_TPM_SLOT_IN_SERVICE;
        }
        return status;
    }
    if (g_relay_slot.state != WT_TPM_SLOT_IN_SERVICE) {
        return PSA_ERROR_BAD_STATE;
    }
    status = wt_tpm_relay_take_frame(runtime, partition_id, msg,
                                     g_relay_slot.resp,
                                     &g_relay_slot.resp_len);
    if (status == PSA_SUCCESS) {
        g_relay_slot.state = WT_TPM_SLOT_DONE;
    }
    return status;
}

/* Role by SPM-stamped identity: the application may only SUBMIT/POLL, the
 * fwTPM partition may only FETCH/RESPOND; everyone else is refused. */
static psa_status_t wt_tpm_relay_call(wt_ffm_runtime_t* runtime,
                                      int32_t partition_id,
                                      const psa_msg_t* msg)
{
    if (g_relay_app_client == 0 ||
            (g_relay_ftpm_client == 0 && g_local_provider == NULL)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (msg->client_id >= 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (msg->type == WT_TPM_OP_SUBMIT || msg->type == WT_TPM_OP_POLL) {
        if (msg->client_id != g_relay_app_client) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        return wt_tpm_relay_app_op(runtime, partition_id, msg);
    }
    if (msg->type == WT_TPM_OP_FETCH || msg->type == WT_TPM_OP_RESPOND) {
        if (g_local_provider != NULL) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        if (msg->client_id != g_relay_ftpm_client) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        return wt_tpm_relay_ftpm_op(runtime, partition_id, msg);
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

int wt_tpm_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
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
    } else {
        reply_status = wt_tpm_relay_call(runtime, partition_id, &msg);
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
