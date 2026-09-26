/* storage_service.c
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

#include "wolftrust/services/storage_service.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* One completed gate op: both transports finish blocking SP-as-client ops
 * before returning (the SVC transport re-issues around the coroutine block;
 * the direct transport dispatches the pending message inline). A residual
 * NOT_READY is therefore a failure, never a reason to spin. */
static int wt_storage_xfer(wt_storage_service_ctx_t* ctx,
                           wt_ffm_runtime_t* runtime, wt_spm_call_t* call)
{
    if (ctx->transport(runtime, call) != WT_FFM_SUCCESS ||
            call->ret_int == WT_FFM_ERROR_NOT_READY) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

/* Lazy SP-to-SP connection to the vault, cached across messages. */
static psa_status_t wt_storage_vault_handle(wt_storage_service_ctx_t* ctx,
                                            wt_ffm_runtime_t* runtime,
                                            int32_t partition_id)
{
    wt_spm_call_t call;

    if (ctx->vault_handle > 0) {
        return PSA_SUCCESS;
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = partition_id;
    call.sid = ctx->vault_sid;
    call.version = 1U;
    if (wt_storage_xfer(ctx, runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS || call.ret_handle <= 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    ctx->vault_handle = call.ret_handle;
    return PSA_SUCCESS;
}

static psa_status_t wt_storage_vault_call(wt_storage_service_ctx_t* ctx,
                                          wt_ffm_runtime_t* runtime,
                                          int32_t partition_id,
                                          int32_t type,
                                          const wt_vault_req_t* vreq,
                                          const uint8_t* set_data,
                                          size_t set_len,
                                          void* out, size_t out_cap,
                                          size_t* out_len)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CALL;
    call.partition_id = partition_id;
    call.msg_handle = ctx->vault_handle;
    call.call_type = type;
    call.sp_in[0].base = vreq;
    call.sp_in[0].len = sizeof(*vreq);
    call.sp_in_len = 1U;
    if (set_data != NULL) {
        call.sp_in[1].base = set_data;
        call.sp_in[1].len = set_len;
        call.sp_in_len = 2U;
    }
    if (out != NULL) {
        call.sp_out[0].base = out;
        call.sp_out[0].len = out_cap;
        call.sp_out_len = 1U;
    }
    if (wt_storage_xfer(ctx, runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (out_len != NULL) {
        *out_len = call.sp_out[0].len;
    }
    return call.ret_status;
}

/* Drain invec[0] — [wt_its_req_t][data] — into a bounded private buffer
 * (WT-FFM-0041 copied transfers). */
static int wt_storage_read_req(wt_storage_service_ctx_t* ctx,
                               wt_ffm_runtime_t* runtime,
                               int32_t partition_id, psa_handle_t msg_handle,
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
        call.vec_idx = 0U;
        call.buffer = buffer + len;
        call.num_bytes = capacity - len;
        if (ctx->transport(runtime, &call) != WT_FFM_SUCCESS) {
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

static int wt_storage_write_reply(wt_storage_service_ctx_t* ctx,
                                  wt_ffm_runtime_t* runtime,
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
    if (ctx->transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static psa_status_t wt_storage_service_call(wt_storage_service_ctx_t* ctx,
                                            wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg)
{
    uint8_t buffer[sizeof(wt_its_req_t) + WT_VAULT_OBJECT_MAX];
    wt_its_req_t req;
    wt_vault_req_t vreq;
    wt_vault_info_t info;
    size_t in_len = 0U;
    size_t out_len = 0U;
    size_t cap;
    psa_status_t status;

    status = PSA_ERROR_INVALID_ARGUMENT;
    if (msg->in_size[0] >= sizeof(req)) {
        if (msg->in_size[0] > sizeof(buffer)) {
            status = PSA_ERROR_INSUFFICIENT_STORAGE;
        }
        else if (wt_storage_read_req(ctx, runtime, partition_id, msg->handle,
                                     buffer, sizeof(buffer), &in_len) !=
                    WT_FFM_SUCCESS || in_len < sizeof(req)) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            (void)memcpy(&req, buffer, sizeof(req));
            /* PSA Storage: uid 0 is invalid for every operation. */
            if (req.uid == 0U) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            /* Optional PS features (create/set_extended): psa_ps_get_support
             * advertises none, so refuse them until implemented. */
            else if (msg->type == WT_PS_OP_CREATE ||
                    msg->type == WT_PS_OP_SET_EXTENDED) {
                status = PSA_ERROR_NOT_SUPPORTED;
            }
            else {
                status = wt_storage_vault_handle(ctx, runtime, partition_id);
            }
        }
    }

    if (status == PSA_SUCCESS) {
        /* The vault namespaces by (this partition, end client, uid): the
         * SPM-stamped message client id is the delegated sub_owner. */
        (void)memset(&vreq, 0, sizeof(vreq));
        vreq.uid = req.uid;
        vreq.flags = req.flags;
        vreq.offset = req.offset;
        vreq.sub_owner = msg->client_id;

        switch (msg->type) {
        case WT_ITS_OP_SET:
            if ((req.flags & ~ctx->client_flags_mask) != 0U) {
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
            }
            vreq.flags = req.flags | ctx->vault_flags;
            status = wt_storage_vault_call(ctx, runtime, partition_id,
                                           WT_VAULT_OP_SET, &vreq,
                                           buffer + sizeof(req),
                                           in_len - sizeof(req), NULL, 0U,
                                           NULL);
            break;
        case WT_ITS_OP_GET:
            cap = msg->out_size[0];
            if (cap > WT_VAULT_OBJECT_MAX) {
                cap = WT_VAULT_OBJECT_MAX;
            }
            status = wt_storage_vault_call(ctx, runtime, partition_id,
                                           WT_VAULT_OP_GET, &vreq, NULL, 0U,
                                           buffer, cap, &out_len);
            if (status == PSA_SUCCESS &&
                    wt_storage_write_reply(ctx, runtime, partition_id,
                                           msg->handle, buffer, out_len) !=
                        WT_FFM_SUCCESS) {
                status = PSA_ERROR_GENERIC_ERROR;
            }
            break;
        case WT_ITS_OP_GET_INFO:
            if (msg->out_size[0] < sizeof(info)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = wt_storage_vault_call(ctx, runtime, partition_id,
                                               WT_VAULT_OP_GET_INFO, &vreq,
                                               NULL, 0U, &info, sizeof(info),
                                               NULL);
                if (status == PSA_SUCCESS) {
                    /* Hide the frontend's internal sealing flag. */
                    info.flags &= ~ctx->vault_flags;
                }
                if (status == PSA_SUCCESS &&
                        wt_storage_write_reply(ctx, runtime, partition_id,
                                               msg->handle, &info,
                                               sizeof(info)) !=
                            WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        case WT_ITS_OP_REMOVE:
            status = wt_storage_vault_call(ctx, runtime, partition_id,
                                           WT_VAULT_OP_REMOVE, &vreq, NULL,
                                           0U, NULL, 0U, NULL);
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    wt_forceZero(buffer, sizeof(buffer));
    return status;
}

int wt_storage_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                int32_t partition_id)
{
    wt_storage_service_ctx_t* ctx = (wt_storage_service_ctx_t*)context;
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;
    uint32_t caps;

    if (ctx == NULL || ctx->transport == NULL) {
        return WT_FFM_ERROR_STATE;
    }
    if (wt_spm_wait_service_signal(ctx->transport, runtime, partition_id,
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
    if (ctx->transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_status != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }

    if (msg.type == PSA_IPC_CONNECT || msg.type == PSA_IPC_DISCONNECT) {
        reply_status = PSA_SUCCESS;
    } else if (msg.type == WT_PS_OP_GET_SUPPORT) {
        caps = ctx->caps;
        if (msg.out_size[0] < sizeof(caps)) {
            reply_status = PSA_ERROR_INVALID_ARGUMENT;
        } else if (wt_storage_write_reply(ctx, runtime, partition_id,
                                          msg.handle, &caps,
                                          sizeof(caps)) != WT_FFM_SUCCESS) {
            reply_status = PSA_ERROR_GENERIC_ERROR;
        } else {
            reply_status = PSA_SUCCESS;
        }
    } else if (msg.type >= WT_ITS_OP_SET &&
               msg.type <= WT_PS_OP_SET_EXTENDED) {
        reply_status = wt_storage_service_call(ctx, runtime, partition_id,
                                               &msg);
    } else {
        reply_status = PSA_ERROR_NOT_SUPPORTED;
    }

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = msg.handle;
    call.status = reply_status;
    if (ctx->transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
