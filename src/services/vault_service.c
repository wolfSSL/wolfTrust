/* vault_service.c
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

#include "wolftrust/services/vault_service.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* Fail-closed default: no backing store means no storage capability is
 * advertised or silently faked (no always-success stubs). */
static psa_status_t wt_vault_default_set(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t flags,
                                         const uint8_t* data, size_t len)
{
    (void)owner; (void)sub; (void)uid; (void)flags; (void)data; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_get(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t offset,
                                         uint8_t* data, size_t size,
                                         size_t* out_len)
{
    (void)owner; (void)sub; (void)uid; (void)offset; (void)data; (void)size;
    (void)out_len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_get_info(int32_t owner, int32_t sub,
                                              uint64_t uid,
                                              wt_vault_info_t* info)
{
    (void)owner; (void)sub; (void)uid; (void)info;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_remove(int32_t owner, int32_t sub,
                                            uint64_t uid)
{
    (void)owner; (void)sub; (void)uid;
    return PSA_ERROR_NOT_SUPPORTED;
}

static const wt_vault_backend_t g_vault_default_backend = {
    wt_vault_default_set,
    wt_vault_default_get,
    wt_vault_default_get_info,
    wt_vault_default_remove
};

/* Fail-closed key-op defaults (WT-FFM-0046): no key backend, no key ops. */
static psa_status_t wt_vault_default_key_generate(int32_t owner, int32_t sub,
                                                  uint64_t uid, uint32_t type,
                                                  uint32_t usage)
{
    (void)owner; (void)sub; (void)uid; (void)type; (void)usage;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_key_import(int32_t owner, int32_t sub,
                                                uint64_t uid, uint32_t type,
                                                uint32_t usage,
                                                const uint8_t* data,
                                                size_t len)
{
    (void)owner; (void)sub; (void)uid; (void)type; (void)usage; (void)data;
    (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_key_export_public(int32_t owner,
                                                       int32_t sub,
                                                       uint64_t uid,
                                                       uint8_t* out,
                                                       size_t cap,
                                                       size_t* out_len)
{
    (void)owner; (void)sub; (void)uid; (void)out; (void)cap; (void)out_len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_key_sign(int32_t owner, int32_t sub,
                                              uint64_t uid,
                                              const uint8_t* digest,
                                              size_t digest_len, uint8_t* sig,
                                              size_t cap, size_t* out_len)
{
    (void)owner; (void)sub; (void)uid; (void)digest; (void)digest_len;
    (void)sig; (void)cap; (void)out_len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_key_verify(int32_t owner, int32_t sub,
                                                uint64_t uid,
                                                const uint8_t* digest,
                                                size_t digest_len,
                                                const uint8_t* sig,
                                                size_t sig_len)
{
    (void)owner; (void)sub; (void)uid; (void)digest; (void)digest_len;
    (void)sig; (void)sig_len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_key_encrypt(int32_t owner, int32_t sub,
                                                 uint64_t uid,
                                                 const uint8_t* input,
                                                 size_t input_len,
                                                 uint8_t* out, size_t cap,
                                                 size_t* out_len)
{
    (void)owner; (void)sub; (void)uid; (void)input; (void)input_len;
    (void)out; (void)cap; (void)out_len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_key_decrypt(int32_t owner, int32_t sub,
                                                 uint64_t uid,
                                                 const uint8_t* input,
                                                 size_t input_len,
                                                 uint8_t* out, size_t cap,
                                                 size_t* out_len)
{
    (void)owner; (void)sub; (void)uid; (void)input; (void)input_len;
    (void)out; (void)cap; (void)out_len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static const wt_vault_key_backend_t g_vault_default_key_backend = {
    wt_vault_default_key_generate,
    wt_vault_default_key_import,
    wt_vault_default_key_export_public,
    wt_vault_default_key_sign,
    wt_vault_default_key_verify,
    wt_vault_default_key_encrypt,
    wt_vault_default_key_decrypt
};

static psa_status_t wt_vault_default_rng(uint8_t* out, size_t len)
{
    (void)out; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static const wt_vault_backend_t* g_vault_backend = &g_vault_default_backend;
static const wt_vault_key_backend_t* g_vault_key_backend =
    &g_vault_default_key_backend;
static wt_vault_rng_fn g_vault_rng = wt_vault_default_rng;
static wt_spm_transport_fn g_vault_transport = wt_spm_transport_direct;

void wt_vault_service_set_backend(const wt_vault_backend_t* backend)
{
    g_vault_backend = (backend != NULL) ? backend : &g_vault_default_backend;
}

void wt_vault_service_set_key_backend(const wt_vault_key_backend_t* backend)
{
    g_vault_key_backend = (backend != NULL) ? backend :
                          &g_vault_default_key_backend;
}

void wt_vault_service_set_rng(wt_vault_rng_fn fn)
{
    g_vault_rng = (fn != NULL) ? fn : wt_vault_default_rng;
}

void wt_vault_service_set_transport(wt_spm_transport_fn fn)
{
    g_vault_transport = (fn != NULL) ? fn : wt_spm_transport_direct;
}

/* Drain invec[idx] into a bounded private buffer (WT-FFM-0041 copied
 * transfers). Returns the byte count or a negative WT_FFM error. */
static int wt_vault_read_vec(wt_ffm_runtime_t* runtime, int32_t partition_id,
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
        if (g_vault_transport(runtime, &call) != WT_FFM_SUCCESS) {
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

static int wt_vault_write_vec(wt_ffm_runtime_t* runtime, int32_t partition_id,
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
    if (g_vault_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static psa_status_t wt_vault_service_call(wt_ffm_runtime_t* runtime,
                                          int32_t partition_id,
                                          const psa_msg_t* msg)
{
    uint8_t data[WT_VAULT_OBJECT_MAX];
    uint8_t out[WT_VAULT_OBJECT_MAX];
    wt_vault_req_t req;
    wt_vault_info_t info;
    size_t req_len = 0U;
    size_t data_len = 0U;
    size_t out_len = 0U;
    size_t cap;
    psa_status_t status;

    status = PSA_ERROR_INVALID_ARGUMENT;
    if (msg->in_size[0] == sizeof(req) &&
            wt_vault_read_vec(runtime, partition_id, msg->handle, 0U,
                              (uint8_t*)&req, sizeof(req), &req_len) ==
                WT_FFM_SUCCESS && req_len == sizeof(req)) {
        switch (msg->type) {
        case WT_VAULT_OP_SET:
            if (msg->in_size[1] > sizeof(data)) {
                status = PSA_ERROR_INSUFFICIENT_STORAGE;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, sizeof(data), &data_len) !=
                    WT_FFM_SUCCESS) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_backend->set(msg->client_id, req.sub_owner,
                                              req.uid, req.flags, data, data_len);
            }
            break;
        case WT_VAULT_OP_GET:
            /* A caller buffer larger than the object bound is legal PSA usage.
             * Clamp it because no object exceeds the transfer buffer. */
            data_len = msg->out_size[0];
            if (data_len > sizeof(data)) {
                data_len = sizeof(data);
            }
            status = g_vault_backend->get(msg->client_id, req.sub_owner, req.uid,
                                          req.offset, data, data_len, &out_len);
            if (status == PSA_SUCCESS &&
                    wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                       data, out_len) != WT_FFM_SUCCESS) {
                status = PSA_ERROR_GENERIC_ERROR;
            }
            break;
        case WT_VAULT_OP_GET_INFO:
            if (msg->out_size[0] < sizeof(info)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_backend->get_info(msg->client_id, req.sub_owner,
                                                   req.uid, &info);
                if (status == PSA_SUCCESS &&
                        wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                           &info, sizeof(info)) !=
                            WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        case WT_VAULT_OP_REMOVE:
            status = g_vault_backend->remove(msg->client_id, req.sub_owner,
                                             req.uid);
            break;
        case WT_VAULT_OP_KEY_GENERATE:
            /* Key ops carry type in reserved and usage in flags. */
            status = g_vault_key_backend->generate(msg->client_id, req.sub_owner,
                                                   req.uid, req.reserved,
                                                   req.flags);
            break;
        case WT_VAULT_OP_KEY_IMPORT:
            if (msg->in_size[1] > sizeof(data)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, sizeof(data), &data_len) !=
                    WT_FFM_SUCCESS) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_key_backend->import(msg->client_id,
                                                     req.sub_owner, req.uid,
                                                     req.reserved, req.flags,
                                                     data, data_len);
            }
            break;
        case WT_VAULT_OP_KEY_EXPORT_PUBLIC:
            cap = msg->out_size[0];
            if (cap > sizeof(out)) {
                cap = sizeof(out);
            }
            status = g_vault_key_backend->export_public(msg->client_id,
                                                        req.sub_owner, req.uid,
                                                        out, cap, &out_len);
            if (status == PSA_SUCCESS &&
                    wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                       out, out_len) != WT_FFM_SUCCESS) {
                status = PSA_ERROR_GENERIC_ERROR;
            }
            break;
        case WT_VAULT_OP_KEY_SIGN:
            if (msg->in_size[1] > sizeof(data)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, sizeof(data), &data_len) !=
                    WT_FFM_SUCCESS) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                cap = msg->out_size[0];
                if (cap > sizeof(out)) {
                    cap = sizeof(out);
                }
                status = g_vault_key_backend->sign(msg->client_id, req.sub_owner,
                                                   req.uid, data, data_len, out,
                                                   cap, &out_len);
                if (status == PSA_SUCCESS &&
                        wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                           out, out_len) != WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        case WT_VAULT_OP_KEY_VERIFY:
            /* invec[1] = [digest][raw r||s signature]. */
            if (msg->in_size[1] > sizeof(data)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, sizeof(data), &data_len) !=
                        WT_FFM_SUCCESS ||
                    data_len <= WT_VAULT_KEY_SIG_LEN) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_key_backend->verify(
                    msg->client_id, req.sub_owner, req.uid, data,
                    data_len - WT_VAULT_KEY_SIG_LEN,
                    data + data_len - WT_VAULT_KEY_SIG_LEN,
                    WT_VAULT_KEY_SIG_LEN);
            }
            break;
        case WT_VAULT_OP_KEY_ENCRYPT:
        case WT_VAULT_OP_KEY_DECRYPT:
            if (msg->in_size[1] > sizeof(data)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, sizeof(data), &data_len) !=
                    WT_FFM_SUCCESS) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                cap = msg->out_size[0];
                if (cap > sizeof(out)) {
                    cap = sizeof(out);
                }
                if (msg->type == WT_VAULT_OP_KEY_ENCRYPT) {
                    status = g_vault_key_backend->encrypt(
                        msg->client_id, req.sub_owner, req.uid, data, data_len,
                        out, cap, &out_len);
                }
                else {
                    status = g_vault_key_backend->decrypt(
                        msg->client_id, req.sub_owner, req.uid, data, data_len,
                        out, cap, &out_len);
                }
                if (status == PSA_SUCCESS &&
                        wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                           out, out_len) != WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        case WT_VAULT_OP_RANDOM:
            cap = msg->out_size[0];
            if (cap == 0U || cap > WT_VAULT_RANDOM_MAX) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_rng(out, cap);
                if (status == PSA_SUCCESS &&
                        wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                           out, cap) != WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    wt_forceZero(data, sizeof(data));
    wt_forceZero(out, sizeof(out));
    return status;
}

int wt_vault_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                              int32_t partition_id)
{
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;

    (void)context;
    if (wt_spm_wait_service_signal(g_vault_transport, runtime, partition_id,
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
    if (g_vault_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_status != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }

    if (msg.type == PSA_IPC_CONNECT) {
        /* Defense in depth on top of nonsecure_clients=false: the vault
         * serves Secure Partitions only (WT-FFM-0047). */
        reply_status = (msg.client_id > 0) ? PSA_SUCCESS :
                       PSA_ERROR_CONNECTION_REFUSED;
    } else if (msg.type == PSA_IPC_DISCONNECT) {
        reply_status = PSA_SUCCESS;
    } else if (msg.type >= WT_VAULT_OP_SET &&
               msg.type <= WT_VAULT_OP_RANDOM) {
        reply_status = wt_vault_service_call(runtime, partition_id, &msg);
    } else {
        reply_status = PSA_ERROR_NOT_SUPPORTED;
    }

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = msg.handle;
    call.status = reply_status;
    if (g_vault_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
