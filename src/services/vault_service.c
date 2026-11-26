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

/* Fail-closed keystore door defaults: no store backend, no door. */
static psa_status_t wt_vault_default_nvm_get_available(
    wt_vault_nvm_avail_t* avail)
{
    (void)avail;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_get_metadata(uint16_t id,
                                                      wt_vault_nvm_meta_t* meta)
{
    (void)id; (void)meta;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_add_object(
    const wt_vault_nvm_meta_t* meta, const uint8_t* data, size_t len)
{
    (void)meta; (void)data; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_destroy(const uint16_t* ids,
                                                 size_t count)
{
    (void)ids; (void)count;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_read(uint16_t id, uint32_t offset,
                                              uint8_t* data, size_t len)
{
    (void)id; (void)offset; (void)data; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static const wt_vault_nvm_backend_t g_vault_default_nvm_backend = {
    wt_vault_default_nvm_get_available,
    wt_vault_default_nvm_get_metadata,
    wt_vault_default_nvm_add_object,
    wt_vault_default_nvm_destroy,
    wt_vault_default_nvm_read
};

static const wt_vault_backend_t* g_vault_backend = &g_vault_default_backend;
static const wt_vault_key_backend_t* g_vault_key_backend =
    &g_vault_default_key_backend;
static const wt_vault_nvm_backend_t* g_vault_nvm_backend =
    &g_vault_default_nvm_backend;
static int32_t g_vault_keystore_client;
static wt_vault_rng_fn g_vault_rng = wt_vault_default_rng;
static wt_spm_transport_fn g_vault_transport = WT_SPM_TRANSPORT_DEFAULT;

#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_vault_restart_probe)
#endif

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
    g_vault_transport = (fn != NULL) ? fn : WT_SPM_TRANSPORT_DEFAULT;
}

void wt_vault_service_set_keystore_client(int32_t partition_id)
{
    g_vault_keystore_client = (partition_id > 0) ? partition_id : 0;
}

void wt_vault_service_set_nvm_backend(const wt_vault_nvm_backend_t* backend)
{
    g_vault_nvm_backend = (backend != NULL) ? backend :
                          &g_vault_default_nvm_backend;
}

#if defined(WT_VAULT_WIPE_PROBE) && (WT_VAULT_WIPE_PROBE == 1)
void wt_vault_wipe_probe(const uint8_t* buf, size_t len);
#define WT_VAULT_WIPED(buf, len) wt_vault_wipe_probe((buf), (len))
#else
#define WT_VAULT_WIPED(buf, len) ((void)0)
#endif

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

static psa_status_t wt_vault_service_serve(wt_ffm_runtime_t* runtime,
                                           int32_t partition_id,
                                           const psa_msg_t* msg,
                                           uint8_t* data, uint8_t* out)
{
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
            if (msg->in_size[1] > WT_VAULT_OBJECT_MAX) {
                status = PSA_ERROR_INSUFFICIENT_STORAGE;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, WT_VAULT_OBJECT_MAX, &data_len) !=
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
            if (data_len > WT_VAULT_OBJECT_MAX) {
                data_len = WT_VAULT_OBJECT_MAX;
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
            if (msg->in_size[1] > WT_VAULT_OBJECT_MAX) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, WT_VAULT_OBJECT_MAX, &data_len) !=
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
            if (cap > WT_VAULT_OBJECT_MAX) {
                cap = WT_VAULT_OBJECT_MAX;
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
            if (msg->in_size[1] > WT_VAULT_OBJECT_MAX) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, WT_VAULT_OBJECT_MAX, &data_len) !=
                    WT_FFM_SUCCESS) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                cap = msg->out_size[0];
                if (cap > WT_VAULT_OBJECT_MAX) {
                    cap = WT_VAULT_OBJECT_MAX;
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
            if (msg->in_size[1] > WT_VAULT_OBJECT_MAX) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, WT_VAULT_OBJECT_MAX, &data_len) !=
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
            if (msg->in_size[1] > WT_VAULT_OBJECT_MAX) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                       data, WT_VAULT_OBJECT_MAX, &data_len) !=
                    WT_FFM_SUCCESS) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                cap = msg->out_size[0];
                if (cap > WT_VAULT_OBJECT_MAX) {
                    cap = WT_VAULT_OBJECT_MAX;
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
    return status;
}

/* The copied transfers carry caller objects and key material: wipe the
 * buffers before the frame is released. */
static psa_status_t wt_vault_service_call(wt_ffm_runtime_t* runtime,
                                          int32_t partition_id,
                                          const psa_msg_t* msg)
{
    uint8_t data[WT_VAULT_OBJECT_MAX];
    uint8_t out[WT_VAULT_OBJECT_MAX];
    psa_status_t status;

    status = wt_vault_service_serve(runtime, partition_id, msg, data, out);
    wt_forceZero(data, sizeof(data));
    wt_forceZero(out, sizeof(out));
    WT_VAULT_WIPED(data, sizeof(data));
    WT_VAULT_WIPED(out, sizeof(out));
    return status;
}

/* Keystore object door (WT_VAULT_OP_NVM_*): the crypto partition's NVM
 * callbacks, served only for the registered keystore client. Object data
 * crosses in copied IOVECs bounded by WT_VAULT_OBJECT_MAX. */
static psa_status_t wt_vault_nvm_serve(wt_ffm_runtime_t* runtime,
                                       int32_t partition_id,
                                       const psa_msg_t* msg, uint8_t* data)
{
    uint16_t ids[WT_VAULT_NVM_DESTROY_MAX];
    wt_vault_nvm_req_t req;
    wt_vault_nvm_meta_t meta;
    wt_vault_nvm_avail_t avail;
    size_t req_len = 0U;
    size_t data_len = 0U;
    size_t count;
    psa_status_t status;

    if (g_vault_keystore_client == 0 ||
            msg->client_id != g_vault_keystore_client) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (msg->in_size[0] != sizeof(req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_vault_read_vec(runtime, partition_id, msg->handle, 0U,
                          (uint8_t*)&req, sizeof(req), &req_len) !=
            WT_FFM_SUCCESS || req_len != sizeof(req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (msg->type) {
    case WT_VAULT_OP_NVM_GET_AVAILABLE:
        if (msg->out_size[0] < sizeof(avail)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        (void)memset(&avail, 0, sizeof(avail));
        status = g_vault_nvm_backend->get_available(&avail);
        if (status == PSA_SUCCESS &&
                wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                   &avail, sizeof(avail)) != WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        break;
    case WT_VAULT_OP_NVM_GET_METADATA:
        if (msg->out_size[0] < sizeof(meta)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        (void)memset(&meta, 0, sizeof(meta));
        status = g_vault_nvm_backend->get_metadata(req.id, &meta);
        if (status == PSA_SUCCESS &&
                wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                   &meta, sizeof(meta)) != WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        break;
    case WT_VAULT_OP_NVM_ADD_OBJECT:
        if (msg->in_size[1] > WT_VAULT_OBJECT_MAX ||
                req.len != msg->in_size[1]) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U, data,
                              WT_VAULT_OBJECT_MAX, &data_len) != WT_FFM_SUCCESS) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        (void)memset(&meta, 0, sizeof(meta));
        meta.id = req.id;
        meta.access = req.access;
        meta.flags = req.flags;
        meta.len = (uint16_t)data_len;
        (void)memcpy(meta.label, req.label, sizeof(meta.label));
        status = g_vault_nvm_backend->add_object(&meta, data, data_len);
        break;
    case WT_VAULT_OP_NVM_DESTROY:
        count = req.count;
        if (count > WT_VAULT_NVM_DESTROY_MAX ||
                msg->in_size[1] != count * sizeof(ids[0])) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (count != 0U &&
                (wt_vault_read_vec(runtime, partition_id, msg->handle, 1U,
                                   (uint8_t*)ids, count * sizeof(ids[0]),
                                   &data_len) != WT_FFM_SUCCESS ||
                 data_len != count * sizeof(ids[0]))) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = g_vault_nvm_backend->destroy(ids, count);
        break;
    case WT_VAULT_OP_NVM_READ:
        if (req.len > WT_VAULT_OBJECT_MAX || msg->out_size[0] < req.len) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = g_vault_nvm_backend->read(req.id, req.offset, data,
                                           (size_t)req.len);
        if (status == PSA_SUCCESS &&
                wt_vault_write_vec(runtime, partition_id, msg->handle, 0U,
                                   data, (size_t)req.len) != WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }
    return status;
}

static psa_status_t wt_vault_nvm_call(wt_ffm_runtime_t* runtime,
                                      int32_t partition_id,
                                      const psa_msg_t* msg)
{
    uint8_t data[WT_VAULT_OBJECT_MAX];
    psa_status_t status;

    status = wt_vault_nvm_serve(runtime, partition_id, msg, data);
    wt_forceZero(data, sizeof(data));
    WT_VAULT_WIPED(data, sizeof(data));
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
        if (g_vault_keystore_client != 0 &&
                msg.client_id == g_vault_keystore_client) {
            reply_status = PSA_ERROR_NOT_PERMITTED;
        } else {
            reply_status = wt_vault_service_call(runtime, partition_id, &msg);
        }
    } else if (msg.type >= WT_VAULT_OP_NVM_GET_AVAILABLE &&
               msg.type <= WT_VAULT_OP_NVM_READ) {
        reply_status = wt_vault_nvm_call(runtime, partition_id, &msg);
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
