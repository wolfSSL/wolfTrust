/* hsm_relay_service.c
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

#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/zeroize.h"
#if defined(WT_PKCS11_HSM_RESTART_PROBE) && \
    (WT_PKCS11_HSM_RESTART_PROBE == 1)
#include "wolftrust/arch.h"
#endif

#include <string.h>

static int wt_hsm_relay_default_submit(void* submit_ctx, int32_t client_id,
                                       const uint8_t* req, size_t req_len,
                                       uint8_t* resp, size_t resp_cap,
                                       size_t* resp_len)
{
    (void)submit_ctx; (void)client_id; (void)req; (void)req_len;
    (void)resp; (void)resp_cap; (void)resp_len;
    return -1;
}

static wt_hsm_relay_submit_fn g_relay_submit = NULL;
static void* g_relay_submit_ctx = NULL;
static wt_spm_transport_fn g_relay_transport = wt_spm_transport_direct;
#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
static int32_t g_relay_secure_client = 0;
#endif
static int32_t g_relay_attest_client = 0;
static wt_hsm_attest_sign_fn g_relay_attest_sign = NULL;
static wt_hsm_attest_public_key_fn g_relay_attest_public_key = NULL;

/* P-256 verify needs roughly 4 KiB below the relay frames. Keep the copied
 * packets in Secure KEYSTORE instead of the HSM partition's 8 KiB stack. */
static struct {
    uint8_t req[WT_HSM_RELAY_MSG_MAX];
    uint8_t resp[WT_HSM_RELAY_MSG_MAX];
} g_relay_io;

#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_hsm_relay_restart_probe)
#endif

void wt_hsm_relay_set_submit(wt_hsm_relay_submit_fn fn, void* submit_ctx)
{
    g_relay_submit = fn;
    g_relay_submit_ctx = (fn != NULL) ? submit_ctx : NULL;
}

#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
void wt_hsm_relay_set_secure_client_policy(int32_t partition_id)
{
    g_relay_secure_client = (partition_id > 0) ? partition_id : 0;
}
#endif

void wt_hsm_relay_set_transport(wt_spm_transport_fn fn)
{
    g_relay_transport = (fn != NULL) ? fn : wt_spm_transport_direct;
}

void wt_hsm_relay_set_attest_ops(int32_t attest_partition_id,
                                 wt_hsm_attest_sign_fn sign,
                                 wt_hsm_attest_public_key_fn public_key)
{
    g_relay_attest_client = (attest_partition_id > 0) ? attest_partition_id :
                            0;
    g_relay_attest_sign = sign;
    g_relay_attest_public_key = public_key;
}

/* Drain invec[0] into a bounded private buffer (WT-FFM-0041 copied
 * transfers). */
static int wt_hsm_relay_read_req(wt_ffm_runtime_t* runtime,
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

static int wt_hsm_relay_write_resp(wt_ffm_runtime_t* runtime,
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

static psa_status_t wt_hsm_relay_call_inner(wt_ffm_runtime_t* runtime,
                                            int32_t partition_id,
                                            const psa_msg_t* msg)
{
    size_t req_len = 0U;
    size_t resp_len = 0U;
    size_t resp_cap;
    wt_hsm_relay_submit_fn submit = g_relay_submit;

    if (msg->in_size[0] == 0U ||
            msg->in_size[0] > sizeof(g_relay_io.req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    resp_cap = msg->out_size[0];
    if (resp_cap == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (resp_cap > sizeof(g_relay_io.resp)) {
        resp_cap = sizeof(g_relay_io.resp);
    }
    if (submit == NULL) {
        /* Fail closed: no platform submit hook, no path to the server. */
        submit = wt_hsm_relay_default_submit;
    }
    if (wt_hsm_relay_read_req(runtime, partition_id, msg->handle,
                              g_relay_io.req, sizeof(g_relay_io.req),
                              &req_len) != WT_FFM_SUCCESS ||
            req_len != msg->in_size[0]) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (submit == wt_hsm_relay_default_submit) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (submit(g_relay_submit_ctx, msg->client_id, g_relay_io.req, req_len,
               g_relay_io.resp, resp_cap, &resp_len) != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (resp_len == 0U || resp_len > resp_cap) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (wt_hsm_relay_write_resp(runtime, partition_id, msg->handle,
                                g_relay_io.resp, resp_len) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

/* Relay packets carry key material, so scrub them on every call path. */
static psa_status_t wt_hsm_relay_call(wt_ffm_runtime_t* runtime,
                                      int32_t partition_id,
                                      const psa_msg_t* msg)
{
    psa_status_t status = wt_hsm_relay_call_inner(runtime, partition_id, msg);

    wt_forceZero(&g_relay_io, sizeof(g_relay_io));
    return status;
}

/* Map the engine signer's wolfHSM-style result onto a PSA status; NOTREADY
 * (no IAK yet) surfaces as BAD_STATE so the attestation partition reports
 * not-ready rather than a generic failure. */
static psa_status_t wt_hsm_relay_attest_status(int rc)
{
    psa_status_t status;

    if (rc == 0) {
        status = PSA_SUCCESS;
    }
    else if (rc == WT_HSM_ATTEST_NOT_READY) {
        status = PSA_ERROR_BAD_STATE;
    }
    else {
        status = PSA_ERROR_GENERIC_ERROR;
    }
    return status;
}

static psa_status_t wt_hsm_relay_attest_call(wt_ffm_runtime_t* runtime,
                                             int32_t partition_id,
                                             const psa_msg_t* msg)
{
    uint8_t digest[WT_HSM_ATTEST_DIGEST_LEN];
    uint8_t out[WT_HSM_ATTEST_PUBLIC_KEY_LEN];
    size_t digest_len = 0U;
    size_t out_len = 0U;
    psa_status_t status;

    if (g_relay_attest_client == 0 || msg->client_id != g_relay_attest_client) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (msg->type == WT_HSM_OP_ATTEST_SIGN) {
        if (g_relay_attest_sign == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (msg->in_size[0] != sizeof(digest) ||
                msg->out_size[0] < WT_HSM_ATTEST_SIGNATURE_LEN) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (wt_hsm_relay_read_req(runtime, partition_id, msg->handle, digest,
                                  sizeof(digest), &digest_len) !=
                WT_FFM_SUCCESS || digest_len != sizeof(digest)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = wt_hsm_relay_attest_status(
            g_relay_attest_sign(digest, digest_len, out,
                                WT_HSM_ATTEST_SIGNATURE_LEN, &out_len));
        if (status == PSA_SUCCESS && out_len != WT_HSM_ATTEST_SIGNATURE_LEN) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
    }
    else {
        if (g_relay_attest_public_key == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (msg->out_size[0] < WT_HSM_ATTEST_PUBLIC_KEY_LEN) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = wt_hsm_relay_attest_status(
            g_relay_attest_public_key(out, sizeof(out), &out_len));
        if (status == PSA_SUCCESS && out_len != WT_HSM_ATTEST_PUBLIC_KEY_LEN) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
    }
    if (status == PSA_SUCCESS &&
            wt_hsm_relay_write_resp(runtime, partition_id, msg->handle, out,
                                    out_len) != WT_FFM_SUCCESS) {
        status = PSA_ERROR_GENERIC_ERROR;
    }
    wt_forceZero(digest, sizeof(digest));
    wt_forceZero(out, sizeof(out));
    return status;
}

int wt_hsm_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
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
#if defined(WT_PKCS11_HSM_RESTART_PROBE) && \
    (WT_PKCS11_HSM_RESTART_PROBE == 1)
    else if (msg.type == WT_HSM_OP_TEST_RESTART && msg.client_id < 0) {
        wt_arch_sp_fault_probe(0U);
        reply_status = PSA_ERROR_GENERIC_ERROR;
    }
#endif
    else if (msg.type == PSA_IPC_CALL) {
#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
        /* Authorize before copying the request. The backend repeats the
         * identity-to-namespace check before touching wolfHSM state. */
        if (msg.client_id < 0 ||
                (g_relay_secure_client > 0 &&
                 msg.client_id == g_relay_secure_client)) {
#else
        if (msg.client_id < 0) {
#endif
            reply_status = wt_hsm_relay_call(runtime, partition_id, &msg);
        }
        else {
            reply_status = PSA_ERROR_NOT_PERMITTED;
        }
    } else if (msg.type == WT_HSM_OP_ATTEST_SIGN ||
               msg.type == WT_HSM_OP_ATTEST_PUBLIC_KEY) {
        reply_status = wt_hsm_relay_attest_call(runtime, partition_id, &msg);
    } else {
        reply_status = PSA_ERROR_NOT_SUPPORTED;
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
