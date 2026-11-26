/* spm_gate.c
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

#include "wolftrust/spm_gate.h"

#include "wolftrust/spm_core.h"

static int wt_spm_check_buffer(const wt_secure_domain_t* domain,
                               const void* buffer, size_t len, int need_write)
{
    if (len == 0U) {
        return WT_FFM_SUCCESS;
    }
    if (buffer == NULL) {
        return WT_FFM_ERROR_BUFFER;
    }
    /* NULL domain: the host direct transport, where the caller owns it. */
    if (domain != NULL && wt_secure_domain_contains(domain, (uintptr_t)buffer,
            len, need_write) == 0) {
        return WT_FFM_ERROR_BUFFER;
    }
    return WT_FFM_SUCCESS;
}

/* Every SP vector base must lie in the acting partition's own domain. */
static int wt_spm_sp_vectors(const wt_secure_domain_t* domain,
                             const wt_spm_call_t* call, wt_spm_vec_t* vec)
{
    size_t i;
    int ret = WT_FFM_SUCCESS;

    if (call->sp_in_len > WT_SPM_SP_IOVEC ||
            call->sp_out_len > WT_SPM_SP_IOVEC) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    for (i = 0U; i < PSA_MAX_IOVEC && ret == WT_FFM_SUCCESS; i++) {
        vec[i].base = (void*)(uintptr_t)call->sp_in[i].base;
        vec[i].len = i < call->sp_in_len ? call->sp_in[i].len : 0U;
        vec[PSA_MAX_IOVEC + i].base = call->sp_out[i].base;
        vec[PSA_MAX_IOVEC + i].len = i < call->sp_out_len ?
                                     call->sp_out[i].len : 0U;
        ret = wt_spm_check_buffer(domain, vec[i].base, vec[i].len, 0);
        if (ret == WT_FFM_SUCCESS) {
            ret = wt_spm_check_buffer(domain, vec[PSA_MAX_IOVEC + i].base,
                                      vec[PSA_MAX_IOVEC + i].len, 1);
        }
    }
    return ret;
}

/* Starts a client message, or on the resume pass harvests it; returns 1 when
 * the reply is in, 0 when the caller blocks or the begin pass refused. */
static int wt_spm_client_op(wt_spm_call_t* call, int32_t kind, int32_t begun)
{
    int done;

    if (call->pending_valid == 0U) {
        if (begun < 0 || begun == (int32_t)WT_SPM_NO_SLOT) {
            return 0;
        }
        call->pending_msg = (uint16_t)begun;
        call->pending_valid = 1U;
        call->ret_int = WT_FFM_ERROR_NOT_READY;
        return 0;
    }
    done = wt_spm_done((uint8_t)call->pending_msg,
                       (psa_client_id_t)call->partition_id, kind);
    if (done <= 0) {
        call->ret_int = done < 0 ? WT_FFM_ERROR_ARGUMENT :
                                   WT_FFM_ERROR_NOT_READY;
        return 0;
    }
    call->pending_valid = 0U;
    call->ret_int = WT_FFM_SUCCESS;
    return 1;
}

static void wt_spm_gate_client(const wt_secure_domain_t* domain,
                               wt_spm_call_t* call)
{
    wt_spm_vec_t vec[WT_SPM_VECS];
    psa_client_id_t caller = (psa_client_id_t)call->partition_id;
    int32_t begun = 0;
    size_t i;

    call->ret_int = WT_FFM_SUCCESS;
    switch (call->op) {
    case WT_SPM_OP_CONNECT:
        if (call->pending_valid == 0U) {
            begun = wt_spm_connect_begin(caller, call->sid, call->version);
            call->ret_handle = (psa_handle_t)begun;
            /* FF-M: an SPM policy refusal panics a Secure caller; BUSY and
             * a refusal the service replied stay returnable. */
            call->must_panic = begun == PSA_ERROR_CONNECTION_REFUSED ||
                               begun == PSA_ERROR_NOT_SUPPORTED;
        }
        if (wt_spm_client_op(call, PSA_IPC_CONNECT, begun)) {
            call->ret_handle = wt_spm_connect_finish(
                (uint8_t)call->pending_msg);
        }
        break;
    case WT_SPM_OP_CALL:
        if (wt_spm_sp_vectors(domain, call, vec) != WT_FFM_SUCCESS) {
            /* Out-of-domain vectors panic a Secure caller (FF-M). */
            call->ret_status = PSA_ERROR_PROGRAMMER_ERROR;
            call->must_panic = 1U;
            break;
        }
        if (call->pending_valid == 0U) {
            begun = wt_spm_call_begin(caller, call->msg_handle,
                                      call->call_type, vec, call->sp_in_len,
                                      call->sp_out_len);
            call->ret_status = begun < 0 ? (psa_status_t)begun : PSA_SUCCESS;
            call->must_panic = begun == PSA_ERROR_PROGRAMMER_ERROR;
        }
        if (wt_spm_client_op(call, PSA_IPC_CALL, begun)) {
            call->ret_status = wt_spm_call_finish((uint8_t)call->pending_msg,
                                                  vec);
            for (i = 0U; i < call->sp_out_len; i++) {
                call->sp_out[i].len = vec[PSA_MAX_IOVEC + i].len;
            }
            /* A server's PROGRAMMER_ERROR panics a Secure client (i027). */
            call->must_panic = call->ret_status == PSA_ERROR_PROGRAMMER_ERROR;
        }
        break;
    default:
        if (call->pending_valid == 0U) {
            begun = wt_spm_close_begin(caller, call->msg_handle);
            /* psa_close on a bad or busy handle panics a Secure caller. */
            call->ret_int = begun < 0 ? (int)begun : WT_FFM_SUCCESS;
            call->must_panic = begun < 0;
        }
        if (wt_spm_client_op(call, PSA_IPC_DISCONNECT, begun)) {
            wt_spm_close_finish((uint8_t)call->pending_msg);
        }
        break;
    }
}

/* Each FF-M misuse below panics the server (FF-M 1.0 section 4, i013-i062);
 * an exhausted vector or an empty poll stays a legal return. */
static int wt_spm_gate_held(const wt_secure_domain_t* domain,
                            wt_spm_call_t* call)
{
    int sp = wt_spm_sp_index(call->partition_id);
    uint8_t index = (uint8_t)sp;
    uint32_t irq = 0U;
    int ret = WT_FFM_ERROR_ARGUMENT;

    call->ret_status = PSA_ERROR_PROGRAMMER_ERROR;
    call->ret_size = 0U;
    call->must_panic = 0U;
    if (call->op == WT_SPM_OP_CONNECT || call->op == WT_SPM_OP_CALL ||
            call->op == WT_SPM_OP_CLOSE) {
        wt_spm_gate_client(domain, call);
        return WT_FFM_SUCCESS;
    }
    if (call->op == WT_SPM_OP_VERSION) {
        call->ret_version = wt_spm_service_version(
            (psa_client_id_t)call->partition_id, call->sid);
        call->ret_int = WT_FFM_SUCCESS;
        return WT_FFM_SUCCESS;
    }
    if (call->op == WT_SPM_OP_LIFECYCLE) {
        call->ret_version = g_wt_spm.lifecycle;
        call->ret_int = WT_FFM_SUCCESS;
        return WT_FFM_SUCCESS;
    }
    if (sp < 0) {
        call->ret_int = WT_FFM_ERROR_ARGUMENT;
        call->must_panic = 1U;
        return WT_FFM_SUCCESS;
    }
    switch (call->op) {
    case WT_SPM_OP_WAIT:
        ret = wt_spm_check_buffer(domain, call->asserted,
                                  sizeof(*call->asserted), 1);
        if (ret == WT_FFM_SUCCESS) {
            ret = wt_spm_wait(index, call->signal_mask, call->asserted);
        }
        call->must_panic = ret != WT_FFM_SUCCESS &&
                           ret != WT_FFM_ERROR_NOT_READY;
        break;
    case WT_SPM_OP_GET:
        ret = wt_spm_check_buffer(domain, call->msg, sizeof(*call->msg), 1);
        call->ret_status = (psa_status_t)ret;
        if (ret == WT_FFM_SUCCESS) {
            call->ret_status = wt_spm_get(index, call->signal, call->msg);
        }
        call->must_panic = call->ret_status != PSA_SUCCESS;
        break;
#if defined(WT_FFM_SP_RHANDLE) && (WT_FFM_SP_RHANDLE == 1)
    case WT_SPM_OP_SET_RHANDLE:
        ret = wt_spm_set_rhandle(index, call->msg_handle, call->rhandle);
        call->must_panic = ret != WT_FFM_SUCCESS;
        break;
#endif
    case WT_SPM_OP_READ:
#if defined(WT_FFM_SP_SKIP) && (WT_FFM_SP_SKIP == 1)
    case WT_SPM_OP_SKIP:
#endif
    case WT_SPM_OP_WRITE:
        ret = call->op == WT_SPM_OP_SKIP ? WT_FFM_SUCCESS :
              wt_spm_check_buffer(domain, call->buffer, call->num_bytes,
                                  call->op == WT_SPM_OP_READ);
        if (ret == WT_FFM_SUCCESS) {
            ret = wt_spm_copy(index, call->msg_handle, call->vec_idx,
                              call->op == WT_SPM_OP_SKIP ? NULL : call->buffer,
                              call->num_bytes, call->op == WT_SPM_OP_WRITE,
                              &call->ret_size);
        }
        call->must_panic = ret != WT_FFM_SUCCESS;
        break;
    case WT_SPM_OP_REPLY:
        ret = wt_spm_reply(index, call->msg_handle, call->status);
        call->must_panic = ret != WT_FFM_SUCCESS;
        break;
#if defined(WT_FFM_SP_DOORBELL) && (WT_FFM_SP_DOORBELL == 1)
    case WT_SPM_OP_NOTIFY:
        ret = wt_spm_notify(call->notify_partition);
        call->must_panic = ret != WT_FFM_SUCCESS;
        break;
    case WT_SPM_OP_CLEAR:
        ret = wt_spm_clear(index, PSA_DOORBELL);
        call->must_panic = ret != WT_FFM_SUCCESS;
        break;
#endif
    case WT_SPM_OP_EOI:
    case WT_SPM_OP_IRQ_ENABLE:
        /* The arch layer unmasks interrupt ret_version on success. */
        ret = wt_spm_irq_of(index, call->signal_mask, &irq);
        if (ret == WT_FFM_SUCCESS && call->op == WT_SPM_OP_EOI) {
            ret = wt_spm_clear(index, call->signal_mask);
        }
        call->ret_version = irq;
        call->must_panic = ret != WT_FFM_SUCCESS;
        break;
    default:
        return WT_FFM_ERROR_ARGUMENT;
    }
    call->ret_int = ret;
    return WT_FFM_SUCCESS;
}

int wt_spm_gate(wt_ffm_runtime_t* runtime,
                const wt_secure_domain_t* caller_domain,
                wt_spm_call_t* call)
{
    wt_spm_call_t held;
    int ret;

    (void)runtime;
    if (call == NULL) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    /* The block lives in the caller's memory: read it once, so every check
     * and every use sees the same vectors, handles and resume state. */
    held = *call;
    ret = wt_spm_gate_held(caller_domain, &held);
    *call = held;
    return ret;
}

int wt_spm_call_would_block(const wt_spm_call_t* call)
{
    if (call == NULL || call->ret_int != WT_FFM_ERROR_NOT_READY) {
        return 0;
    }
    if (call->op == WT_SPM_OP_WAIT) {
        return (call->timeout & PSA_BLOCK) != 0U;
    }
    return call->op == WT_SPM_OP_CONNECT ||
           call->op == WT_SPM_OP_CALL || call->op == WT_SPM_OP_CLOSE;
}

int wt_spm_transport_direct(wt_ffm_runtime_t* runtime, wt_spm_call_t* call)
{
    int status = wt_spm_gate(runtime, NULL, call);
    unsigned int guard = 0U;

    /* Host stand-in for the scheduler wake: run the partitions the blocked
     * request queued for, then harvest. Bounded against a silent service. */
    while (status == WT_FFM_SUCCESS && call->pending_valid != 0U &&
            call->ret_int == WT_FFM_ERROR_NOT_READY && guard < 8U) {
        wt_spm_run();
        status = wt_spm_gate(runtime, NULL, call);
        guard++;
    }
    return status;
}
