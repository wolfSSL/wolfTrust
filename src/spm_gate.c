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

static int wt_spm_check_buffer(const wt_secure_domain_t* domain,
                               const void* buffer, size_t len, int need_write)
{
    if (domain == NULL)
        return WT_FFM_SUCCESS; /* validation disabled: caller owns the range */
    if (len == 0U)
        return WT_FFM_SUCCESS; /* FF-M zero-length transfer: nothing crosses */
    if (buffer == NULL)
        return WT_FFM_ERROR_BUFFER;
    if (wt_secure_domain_contains(domain, (uintptr_t)buffer, len, need_write)
            == 0)
        return WT_FFM_ERROR_BUFFER;
    return WT_FFM_SUCCESS;
}

/* A resumed CONNECT/CALL/CLOSE may only harvest a message the acting
 * partition itself created; a forged pending_msg cannot reach another
 * caller's message. */
static int wt_spm_pending_owned(const wt_ffm_runtime_t* runtime,
                                const wt_spm_call_t* call)
{
    if (call->pending_msg >= WT_FFM_MAX_MESSAGES)
        return 0;
    if (runtime->messages[call->pending_msg].allocated == 0U)
        return 0;
    return runtime->messages[call->pending_msg].caller ==
           (psa_client_id_t)call->partition_id;
}

/* Every SP-supplied vector base must lie inside the acting partition's own
 * domain before the SPM captures or writes it. */
static int wt_spm_check_sp_vectors(const wt_secure_domain_t* domain,
                                   const wt_spm_call_t* call)
{
    size_t i;
    int ret;

    if (call->sp_in_len > WT_SPM_SP_IOVEC ||
            call->sp_out_len > WT_SPM_SP_IOVEC)
        return WT_FFM_ERROR_ARGUMENT;
    for (i = 0U; i < call->sp_in_len; i++) {
        if (call->sp_in[i].len == 0U)
            continue;
        ret = wt_spm_check_buffer(domain, call->sp_in[i].base,
                                  call->sp_in[i].len, 0);
        if (ret != WT_FFM_SUCCESS)
            return ret;
    }
    for (i = 0U; i < call->sp_out_len; i++) {
        if (call->sp_out[i].len == 0U)
            continue;
        ret = wt_spm_check_buffer(domain, call->sp_out[i].base,
                                  call->sp_out[i].len, 1);
        if (ret != WT_FFM_SUCCESS)
            return ret;
    }
    return WT_FFM_SUCCESS;
}

int wt_spm_gate(wt_ffm_runtime_t* runtime,
                const wt_secure_domain_t* caller_domain,
                wt_spm_call_t* call)
{
    int ret;

    if (runtime == NULL || call == NULL)
        return WT_FFM_ERROR_ARGUMENT;

    call->ret_status = PSA_ERROR_PROGRAMMER_ERROR;
    call->ret_size = 0U;
    call->ret_int = WT_FFM_ERROR_ARGUMENT;
    call->must_panic = 0U;

    switch (call->op) {
    case WT_SPM_OP_WAIT:
        ret = wt_spm_check_buffer(caller_domain, call->asserted,
                                  sizeof(*call->asserted), 1);
        if (ret == WT_FFM_SUCCESS) {
            ret = wt_ffm_wait(runtime, call->partition_id, call->signal_mask,
                              call->asserted);
            /* A mask with no assignable signal is a PROGRAMMER ERROR (i062);
             * a poll miss (NOT_READY) stays a legal return. */
            if (ret == WT_FFM_ERROR_ARGUMENT) {
                call->must_panic = 1U;
            }
        }
        else {
            call->must_panic = 1U;
        }
        call->ret_int = ret;
        break;
    case WT_SPM_OP_GET:
        ret = wt_spm_check_buffer(caller_domain, call->msg, sizeof(*call->msg),
                                  1);
        if (ret == WT_FFM_SUCCESS) {
            call->ret_status = wt_ffm_get(runtime, call->partition_id,
                                          call->signal, call->msg);
            /* psa_get on a multi-bit, non-service, or unasserted signal —
             * or with no queued message — is a PROGRAMMER ERROR the SPM
             * must panic the server for (i013-i016). */
            if (call->ret_status != PSA_SUCCESS) {
                call->must_panic = 1U;
            }
        }
        else {
            /* psa_get with an invalid message buffer is a programmer error
             * the SPM must panic the caller for (FF-M). */
            call->ret_status = (psa_status_t)ret;
            call->must_panic = 1U;
        }
        call->ret_int = ret;
        break;
    case WT_SPM_OP_SET_RHANDLE:
        call->ret_int = wt_ffm_set_rhandle(runtime, call->partition_id,
                                           call->msg_handle, call->rhandle);
        /* psa_set_rhandle on a forged or null message handle must panic
         * the server (i018/i019). */
        if (call->ret_int != WT_FFM_SUCCESS) {
            call->must_panic = 1U;
        }
        break;
    case WT_SPM_OP_READ:
        /* psa_read on a connect/disconnect message, a forged or null handle,
         * or an out-of-range vector index must panic the server (i028-i033);
         * a legal read of an exhausted vector still returns 0 bytes. */
        ret = wt_ffm_msg_access_check(runtime, call->partition_id,
                                      call->msg_handle, call->vec_idx);
        if (ret != WT_FFM_SUCCESS) {
            call->ret_int = ret;
            call->must_panic = 1U;
            break;
        }
        ret = wt_spm_check_buffer(caller_domain, call->buffer, call->num_bytes,
                                  1);
        if (ret == WT_FFM_SUCCESS) {
            call->ret_size = wt_ffm_read(runtime, call->partition_id,
                                         call->msg_handle, call->vec_idx,
                                         call->buffer, call->num_bytes);
            call->ret_int = WT_FFM_SUCCESS;
        } else {
            /* psa_read into an out-of-domain buffer must panic the caller. */
            call->ret_int = ret;
            call->must_panic = 1U;
        }
        break;
    case WT_SPM_OP_SKIP:
        /* psa_skip misuse panics like psa_read (i034-i039). */
        ret = wt_ffm_msg_access_check(runtime, call->partition_id,
                                      call->msg_handle, call->vec_idx);
        if (ret != WT_FFM_SUCCESS) {
            call->ret_int = ret;
            call->must_panic = 1U;
            break;
        }
        call->ret_size = wt_ffm_skip(runtime, call->partition_id,
                                     call->msg_handle, call->vec_idx,
                                     call->num_bytes);
        call->ret_int = WT_FFM_SUCCESS;
        break;
    case WT_SPM_OP_WRITE:
        ret = wt_spm_check_buffer(caller_domain, call->buffer, call->num_bytes,
                                  0);
        if (ret != WT_FFM_SUCCESS) {
            /* psa_write from an out-of-domain buffer must panic the caller. */
            call->must_panic = 1U;
        }
        else {
            ret = wt_ffm_write(runtime, call->partition_id, call->msg_handle,
                               call->vec_idx, call->buffer, call->num_bytes);
            /* psa_write on a bad handle/index/message type, or past the
             * out-vector's declared capacity, panics (i040-i046). */
            if (ret != WT_FFM_SUCCESS) {
                call->must_panic = 1U;
            }
        }
        call->ret_int = ret;
        break;
    case WT_SPM_OP_REPLY:
        call->ret_int = wt_ffm_reply(runtime, call->partition_id,
                                     call->msg_handle, call->status);
        /* psa_reply on a forged or null message handle, or a connect reply
         * outside SUCCESS/REFUSED/BUSY, must panic the server (i020-i023). */
        if (call->ret_int != WT_FFM_SUCCESS) {
            call->must_panic = 1U;
        }
        break;
    case WT_SPM_OP_NOTIFY:
        call->ret_int = wt_ffm_notify(runtime, call->notify_partition);
        /* psa_notify to a negative or unknown partition id panics (i059/60). */
        if (call->ret_int != WT_FFM_SUCCESS) {
            call->must_panic = 1U;
        }
        break;
    case WT_SPM_OP_CLEAR:
        call->ret_int = wt_ffm_clear(runtime, call->partition_id);
        /* psa_clear with the doorbell unasserted panics (i061). */
        if (call->ret_int != WT_FFM_SUCCESS) {
            call->must_panic = 1U;
        }
        break;
    case WT_SPM_OP_EOI:
        ret = wt_ffm_eoi(runtime, call->partition_id, call->signal_mask);
        if (ret != WT_FFM_SUCCESS) {
            /* psa_eoi with a non-interrupt, unasserted, or multiple-bit signal
             * is a programmer error the SPM must panic the caller for (FF-M). */
            call->must_panic = 1U;
        }
        else {
            /* FF-M 4.5.3: psa_eoi re-enables the interrupt. Resolve the
             * manifest-bound number here; the arch layer performs the
             * privileged controller unmask on success (ret_version = irq),
             * mirroring WT_SPM_OP_IRQ_ENABLE. */
            ret = wt_ffm_irq_lookup(runtime, call->partition_id,
                                    call->signal_mask, &call->ret_version);
        }
        call->ret_int = ret;
        break;
    case WT_SPM_OP_IRQ_ENABLE:
        /* Resolve the manifest-bound interrupt number; the arch layer performs
         * the privileged controller enable on success (ret_version = irq). */
        ret = wt_ffm_irq_lookup(runtime, call->partition_id, call->signal_mask,
                                &call->ret_version);
        if (ret != WT_FFM_SUCCESS) {
            /* psa_irq_enable on a signal the partition did not declare as an
             * interrupt is a programmer error the SPM must panic for (FF-M). */
            call->must_panic = 1U;
        }
        call->ret_int = ret;
        break;
    case WT_SPM_OP_VERSION:
        call->ret_version = wt_ffm_service_version(runtime,
                                                   call->partition_id,
                                                   call->sid);
        call->ret_int = WT_FFM_SUCCESS;
        break;
    case WT_SPM_OP_LIFECYCLE:
        call->ret_version = runtime->lifecycle;
        call->ret_int = WT_FFM_SUCCESS;
        break;
    case WT_SPM_OP_CONNECT:
        if (call->pending_valid == 0U) {
            psa_handle_t handle = wt_ffm_connect_begin(runtime,
                call->partition_id, call->sid, call->version,
                &call->pending_msg);
            if (handle <= 0) {
                call->ret_handle = handle;
                call->ret_int = WT_FFM_SUCCESS;
                /* FF-M: an SPM-level policy refusal (unknown SID, version or
                 * dependency violation) is a PROGRAMMER ERROR that must panic
                 * a Secure caller; CONNECTION_BUSY resource exhaustion and
                 * server-replied refusals stay returnable statuses. */
                if (handle == (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED ||
                        handle == (psa_handle_t)PSA_ERROR_NOT_SUPPORTED) {
                    call->must_panic = 1U;
                }
            } else {
                call->pending_valid = 1U;
                call->ret_int = WT_FFM_ERROR_NOT_READY;
            }
        } else if (wt_spm_pending_owned(runtime, call) == 0) {
            call->ret_int = WT_FFM_ERROR_ARGUMENT;
        } else if (!wt_ffm_msg_complete(runtime, call->pending_msg)) {
            call->ret_int = WT_FFM_ERROR_NOT_READY;
        } else {
            call->ret_handle = wt_ffm_connect_finish(runtime,
                                                     call->pending_msg);
            call->pending_valid = 0U;
            call->ret_int = WT_FFM_SUCCESS;
        }
        break;
    case WT_SPM_OP_CALL:
        if (call->pending_valid == 0U) {
            ret = wt_spm_check_sp_vectors(caller_domain, call);
            if (ret != WT_FFM_SUCCESS) {
                /* An SP passing an out-of-domain vector to psa_call is a
                 * PROGRAMMER ERROR that must panic a Secure caller (FF-M);
                 * only Non-secure callers may see it as a returned status. */
                call->ret_status = PSA_ERROR_PROGRAMMER_ERROR;
                call->ret_int = WT_FFM_SUCCESS;
                call->must_panic = 1U;
                break;
            }
            call->ret_status = wt_ffm_call_begin(runtime, call->partition_id,
                call->msg_handle, call->call_type, call->sp_in,
                call->sp_in_len, call->sp_out, call->sp_out_len,
                &call->pending_msg);
            if (call->ret_status != PSA_SUCCESS) {
                call->ret_int = WT_FFM_SUCCESS;
                /* FF-M: an invalid/null handle or an iovec-count violation is
                 * a PROGRAMMER ERROR that must panic a Secure caller; other
                 * statuses (BAD_STATE, resource limits) stay returnable. */
                if (call->ret_status == PSA_ERROR_PROGRAMMER_ERROR) {
                    call->must_panic = 1U;
                }
            } else {
                call->pending_valid = 1U;
                call->ret_int = WT_FFM_ERROR_NOT_READY;
            }
        } else if (wt_spm_pending_owned(runtime, call) == 0) {
            call->ret_int = WT_FFM_ERROR_ARGUMENT;
        } else if (!wt_ffm_msg_complete(runtime, call->pending_msg)) {
            call->ret_int = WT_FFM_ERROR_NOT_READY;
        } else {
            call->ret_status = wt_ffm_call_finish(runtime, call->pending_msg,
                                                  call->sp_out,
                                                  call->sp_out_len);
            call->pending_valid = 0U;
            call->ret_int = WT_FFM_SUCCESS;
            /* A server completing a call with PROGRAMMER_ERROR must panic a
             * Secure client (i027); only NS clients may see the status. */
            if (call->ret_status == PSA_ERROR_PROGRAMMER_ERROR) {
                call->must_panic = 1U;
            }
        }
        break;
    case WT_SPM_OP_CLOSE:
        if (call->pending_valid == 0U) {
            ret = wt_ffm_close_begin(runtime, call->partition_id,
                                     call->msg_handle, &call->pending_msg);
            if (ret != WT_FFM_SUCCESS) {
                /* psa_close on an invalid or in-use handle is a PROGRAMMER
                 * ERROR the SPM must panic a Secure caller for (FF-M). */
                call->ret_int = ret;
                call->must_panic = 1U;
            } else if (call->pending_msg == WT_FFM_QUEUE_NONE) {
                call->ret_int = WT_FFM_SUCCESS;
            } else {
                call->pending_valid = 1U;
                call->ret_int = WT_FFM_ERROR_NOT_READY;
            }
        } else if (wt_spm_pending_owned(runtime, call) == 0) {
            call->ret_int = WT_FFM_ERROR_ARGUMENT;
        } else if (!wt_ffm_msg_complete(runtime, call->pending_msg)) {
            call->ret_int = WT_FFM_ERROR_NOT_READY;
        } else {
            call->ret_int = wt_ffm_close_finish(runtime, call->pending_msg);
            call->pending_valid = 0U;
        }
        break;
    default:
        return WT_FFM_ERROR_ARGUMENT;
    }

    return WT_FFM_SUCCESS;
}

int wt_spm_call_would_block(const wt_spm_call_t* call)
{
    if (call == NULL)
        return 0;
    if (call->ret_int != WT_FFM_ERROR_NOT_READY)
        return 0;
    if (call->op == WT_SPM_OP_WAIT)
        return (call->timeout & PSA_BLOCK) != 0U; /* PSA_POLL never blocks */
    return call->op == WT_SPM_OP_CONNECT ||
           call->op == WT_SPM_OP_CALL || call->op == WT_SPM_OP_CLOSE;
}

int wt_spm_transport_direct(wt_ffm_runtime_t* runtime, wt_spm_call_t* call)
{
    int status = wt_spm_gate(runtime, NULL, call);
    unsigned int guard = 0U;

    /* Host stand-in for the scheduler wake: an SP-as-client begin parks the
     * message NOT_READY; dispatch the queued message inline, then harvest
     * with the finish pass. Bounded so a never-replying service cannot spin. */
    while (status == WT_FFM_SUCCESS && call->pending_valid != 0U &&
            call->ret_int == WT_FFM_ERROR_NOT_READY && guard < 8U) {
        (void)wt_ffm_dispatch_pending(runtime, call->pending_msg);
        status = wt_spm_gate(runtime, NULL, call);
        guard++;
    }
    return status;
}
