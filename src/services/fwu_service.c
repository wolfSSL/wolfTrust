/* fwu_service.c
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

#include "wolftrust/services/fwu_service.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* Largest write block copied into the SP's private buffer per WRITE message
 * (WT-FFM-0041 copied transfers). The client streams the image in chunks no
 * larger than this. */
#define WT_FWU_BLOCK_MAX 1024u

static int wt_fwu_component_ok(uint32_t component)
{
    return component == WT_FWU_COMPONENT_PRIMARY;
}

int wt_fwu_wolfboot_arm_trailer(uint8_t* block, uint32_t len)
{
    uint32_t i;

    if (block == NULL || len < 5u) {
        return -1;
    }
    for (i = 0u; i < len; i++) {
        block[i] = 0xFFu;
    }
    block[len - 5u] = (uint8_t)WT_WOLFBOOT_IMG_STATE_UPDATING;
    block[len - 4u] = (uint8_t)(WT_WOLFBOOT_MAGIC_TRAIL & 0xFFu);
    block[len - 3u] = (uint8_t)((WT_WOLFBOOT_MAGIC_TRAIL >> 8) & 0xFFu);
    block[len - 2u] = (uint8_t)((WT_WOLFBOOT_MAGIC_TRAIL >> 16) & 0xFFu);
    block[len - 1u] = (uint8_t)((WT_WOLFBOOT_MAGIC_TRAIL >> 24) & 0xFFu);
    return 0;
}

psa_status_t wt_fwu_start(wt_fwu_service_ctx_t* ctx, uint32_t component,
                          uint32_t version)
{
    if (ctx == NULL || ctx->backend == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (!wt_fwu_component_ok(component)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->state != PSA_FWU_READY) {
        return PSA_ERROR_BAD_STATE;
    }
    /* Reject a rolled-back candidate before the update partition is touched;
     * an undeclared version is bound from the image header at FINISH. */
    if (version != WT_FWU_VERSION_UNDECLARED && version < ctx->version_floor) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (ctx->backend->begin != NULL &&
            ctx->backend->begin(ctx->backend_ctx) != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    ctx->state = PSA_FWU_WRITING;
    ctx->write_high = 0u;
    ctx->candidate_version = version;
    ctx->armed = 0u;
    return PSA_SUCCESS;
}

psa_status_t wt_fwu_write(wt_fwu_service_ctx_t* ctx, uint32_t component,
                          uint32_t offset, const uint8_t* data, uint32_t size)
{
    uint8_t tail[WT_FWU_BLOCK_MAX];
    uint32_t align = 1u;
    uint32_t end = 0u;
    uint32_t prefix = 0u;
    uint32_t remainder = 0u;
    uint32_t padding = 0u;
    psa_status_t status = PSA_SUCCESS;

    if (ctx == NULL || ctx->backend == NULL) {
        status = PSA_ERROR_BAD_STATE;
    }
    else if (!wt_fwu_component_ok(component) || data == NULL || size == 0u) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    else if (ctx->state != PSA_FWU_WRITING) {
        status = PSA_ERROR_BAD_STATE;
    }
    else {
        align = ctx->backend->align;
        if (align == 0u) {
            align = 1u;
        }
        end = offset + size;
        if (end < offset || end > ctx->backend->capacity ||
                (offset % align) != 0u) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            remainder = size % align;
            if (remainder != 0u) {
                padding = align - remainder;
                prefix = size - remainder;
                if (align > sizeof(tail) || end > UINT32_MAX - padding ||
                        end + padding > ctx->backend->capacity) {
                    status = PSA_ERROR_INVALID_ARGUMENT;
                }
                else {
                    if (prefix != 0u && ctx->backend->write != NULL &&
                            ctx->backend->write(ctx->backend_ctx, offset,
                                                data, prefix) != 0) {
                        status = PSA_ERROR_STORAGE_FAILURE;
                    }
                    if (status == PSA_SUCCESS) {
                        (void)memset(tail, 0xFF, align);
                        (void)memcpy(tail, data + prefix, remainder);
                        if (ctx->backend->write != NULL &&
                                ctx->backend->write(ctx->backend_ctx,
                                                    offset + prefix, tail,
                                                    align) != 0) {
                            status = PSA_ERROR_STORAGE_FAILURE;
                        }
                    }
                }
            }
            else if (ctx->backend->write != NULL &&
                    ctx->backend->write(ctx->backend_ctx, offset, data,
                                        size) != 0) {
                status = PSA_ERROR_STORAGE_FAILURE;
            }
        }
    }
    if (status == PSA_ERROR_STORAGE_FAILURE) {
        /* A partial program invalidates the candidate: never arm it. */
        ctx->state = PSA_FWU_FAILED;
        ctx->error = PSA_ERROR_STORAGE_FAILURE;
    }
    else if (status == PSA_SUCCESS && end > ctx->write_high) {
        /* Logical image size excludes backend padding bytes. */
        ctx->write_high = end;
    }
    wt_forceZero(tail, sizeof(tail));
    return status;
}

psa_status_t wt_fwu_finish(wt_fwu_service_ctx_t* ctx, uint32_t component)
{
    uint32_t header_version = 0u;

    if (ctx == NULL || ctx->backend == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (!wt_fwu_component_ok(component)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->state != PSA_FWU_WRITING) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->write_high == 0u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Bind the candidate to the staged bytes: a malformed image or a header
     * version that contradicts the declared one never becomes CANDIDATE, so
     * the pre-arm rollback check runs against authenticated-header data. An
     * undeclared version adopts the header's; without a header parser it
     * cannot be bound at all and fails closed. */
    if (ctx->backend->verify != NULL) {
        if (ctx->backend->verify(ctx->backend_ctx, ctx->write_high,
                                 &header_version) != 0) {
            ctx->state = PSA_FWU_FAILED;
            ctx->error = PSA_ERROR_INVALID_ARGUMENT;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (ctx->candidate_version == WT_FWU_VERSION_UNDECLARED) {
            ctx->candidate_version = header_version;
        }
        else if (header_version != ctx->candidate_version) {
            ctx->state = PSA_FWU_FAILED;
            ctx->error = PSA_ERROR_NOT_PERMITTED;
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    if (ctx->candidate_version == WT_FWU_VERSION_UNDECLARED ||
            ctx->candidate_version < ctx->version_floor) {
        ctx->state = PSA_FWU_FAILED;
        ctx->error = PSA_ERROR_NOT_PERMITTED;
        return PSA_ERROR_NOT_PERMITTED;
    }
    ctx->state = PSA_FWU_CANDIDATE;
    return PSA_SUCCESS;
}

psa_status_t wt_fwu_install(wt_fwu_service_ctx_t* ctx)
{
    if (ctx == NULL || ctx->backend == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->state != PSA_FWU_CANDIDATE) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->backend->arm == NULL || ctx->backend->disarm == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    /* Final anti-rollback guard immediately before the swap is armed. */
    if (ctx->candidate_version < ctx->version_floor) {
        ctx->state = PSA_FWU_FAILED;
        ctx->error = PSA_ERROR_NOT_PERMITTED;
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (ctx->backend->arm(ctx->backend_ctx, ctx->write_high,
                          ctx->candidate_version) != 0) {
        /* Arming failed: stay a candidate, no swap pending. */
        return PSA_ERROR_STORAGE_FAILURE;
    }
    ctx->state = PSA_FWU_STAGED;
    ctx->armed = 1u;
    return PSA_SUCCESS_REBOOT;
}

psa_status_t wt_fwu_cancel(wt_fwu_service_ctx_t* ctx, uint32_t component)
{
    if (ctx == NULL || ctx->backend == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (!wt_fwu_component_ok(component)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->state != PSA_FWU_WRITING && ctx->state != PSA_FWU_CANDIDATE) {
        return PSA_ERROR_BAD_STATE;
    }
    /* Client-requested abandonment is not a fault: FAILED with no error. */
    ctx->state = PSA_FWU_FAILED;
    ctx->error = PSA_SUCCESS;
    return PSA_SUCCESS;
}

psa_status_t wt_fwu_clean(wt_fwu_service_ctx_t* ctx, uint32_t component)
{
    if (ctx == NULL || ctx->backend == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (!wt_fwu_component_ok(component)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->state != PSA_FWU_FAILED && ctx->state != PSA_FWU_UPDATED) {
        return PSA_ERROR_BAD_STATE;
    }
    /* If a swap was already armed, clear the trigger so the prior image runs. */
    if (ctx->armed != 0u && ctx->backend->disarm != NULL &&
            ctx->backend->disarm(ctx->backend_ctx) != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    ctx->state = PSA_FWU_READY;
    ctx->write_high = 0u;
    ctx->candidate_version = 0u;
    ctx->armed = 0u;
    ctx->error = PSA_SUCCESS;
    return PSA_SUCCESS;
}

psa_status_t wt_fwu_reject(wt_fwu_service_ctx_t* ctx, psa_status_t error)
{
    if (ctx == NULL || ctx->backend == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    /* Installation commits at the authenticated-launch reboot, so TRIAL never
     * persists; reject applies to a STAGED (not yet rebooted) component. */
    if (ctx->state != PSA_FWU_STAGED) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->armed != 0u && ctx->backend->disarm != NULL &&
            ctx->backend->disarm(ctx->backend_ctx) != 0) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    ctx->armed = 0u;
    ctx->state = PSA_FWU_FAILED;
    ctx->error = error;
    return PSA_SUCCESS;
}

psa_status_t wt_fwu_request_reboot(wt_fwu_service_ctx_t* ctx)
{
    wt_spm_call_t call;

    if (ctx == NULL || ctx->transport == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    /* A platform reset is granted only to complete an armed STAGED install;
     * any other state would let a guest reset unrelated guests at will. */
    if (ctx->state != PSA_FWU_STAGED || ctx->armed == 0u) {
        return PSA_ERROR_BAD_STATE;
    }
    /* The reset is a privileged platform op: hop through the FWU-pinned SVC
     * gate. On target a granted reboot does not return; anywhere the gate
     * lacks the platform op (host), report it unsupported. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_FWU_BACKEND;
    call.call_type = WT_SPM_FWU_REBOOT;
    if (ctx->transport(NULL, &call) != WT_FFM_SUCCESS || call.ret_int != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS_REBOOT;
}

psa_status_t wt_fwu_query(wt_fwu_service_ctx_t* ctx, uint32_t component,
                          psa_fwu_component_info_t* info)
{
    if (ctx == NULL || ctx->backend == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (info == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!wt_fwu_component_ok(component)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memset(info, 0, sizeof(*info));
    info->state = (uint8_t)ctx->state;
    info->error = (ctx->state == PSA_FWU_FAILED) ? ctx->error : PSA_SUCCESS;
    /* wolfBoot versions are one monotonic word, carried in build. The public
     * field is the ACTIVE image version (PSA FWU 1.0 defines no candidate
     * slot); the declared candidate stays private in the service context. */
    info->version.build = ctx->active_version;
    info->max_size = ctx->backend->capacity;
    info->impl.staged_size = ctx->write_high;
    return PSA_SUCCESS;
}

/* Drain invec[0] — [wt_fwu_req_t][block] — into a bounded private buffer. */
static int wt_fwu_read_in(wt_fwu_service_ctx_t* ctx, wt_ffm_runtime_t* runtime,
                          int32_t partition_id, psa_handle_t msg_handle,
                          uint8_t* buffer, size_t capacity, size_t* out_len)
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

static int wt_fwu_write_out(wt_fwu_service_ctx_t* ctx,
                            wt_ffm_runtime_t* runtime, int32_t partition_id,
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

int wt_fwu_owner_expired(psa_client_id_t owner, uint32_t owner_tick,
                         uint32_t now_tick, psa_client_id_t caller)
{
    if (owner == 0 || caller == owner) {
        return 0;
    }
    /* Unsigned subtraction wraps correctly across the 32-bit tick counter. */
    if ((uint32_t)(now_tick - owner_tick) >= WT_FWU_OWNER_IDLE_TIMEOUT_TICKS) {
        return 1;
    }
    return 0;
}

/* Reclaim an abandoned session: disarm any pending swap and return to READY so
 * a new client may start. Never advances the version floor or arms a swap. */
static psa_status_t wt_fwu_force_reset(wt_fwu_service_ctx_t* ctx)
{
    if (ctx->armed != 0u &&
            (ctx->backend == NULL || ctx->backend->disarm == NULL ||
             ctx->backend->disarm(ctx->backend_ctx) != 0)) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    ctx->state = PSA_FWU_READY;
    ctx->write_high = 0u;
    ctx->candidate_version = 0u;
    ctx->armed = 0u;
    ctx->error = PSA_SUCCESS;
    ctx->owner = 0;
    return PSA_SUCCESS;
}

static psa_status_t wt_fwu_service_call(wt_fwu_service_ctx_t* ctx,
                                        wt_ffm_runtime_t* runtime,
                                        int32_t partition_id,
                                        const psa_msg_t* msg,
                                        uint32_t now_tick)
{
    uint8_t buffer[sizeof(wt_fwu_req_t) + WT_FWU_BLOCK_MAX];
    wt_fwu_req_t req;
    psa_fwu_component_info_t info;
    size_t in_len = 0U;
    psa_status_t status;

    if (msg->in_size[0] < sizeof(req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* An input larger than the header plus the maximum block is malformed. */
    if (msg->in_size[0] > sizeof(buffer)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_fwu_read_in(ctx, runtime, partition_id, msg->handle, buffer,
                       sizeof(buffer), &in_len) != WT_FFM_SUCCESS ||
            in_len < sizeof(req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memcpy(&req, buffer, sizeof(req));

    /* Reclaim a session whose owner has gone idle past the timeout so one
     * client that opens an update and stops cannot wedge updates for everyone
     * (DoS). An active owner refreshes its clock on every op below. */
    if (wt_fwu_owner_expired(ctx->owner, ctx->owner_tick, now_tick,
                             msg->client_id)) {
        status = wt_fwu_force_reset(ctx);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    /* Per-transaction owner: only the client that opened the update (START)
     * may drive or reboot it, so one guest cannot hijack, monopolize, arm, or
     * reboot another guest's update (CWE-862). QUERY is read-only; START binds
     * a new owner (and wt_fwu_start itself refuses a second concurrent one). */
    if (msg->type != WT_FWU_OP_QUERY && msg->type != WT_FWU_OP_START &&
            ctx->owner != 0 && msg->client_id != ctx->owner) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    switch (msg->type) {
    case WT_FWU_OP_QUERY:
        if (msg->out_size[0] < sizeof(info)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = wt_fwu_query(ctx, req.component, &info);
        if (status == PSA_SUCCESS &&
                wt_fwu_write_out(ctx, runtime, partition_id, msg->handle,
                                 &info, sizeof(info)) != WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        break;
    case WT_FWU_OP_START:
        status = wt_fwu_start(ctx, req.component, req.version);
        if (status == PSA_SUCCESS) {
            ctx->owner = msg->client_id;
            ctx->owner_tick = now_tick;
        }
        break;
    case WT_FWU_OP_WRITE:
        if (req.size != (uint32_t)(in_len - sizeof(req))) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
        }
        status = wt_fwu_write(ctx, req.component, req.offset,
                              buffer + sizeof(req),
                              (uint32_t)(in_len - sizeof(req)));
        break;
    case WT_FWU_OP_FINISH:
        status = wt_fwu_finish(ctx, req.component);
        break;
    case WT_FWU_OP_INSTALL:
        status = wt_fwu_install(ctx);
        break;
    case WT_FWU_OP_CANCEL:
        status = wt_fwu_cancel(ctx, req.component);
        break;
    case WT_FWU_OP_CLEAN:
        status = wt_fwu_clean(ctx, req.component);
        break;
    case WT_FWU_OP_REJECT:
        /* The client's error code rides the version field of the wire header. */
        status = wt_fwu_reject(ctx, (psa_status_t)req.version);
        break;
    case WT_FWU_OP_REBOOT:
        status = wt_fwu_request_reboot(ctx);
        break;
    case WT_FWU_OP_ACCEPT:
        /* Installation commits at the authenticated-launch reboot; the TRIAL
         * flow is not offered (recorded in the compatibility register). */
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }
    /* The transaction is over once no update is in progress (cancel, clean, or
     * reject returned to READY); an installed-and-pending update keeps its
     * owner until the reboot. Release the owner so the next client may start. */
    if (ctx->state == PSA_FWU_READY) {
        ctx->owner = 0;
    } else if (ctx->owner != 0 && msg->client_id == ctx->owner &&
               msg->type != WT_FWU_OP_QUERY && msg->type != WT_FWU_OP_START) {
        /* Refresh the idle clock only on owner progress (a state-mutating op),
         * never on a read-only QUERY, so an owner cannot keep an abandoned
         * session pinned by polling status under the timeout. START binds the
         * clock in its own case. */
        ctx->owner_tick = now_tick;
    }
    return status;
}

int wt_fwu_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                            int32_t partition_id)
{
    wt_fwu_service_ctx_t* ctx = (wt_fwu_service_ctx_t*)context;
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;

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
    } else if (msg.type >= WT_FWU_OP_QUERY && msg.type <= WT_FWU_OP_ACCEPT) {
        reply_status = wt_fwu_service_call(ctx, runtime, partition_id, &msg,
                                           call.ret_tick);
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
