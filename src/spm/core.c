/* core.c
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

/* FF-M 1.0 connection-based IPC (DEN 0063 section 4). Every connection is a
 * slot that also carries its one in-flight message. */

#include "wolftrust/spm_core.h"

#include <string.h>

#include "wolftrust/manifest.h"
#include "wolftrust/zeroize.h"

#define WT_HANDLE_CONN  1U
#define WT_HANDLE_MSG   2U
#define WT_HANDLE_SHIFT 7U

enum {
    WT_SLOT_FREE = 0,
    WT_SLOT_CONNECTING,
    WT_SLOT_IDLE,
    WT_SLOT_ERROR,
    WT_SLOT_BUSY,
    WT_SLOT_CLOSING
};

enum {
    WT_MSG_NONE = 0,
    WT_MSG_QUEUED,
    WT_MSG_ACTIVE,
    WT_MSG_DONE
};

/* Detached: the client left this message; REPLY keeps the connection for a
 * later close, CLOSE releases it once the service has seen a DISCONNECT. */
enum {
    WT_DETACH_NONE = 0,
    WT_DETACH_REPLY,
    WT_DETACH_CLOSE
};

wt_spm_core_t g_wt_spm;

static psa_handle_t wt_handle(uint32_t type, uint32_t index, uint32_t tag)
{
    return (psa_handle_t)(((tag & 0x00FFFFFFU) << WT_HANDLE_SHIFT) |
                          (type << 5) | (index + 1U));
}

static int wt_decode(psa_handle_t handle, uint32_t type, uint32_t* tag)
{
    uint32_t value = (uint32_t)handle;
    uint32_t index = value & 0x1FU;

    if (handle <= 0 || ((value >> 5) & 0x3U) != type || index == 0U ||
            index > WT_SPM_SLOTS) {
        return -1;
    }
    *tag = value >> WT_HANDLE_SHIFT;
    return (int)index - 1;
}

int wt_spm_sp_index(int32_t pid)
{
    int i;

    for (i = 0; i < (int)g_wt_spm_sp_count; i++) {
        if (g_wt_spm_sps[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

static int wt_find_service(uint32_t sid)
{
    int i;

    for (i = 0; sid != 0U && i < (int)g_wt_spm_service_count; i++) {
        if (g_wt_spm_services[i].sid == sid) {
            return i;
        }
    }
    return -1;
}

static int wt_allowed(psa_client_id_t caller, int svc)
{
    int sp;

    if (caller < 0) {
        return g_wt_spm_services[svc].ns_ok != 0U;
    }
    sp = wt_spm_sp_index(caller);
    return sp >= 0 && (g_wt_spm_sps[sp].deps & (1UL << (uint32_t)svc)) != 0U;
}

static int wt_version_ok(const wt_spm_service_t* svc, uint32_t version)
{
    if (version == 0U) {
        return 0;
    }
    if (svc->policy == (uint8_t)WT_SERVICE_VERSION_UNSPECIFIED) {
        return 1;
    }
    if (svc->policy == (uint8_t)WT_SERVICE_VERSION_STRICT) {
        return version == svc->version;
    }
    return version <= svc->version;
}

static void wt_xfer_free(wt_spm_slot_t* slot)
{
    if (slot->xfer != 0U) {
        wt_forceZero(&g_wt_spm.xfer[slot->xfer - 1U],
                     sizeof(g_wt_spm.xfer[0]));
        slot->xfer = 0U;
    }
}

static void wt_end_msg(wt_spm_slot_t* slot)
{
    wt_xfer_free(slot);
    slot->msg = WT_MSG_NONE;
    slot->detached = WT_DETACH_NONE;
}

/* The client will never collect output: forget where it would have gone. */
static void wt_detach(wt_spm_slot_t* slot, uint8_t how)
{
    if (slot->xfer != 0U) {
        (void)memset(g_wt_spm.xfer[slot->xfer - 1U].dst, 0,
                     sizeof(g_wt_spm.xfer[0].dst));
    }
    slot->detached = how;
}

static void wt_release(wt_spm_slot_t* slot)
{
    uint16_t gen = (uint16_t)(slot->gen + 1U);

    wt_xfer_free(slot);
    (void)memset(slot, 0, sizeof(*slot));
    slot->gen = gen;
}

static void wt_queue(wt_spm_slot_t* slot, int32_t type)
{
    slot->type = type;
    slot->msg = WT_MSG_QUEUED;
    slot->ticket = g_wt_spm.ticket++;
}

void wt_spm_core_init(void)
{
    (void)memset(&g_wt_spm, 0, sizeof(g_wt_spm));
}

uint32_t wt_spm_service_version(psa_client_id_t caller, uint32_t sid)
{
    int svc = wt_find_service(sid);

    if (svc < 0 || caller == 0 || !wt_allowed(caller, svc)) {
        return PSA_VERSION_NONE;
    }
    return g_wt_spm_services[svc].version;
}

static int wt_conn_slot(psa_client_id_t caller, psa_handle_t handle)
{
    uint32_t tag;
    int index = wt_decode(handle, WT_HANDLE_CONN, &tag);
    const wt_spm_slot_t* slot;

    if (index < 0) {
        return WT_SPM_E_HANDLE;
    }
    slot = &g_wt_spm.slot[index];
    if (slot->state == WT_SLOT_FREE || slot->gen != tag) {
        return WT_SPM_E_HANDLE;
    }
    return slot->caller == caller ? index : WT_SPM_E_POLICY;
}

static int wt_msg_slot(uint8_t sp, psa_handle_t handle)
{
    uint32_t tag;
    int index = wt_decode(handle, WT_HANDLE_MSG, &tag);
    const wt_spm_slot_t* slot;

    if (index < 0) {
        return WT_SPM_E_HANDLE;
    }
    slot = &g_wt_spm.slot[index];
    if (slot->msg != WT_MSG_ACTIVE || slot->mgen != tag ||
            g_wt_spm_services[slot->svc].sp != sp) {
        return WT_SPM_E_HANDLE;
    }
    return index;
}

psa_status_t wt_spm_connect_begin(psa_client_id_t caller, uint32_t sid,
                                  uint32_t version, uint8_t* out)
{
    int svc = wt_find_service(sid);
    uint32_t mine = 0U;
    uint32_t ns = 0U;
    int free_slot = -1;
    int i;
    wt_spm_slot_t* slot;

    if (caller == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (svc < 0 || !wt_allowed(caller, svc) ||
            !wt_version_ok(&g_wt_spm_services[svc], version)) {
        return PSA_ERROR_CONNECTION_REFUSED;
    }
    if (g_wt_spm_services[svc].conn == 0U) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    for (i = (int)WT_SPM_SLOTS - 1; i >= 0; i--) {
        slot = &g_wt_spm.slot[i];
        if (slot->state == WT_SLOT_FREE) {
            free_slot = i;
        }
        else {
            mine += slot->caller == caller ? 1U : 0U;
            ns += slot->caller < 0 ? 1U : 0U;
        }
    }
    /* Quotas keep one client, or all guests, from starving the pool. */
    if (free_slot < 0 || mine >= WT_SPM_SLOTS_PER_CLIENT ||
            (caller < 0 && ns >= WT_SPM_NS_SLOTS)) {
        return PSA_ERROR_CONNECTION_BUSY;
    }
    slot = &g_wt_spm.slot[free_slot];
    slot->caller = caller;
    slot->svc = (uint8_t)svc;
    slot->state = WT_SLOT_CONNECTING;
    wt_queue(slot, PSA_IPC_CONNECT);
    *out = (uint8_t)free_slot;
    return PSA_SUCCESS;
}

static void wt_drop(wt_spm_slot_t* slot)
{
    if (slot->state == WT_SLOT_IDLE) {
        slot->state = WT_SLOT_ERROR;
    }
    else {
        slot->latch = 1U;
    }
}

void wt_spm_call_refuse(psa_client_id_t caller, psa_handle_t handle)
{
    int index = wt_conn_slot(caller, handle);

    if (caller != 0 && index >= 0) {
        wt_drop(&g_wt_spm.slot[index]);
    }
}

psa_status_t wt_spm_call_begin(psa_client_id_t caller, psa_handle_t handle,
                               int32_t type, const wt_spm_vec_t* vec,
                               size_t in_len, size_t out_len, uint8_t* out)
{
    int index = caller == 0 ? WT_SPM_E_ARGUMENT : wt_conn_slot(caller, handle);
    wt_spm_slot_t* slot;
    wt_spm_xfer_t* xfer = NULL;
    size_t total = 0U;
    size_t i;
    uint32_t x;

    if (index < 0) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    slot = &g_wt_spm.slot[index];
    if (type < 0 || in_len > PSA_MAX_IOVEC ||
            out_len > PSA_MAX_IOVEC - in_len || slot->state != WT_SLOT_IDLE) {
        wt_drop(slot);
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    for (i = 0U; i < in_len + out_len; i++) {
        if (vec[i].len > WT_SPM_TRANSFER_BYTES - total) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        total += vec[i].len;
    }
    for (x = 0U; x < WT_SPM_TRANSFERS && xfer == NULL; x++) {
        if (g_wt_spm.xfer[x].used == 0U) {
            xfer = &g_wt_spm.xfer[x];
        }
    }
    if (xfer == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    total = 0U;
    for (i = 0U; i < in_len + out_len; i++) {
        xfer->off[i] = (uint16_t)total;
        xfer->len[i] = (uint16_t)vec[i].len;
        if (i >= in_len) {
            xfer->dst[i - in_len] = vec[i].base;
        }
        else if (vec[i].len != 0U) {
            (void)memcpy(&xfer->buf[total], vec[i].base, vec[i].len);
        }
        total += vec[i].len;
    }
    xfer->in_count = (uint8_t)in_len;
    xfer->out_count = (uint8_t)out_len;
    xfer->used = 1U;
    slot->xfer = (uint8_t)x;
    slot->state = WT_SLOT_BUSY;
    wt_queue(slot, type);
    *out = (uint8_t)index;
    return PSA_SUCCESS;
}

psa_status_t wt_spm_close_begin(psa_client_id_t caller, psa_handle_t handle,
                                uint8_t* out)
{
    int index;
    wt_spm_slot_t* slot;

    *out = WT_SPM_NO_SLOT;
    if (handle == PSA_NULL_HANDLE) {
        return PSA_SUCCESS;
    }
    index = caller == 0 ? WT_SPM_E_ARGUMENT : wt_conn_slot(caller, handle);
    if (index < 0) {
        return index;
    }
    slot = &g_wt_spm.slot[index];
    if (slot->state != WT_SLOT_IDLE && slot->state != WT_SLOT_ERROR) {
        return WT_SPM_E_STATE;
    }
    slot->state = WT_SLOT_CLOSING;
    if (slot->detached == WT_DETACH_REPLY) {
        /* The service still holds the abandoned call: disconnect after it. */
        slot->detached = WT_DETACH_CLOSE;
        return PSA_SUCCESS;
    }
    wt_queue(slot, PSA_IPC_DISCONNECT);
    *out = (uint8_t)index;
    return PSA_SUCCESS;
}

int wt_spm_done(uint8_t slot)
{
    return slot < WT_SPM_SLOTS && g_wt_spm.slot[slot].msg == WT_MSG_DONE;
}

psa_handle_t wt_spm_connect_finish(uint8_t index)
{
    wt_spm_slot_t* slot = &g_wt_spm.slot[index];
    psa_status_t status = slot->status;

    slot->msg = WT_MSG_NONE;
    if (status != PSA_SUCCESS) {
        wt_release(slot);
        return (psa_handle_t)status;
    }
    return wt_handle(WT_HANDLE_CONN, index, slot->gen);
}

psa_status_t wt_spm_call_finish(uint8_t index, size_t out_len[PSA_MAX_IOVEC])
{
    wt_spm_slot_t* slot = &g_wt_spm.slot[index];
    wt_spm_xfer_t* xfer = &g_wt_spm.xfer[slot->xfer - 1U];
    psa_status_t status = slot->status;
    uint32_t o;
    uint32_t v;

    /* Publish all output or none: check every destination first. */
    for (o = 0U; o < xfer->out_count; o++) {
        v = xfer->in_count + o;
        if (xfer->pos[v] != 0U && !wt_spm_caller_can_write(slot->caller,
                xfer->dst[o], xfer->pos[v])) {
            status = PSA_ERROR_PROGRAMMER_ERROR;
            slot->state = WT_SLOT_ERROR;
        }
    }
    for (o = 0U; o < PSA_MAX_IOVEC; o++) {
        v = xfer->in_count + o;
        out_len[o] = 0U;
        if (status != PSA_ERROR_PROGRAMMER_ERROR && o < xfer->out_count) {
            if (xfer->pos[v] != 0U) {
                (void)memcpy(xfer->dst[o], &xfer->buf[xfer->off[v]],
                             xfer->pos[v]);
            }
            out_len[o] = xfer->pos[v];
        }
    }
    wt_end_msg(slot);
    return status;
}

void wt_spm_close_finish(uint8_t index)
{
    wt_release(&g_wt_spm.slot[index]);
}

void wt_spm_abandon(uint8_t index)
{
    wt_spm_slot_t* slot = &g_wt_spm.slot[index];

    if (slot->type == PSA_IPC_DISCONNECT || slot->msg != WT_MSG_QUEUED) {
        wt_detach(slot, slot->type >= PSA_IPC_CALL ? WT_DETACH_REPLY :
                                                     WT_DETACH_CLOSE);
        if (slot->type >= PSA_IPC_CALL) {
            slot->state = WT_SLOT_ERROR;
            slot->latch = 1U;
        }
    }
    else if (slot->type == PSA_IPC_CONNECT) {
        wt_release(slot);
    }
    else {
        wt_end_msg(slot);
        slot->state = WT_SLOT_ERROR;
    }
}

psa_signal_t wt_spm_pending(uint8_t sp)
{
    psa_signal_t set = g_wt_spm.asserted[sp];
    uint32_t i;

    for (i = 0U; i < WT_SPM_SLOTS; i++) {
        const wt_spm_slot_t* slot = &g_wt_spm.slot[i];

        if (slot->msg == WT_MSG_QUEUED &&
                g_wt_spm_services[slot->svc].sp == sp) {
            set |= g_wt_spm_services[slot->svc].signal;
        }
    }
    return set;
}

int wt_spm_wait(uint8_t sp, psa_signal_t mask, psa_signal_t* asserted)
{
    /* FF-M 4.5.3: a mask naming none of the caller's signals is an error;
     * unassigned bits beside an assigned one are ignored. */
    if ((mask & g_wt_spm_sps[sp].signals) == 0U) {
        return WT_SPM_E_ARGUMENT;
    }
    *asserted = wt_spm_pending(sp) & mask;
    return *asserted == 0U ? WT_SPM_E_NOT_READY : WT_SPM_OK;
}

psa_status_t wt_spm_get(uint8_t sp, psa_signal_t signal, psa_msg_t* msg)
{
    wt_spm_slot_t* best = NULL;
    uint32_t best_age = 0U;
    uint32_t best_index = 0U;
    uint32_t i;

    if (signal == 0U) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    for (i = 0U; i < WT_SPM_SLOTS; i++) {
        wt_spm_slot_t* slot = &g_wt_spm.slot[i];
        uint32_t age = (uint8_t)(g_wt_spm.ticket - slot->ticket);

        if (slot->msg == WT_MSG_QUEUED &&
                g_wt_spm_services[slot->svc].sp == sp &&
                g_wt_spm_services[slot->svc].signal == signal &&
                (best == NULL || age > best_age)) {
            best = slot;
            best_age = age;
            best_index = i;
        }
    }
    if (best == NULL) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }
    best->msg = WT_MSG_ACTIVE;
    (void)memset(msg, 0, sizeof(*msg));
    msg->handle = wt_handle(WT_HANDLE_MSG, best_index, best->mgen);
    msg->type = best->type;
    msg->client_id = best->caller;
    msg->rhandle = (void*)best->rhandle;
    if (best->xfer != 0U) {
        const wt_spm_xfer_t* xfer = &g_wt_spm.xfer[best->xfer - 1U];

        for (i = 0U; i < xfer->in_count; i++) {
            msg->in_size[i] = xfer->len[i];
        }
        for (i = 0U; i < xfer->out_count; i++) {
            msg->out_size[i] = xfer->len[xfer->in_count + i];
        }
    }
    return PSA_SUCCESS;
}

int wt_spm_set_rhandle(uint8_t sp, psa_handle_t msg, void* rhandle)
{
    int index = wt_msg_slot(sp, msg);

    if (index < 0) {
        return index;
    }
    if (g_wt_spm.slot[index].type != PSA_IPC_DISCONNECT) {
        g_wt_spm.slot[index].rhandle = (uintptr_t)rhandle;
    }
    return WT_SPM_OK;
}

int wt_spm_copy(uint8_t sp, psa_handle_t msg, uint32_t idx, void* buffer,
                size_t len, int write, size_t* done)
{
    int index = idx >= PSA_MAX_IOVEC ? WT_SPM_E_ARGUMENT :
                                       wt_msg_slot(sp, msg);
    wt_spm_xfer_t* xfer;
    uint32_t count;
    uint32_t v;
    size_t left;
    uint8_t* at;

    *done = 0U;
    if (index < 0) {
        return index;
    }
    if (g_wt_spm.slot[index].type < PSA_IPC_CALL) {
        return WT_SPM_E_STATE;
    }
    xfer = &g_wt_spm.xfer[g_wt_spm.slot[index].xfer - 1U];
    count = write ? xfer->out_count : xfer->in_count;
    v = write ? xfer->in_count + idx : idx;
    /* FF-M: an omitted vector has zero capacity. */
    left = idx < count ? (size_t)xfer->len[v] - xfer->pos[v] : 0U;
    if (!write && len > left) {
        len = left;
    }
    if (len > left || (write && buffer == NULL && len != 0U)) {
        return WT_SPM_E_BUFFER;
    }
    if (len != 0U && buffer != NULL) {
        at = &xfer->buf[xfer->off[v] + xfer->pos[v]];
        (void)memcpy(write ? at : buffer, write ? buffer : at, len);
    }
    if (len != 0U) {
        xfer->pos[v] = (uint16_t)(xfer->pos[v] + len);
    }
    *done = len;
    return WT_SPM_OK;
}

static void wt_detached_reply(wt_spm_slot_t* slot)
{
    if ((slot->type == PSA_IPC_CONNECT && slot->status == PSA_SUCCESS) ||
            (slot->type >= PSA_IPC_CALL &&
             slot->detached == WT_DETACH_CLOSE)) {
        /* The service set up per-connection state: let it see a DISCONNECT. */
        wt_xfer_free(slot);
        slot->state = WT_SLOT_CLOSING;
        slot->detached = WT_DETACH_CLOSE;
        wt_queue(slot, PSA_IPC_DISCONNECT);
    }
    else if (slot->type < PSA_IPC_CALL) {
        wt_release(slot);
    }
    else {
        wt_end_msg(slot);
    }
}

int wt_spm_reply(uint8_t sp, psa_handle_t msg, psa_status_t status)
{
    int index = wt_msg_slot(sp, msg);
    wt_spm_slot_t* slot;
    int connect_status;

    if (index < 0) {
        return index;
    }
    slot = &g_wt_spm.slot[index];
    connect_status = status == PSA_SUCCESS ||
                     status == PSA_ERROR_CONNECTION_REFUSED ||
                     status == PSA_ERROR_CONNECTION_BUSY;
    /* FF-M reserves REFUSED and BUSY for connect replies (i020). */
    if (slot->type == PSA_IPC_CONNECT) {
        if (!connect_status) {
            return WT_SPM_E_ARGUMENT;
        }
        slot->state = status == PSA_SUCCESS ? WT_SLOT_IDLE : WT_SLOT_ERROR;
    }
    else if (slot->type >= PSA_IPC_CALL) {
        if (connect_status && status != PSA_SUCCESS) {
            return WT_SPM_E_ARGUMENT;
        }
        slot->state = (status == PSA_ERROR_PROGRAMMER_ERROR ||
                       slot->latch != 0U) ? WT_SLOT_ERROR : WT_SLOT_IDLE;
    }
    slot->status = status;
    slot->msg = WT_MSG_DONE;
    slot->mgen++;
    if (slot->detached != WT_DETACH_NONE) {
        wt_detached_reply(slot);
    }
    return WT_SPM_OK;
}

int wt_spm_notify(int32_t pid)
{
    int sp = wt_spm_sp_index(pid);

    if (sp < 0) {
        return WT_SPM_E_POLICY;
    }
    g_wt_spm.asserted[sp] |= PSA_DOORBELL;
    return WT_SPM_OK;
}

static int wt_clear_signal(uint8_t sp, psa_signal_t signal)
{
    if ((g_wt_spm.asserted[sp] & signal) == 0U) {
        return WT_SPM_E_STATE;
    }
    g_wt_spm.asserted[sp] &= ~signal;
    return WT_SPM_OK;
}

int wt_spm_clear(uint8_t sp)
{
    return wt_clear_signal(sp, PSA_DOORBELL);
}

int wt_spm_irq_of(uint8_t sp, psa_signal_t irq_signal, uint32_t* irq)
{
    uint32_t i;

    /* FF-M: exactly one interrupt signal. */
    if (irq_signal == 0U || (irq_signal & (irq_signal - 1U)) != 0U) {
        return WT_SPM_E_ARGUMENT;
    }
    for (i = 0U; i < g_wt_spm_irq_count; i++) {
        if (g_wt_spm_irqs[i].sp == sp &&
                g_wt_spm_irqs[i].signal == irq_signal) {
            *irq = g_wt_spm_irqs[i].irq;
            return WT_SPM_OK;
        }
    }
    return WT_SPM_E_POLICY;
}

int wt_spm_eoi(uint8_t sp, psa_signal_t irq_signal)
{
    uint32_t irq;
    int ret = wt_spm_irq_of(sp, irq_signal, &irq);

    return ret != WT_SPM_OK ? ret : wt_clear_signal(sp, irq_signal);
}

int wt_spm_irq_assert(uint32_t irq)
{
    uint32_t i;

    for (i = 0U; i < g_wt_spm_irq_count; i++) {
        if (g_wt_spm_irqs[i].irq == irq) {
            g_wt_spm.asserted[g_wt_spm_irqs[i].sp] |= g_wt_spm_irqs[i].signal;
            return (int)g_wt_spm_irqs[i].sp;
        }
    }
    return WT_SPM_E_POLICY;
}

void wt_spm_client_gone(psa_client_id_t caller)
{
    uint32_t i;

    for (i = 0U; i < WT_SPM_SLOTS; i++) {
        wt_spm_slot_t* slot = &g_wt_spm.slot[i];

        if (slot->state == WT_SLOT_FREE || slot->caller != caller) {
            continue;
        }
        if (slot->msg == WT_MSG_ACTIVE) {
            /* The service holds the message: release after its reply. */
            wt_detach(slot, WT_DETACH_CLOSE);
            slot->state = WT_SLOT_CLOSING;
            slot->gen++;
            continue;
        }
        wt_release(slot);
    }
    if (g_wt_spm.ns_entry_caller == caller) {
        g_wt_spm.ns_entry_caller = 0;
    }
}

#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
int wt_spm_sp_restarted(uint8_t sp, psa_status_t status)
{
    int failed = 0;
    uint32_t i;

    for (i = 0U; i < WT_SPM_SLOTS; i++) {
        wt_spm_slot_t* slot = &g_wt_spm.slot[i];

        if (slot->state == WT_SLOT_FREE ||
                g_wt_spm_services[slot->svc].sp != sp) {
            continue;
        }
        slot->rhandle = 0U;
        slot->state = WT_SLOT_ERROR;
        if (slot->msg != WT_MSG_QUEUED && slot->msg != WT_MSG_ACTIVE) {
            continue;
        }
        failed++;
        slot->status = status;
        slot->msg = WT_MSG_DONE;
        slot->mgen++;
        if (slot->xfer != 0U) {
            /* Output the faulted server staged is discarded, not published. */
            (void)memset(g_wt_spm.xfer[slot->xfer - 1U].pos, 0,
                         sizeof(g_wt_spm.xfer[0].pos));
        }
        if (slot->detached == WT_DETACH_CLOSE) {
            wt_release(slot);
        }
        else if (slot->detached == WT_DETACH_REPLY) {
            wt_end_msg(slot);
        }
    }
    wt_spm_client_gone(g_wt_spm_sps[sp].pid);
    g_wt_spm.asserted[sp] = 0U;
    return failed;
}
#endif
