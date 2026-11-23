/* spm_host.c
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

#include "spm_host.h"

#include <string.h>

#define WT_SPM_HOST_IRQS 8U

wt_spm_service_t g_wt_spm_services[WT_SPM_MAX_SERVICES];
uint8_t g_wt_spm_service_count;
wt_spm_sp_ipc_t g_wt_spm_sps[WT_SPM_MAX_SPS];
uint8_t g_wt_spm_sp_count;
wt_spm_irq_t g_wt_spm_irqs[WT_SPM_HOST_IRQS];
uint8_t g_wt_spm_irq_count;
uint32_t g_wt_spm_framework_version;

typedef struct wt_spm_host_sp {
    wt_ffm_dispatch_fn dispatch;
    void* context;
    int busy;
} wt_spm_host_sp_t;

static wt_spm_host_sp_t g_host_sp[WT_SPM_MAX_SPS];
static const wt_spm_host_ops_t* g_host_ops;
static void* g_host_context;

static int wt_spm_host_check(psa_client_id_t caller, void* base, size_t len,
                             int write)
{
    if (len == 0U || g_host_ops == NULL) {
        return 1;
    }
    if (write) {
        return g_host_ops->check_write == NULL ||
               g_host_ops->check_write(g_host_context, caller, base, len);
    }
    return g_host_ops->check_read == NULL ||
           g_host_ops->check_read(g_host_context, caller, base, len);
}

int wt_spm_host_init(const wt_system_manifest_t* manifest,
                     const wt_spm_host_ops_t* ops, void* context)
{
    wt_spm_tables_t tables;
    uint32_t sp;
    int ret;

    (void)memset(g_host_sp, 0, sizeof(g_host_sp));
    (void)memset(&tables, 0, sizeof(tables));
    g_host_ops = ops;
    g_host_context = context;
    wt_spm_core_init();
    tables.services = g_wt_spm_services;
    tables.sps = g_wt_spm_sps;
    tables.irqs = g_wt_spm_irqs;
    tables.irq_cap = WT_SPM_HOST_IRQS;
    ret = wt_spm_tables_derive(manifest, &tables);
    g_wt_spm_service_count = tables.service_count;
    g_wt_spm_sp_count = ret == WT_SPM_OK ? tables.sp_count : 0U;
    g_wt_spm_irq_count = tables.irq_count;
    g_wt_spm_framework_version = tables.framework_version;
    for (sp = 0U; ops != NULL && sp < WT_SPM_MAX_SPS; sp++) {
        g_host_sp[sp].dispatch = ops->dispatch;
        g_host_sp[sp].context = context;
    }
    return ret;
}

int wt_spm_host_bind(int32_t partition_id, wt_ffm_dispatch_fn dispatch,
                     void* context)
{
    int sp = wt_spm_sp_index(partition_id);

    if (sp < 0 || dispatch == NULL) {
        return WT_FFM_ERROR_POLICY;
    }
    g_host_sp[sp].dispatch = dispatch;
    g_host_sp[sp].context = context;
    return WT_FFM_SUCCESS;
}

wt_ffm_runtime_t* wt_spm_host_runtime(void)
{
    return &g_wt_spm;
}

#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
int wt_spm_host_restarted(int32_t partition_id, psa_status_t status)
{
    int sp = wt_spm_sp_index(partition_id);

    return sp < 0 ? WT_FFM_ERROR_POLICY :
                    wt_spm_sp_restarted((uint8_t)sp, status);
}
#endif

int wt_spm_caller_can_write(psa_client_id_t caller, void* base, size_t len)
{
    return wt_spm_host_check(caller, base, len, 1);
}

void wt_spm_run(void)
{
    unsigned int pass;
    unsigned int sp;
    int ran = 1;

    /* A partition mid-dispatch is never re-entered by its own nested call. */
    for (pass = 0U; pass < 64U && ran != 0; pass++) {
        ran = 0;
        for (sp = 0U; sp < g_wt_spm_sp_count; sp++) {
            if (g_host_sp[sp].dispatch == NULL || g_host_sp[sp].busy != 0 ||
                    wt_spm_pending((uint8_t)sp) == 0U) {
                continue;
            }
            g_host_sp[sp].busy = 1;
            (void)g_host_sp[sp].dispatch(g_host_sp[sp].context, &g_wt_spm,
                                         g_wt_spm_sps[sp].pid);
            g_host_sp[sp].busy = 0;
            ran = 1;
        }
    }
}

psa_handle_t wt_spm_host_connect(psa_client_id_t caller, uint32_t sid,
                                 uint32_t version)
{
    int32_t slot = wt_spm_connect_begin(caller, sid, version);

    if (slot < 0) {
        return (psa_handle_t)slot;
    }
    wt_spm_run();
    if (wt_spm_done((uint8_t)slot, caller, PSA_IPC_CONNECT) != 1) {
        wt_spm_abandon((uint8_t)slot);
        return (psa_handle_t)PSA_ERROR_GENERIC_ERROR;
    }
    return wt_spm_connect_finish((uint8_t)slot);
}

psa_status_t wt_spm_host_call(psa_client_id_t caller, psa_handle_t handle,
                              int32_t type, const psa_invec* in_vec,
                              size_t in_len, psa_outvec* out_vec,
                              size_t out_len)
{
    wt_spm_vec_t vec[WT_SPM_VECS];
    psa_status_t status;
    int32_t slot;
    size_t i;
    int ok = (in_len == 0U || in_vec != NULL) &&
             (out_len == 0U || out_vec != NULL);

    (void)memset(vec, 0, sizeof(vec));
    for (i = 0U; ok && i < PSA_MAX_IOVEC; i++) {
        if (i < in_len) {
            vec[i].base = (void*)(uintptr_t)in_vec[i].base;
            vec[i].len = in_vec[i].len;
        }
        if (i < out_len) {
            vec[PSA_MAX_IOVEC + i].base = out_vec[i].base;
            vec[PSA_MAX_IOVEC + i].len = out_vec[i].len;
        }
        ok = wt_spm_host_check(caller, vec[i].base, vec[i].len, 0) &&
             wt_spm_host_check(caller, vec[PSA_MAX_IOVEC + i].base,
                               vec[PSA_MAX_IOVEC + i].len, 1);
    }
    if (!ok) {
        /* A vector outside the caller's memory drops the connection. */
        wt_spm_call_refuse(caller, handle);
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    slot = wt_spm_call_begin(caller, handle, type, vec, in_len, out_len);
    if (slot < 0) {
        return (psa_status_t)slot;
    }
    wt_spm_run();
    if (wt_spm_done((uint8_t)slot, caller, PSA_IPC_CALL) != 1) {
        wt_spm_abandon((uint8_t)slot);
        return PSA_ERROR_GENERIC_ERROR;
    }
    status = wt_spm_call_finish((uint8_t)slot, vec);
    for (i = 0U; i < out_len && i < PSA_MAX_IOVEC; i++) {
        out_vec[i].len = vec[PSA_MAX_IOVEC + i].len;
    }
    return status;
}

int wt_spm_host_close(psa_client_id_t caller, psa_handle_t handle)
{
    int32_t slot = wt_spm_close_begin(caller, handle);

    if (slot < 0 || slot == (int32_t)WT_SPM_NO_SLOT) {
        return slot < 0 ? (int)slot : WT_FFM_SUCCESS;
    }
    wt_spm_run();
    if (wt_spm_done((uint8_t)slot, caller, PSA_IPC_DISCONNECT) != 1) {
        wt_spm_abandon((uint8_t)slot);
        return WT_FFM_ERROR_NOT_READY;
    }
    wt_spm_close_finish((uint8_t)slot);
    return WT_FFM_SUCCESS;
}

static int wt_spm_host_sp(int32_t pid, uint8_t* sp)
{
    int index = wt_spm_sp_index(pid);

    *sp = (uint8_t)index;
    return index >= 0;
}

int wt_spm_host_wait(int32_t pid, psa_signal_t mask, psa_signal_t* asserted)
{
    uint8_t sp;

    return wt_spm_host_sp(pid, &sp) ? wt_spm_wait(sp, mask, asserted) :
                                      WT_SPM_E_POLICY;
}

psa_status_t wt_spm_host_get(int32_t pid, psa_signal_t signal,
                             psa_msg_t* msg)
{
    uint8_t sp;

    return wt_spm_host_sp(pid, &sp) ? wt_spm_get(sp, signal, msg) :
                                      PSA_ERROR_PROGRAMMER_ERROR;
}

int wt_spm_host_reply(int32_t pid, psa_handle_t msg, psa_status_t status)
{
    uint8_t sp;

    return wt_spm_host_sp(pid, &sp) ? wt_spm_reply(sp, msg, status) :
                                      WT_SPM_E_POLICY;
}

size_t wt_spm_host_read(int32_t pid, psa_handle_t msg, uint32_t idx,
                        void* buffer, size_t len)
{
    size_t done = 0U;
    uint8_t sp;

    if (wt_spm_host_sp(pid, &sp)) {
        (void)wt_spm_copy(sp, msg, idx, buffer, len, 0, &done);
    }
    return done;
}

size_t wt_spm_host_skip(int32_t pid, psa_handle_t msg, uint32_t idx,
                        size_t len)
{
    return wt_spm_host_read(pid, msg, idx, NULL, len);
}

int wt_spm_host_write(int32_t pid, psa_handle_t msg, uint32_t idx,
                      const void* buffer, size_t len)
{
    size_t done = 0U;
    uint8_t sp;

    return wt_spm_host_sp(pid, &sp) ?
           wt_spm_copy(sp, msg, idx, (void*)(uintptr_t)buffer, len, 1,
                       &done) :
           WT_SPM_E_POLICY;
}

int wt_spm_host_set_rhandle(int32_t pid, psa_handle_t msg, void* rhandle)
{
#if defined(WT_FFM_SP_RHANDLE) && (WT_FFM_SP_RHANDLE == 1)
    uint8_t sp;

    return wt_spm_host_sp(pid, &sp) ? wt_spm_set_rhandle(sp, msg, rhandle) :
                                      WT_SPM_E_POLICY;
#else
    (void)pid;
    (void)msg;
    (void)rhandle;
    return WT_SPM_E_POLICY;
#endif
}

int wt_spm_host_clear(int32_t pid)
{
    uint8_t sp;

    return wt_spm_host_sp(pid, &sp) ? wt_spm_clear(sp, PSA_DOORBELL) :
                                      WT_SPM_E_POLICY;
}

int wt_spm_host_eoi(int32_t pid, psa_signal_t irq_signal)
{
    uint32_t irq;
    uint8_t sp;
    int ret = WT_SPM_E_POLICY;

    if (wt_spm_host_sp(pid, &sp)) {
        ret = wt_spm_irq_of(sp, irq_signal, &irq);
    }
    if (ret == WT_SPM_OK) {
        ret = wt_spm_clear(sp, irq_signal);
    }
    return ret;
}

void wt_spm_host_panic(int32_t pid)
{
    if (g_host_ops != NULL && g_host_ops->panic != NULL) {
        g_host_ops->panic(g_host_context, pid);
    }
}
