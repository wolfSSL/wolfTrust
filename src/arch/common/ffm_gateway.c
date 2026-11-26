/* ffm_gateway.c
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

/* Architecture-neutral Non-secure client gateway: caller identity from the
 * active guest, one snapshot of the guest's vectors checked once, then the
 * core's begin, the partition scheduler, and finish. The arch layer owns the
 * entry mechanism and the Non-secure range checks (wt_arch_ns_check_*). */

#include "wolftrust/ffm_gateway.h"

#include <string.h>

#include "wolftrust/arch.h"
#include "wolftrust/platform.h"
#include "wolftrust/spm_core.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_sched.h"
#include "wolftrust/static_assert.h"
#include "wolftrust/types.h"

WT_STATIC_ASSERT(WT_FFM_VENEER_IOVEC_MAX == PSA_MAX_IOVEC,
    "the veneer carries every FF-M vector");

#if defined(WT_TARGET_BUILD)
int wt_spm_caller_can_write(psa_client_id_t caller, void* base, size_t len)
{
    if (caller > 0) {
        return wt_spm_partition_memory_ok((int32_t)caller, base, len, 1);
    }
    return caller < 0 &&
           wt_arch_ns_check_write((wt_guest_id_t)(-caller - 1), base, len);
}
#endif

/* Never trust a guest-supplied id: the caller is the guest that is running. */
static int wt_ffm_gateway_enter(psa_client_id_t* caller)
{
    uint32_t guest_id = wt_arch_active_guest_id();

    if (guest_id >= (uint32_t)WT_MAX_GUESTS) {
        return 0;
    }
    /* Non-secure exceptions are masked for an entry: a nested one means the
     * mask failed, and the core is not re-entrant. */
    if (g_wt_spm.ns_entry_caller != 0) {
        wt_platform_panic();
    }
    *caller = -(psa_client_id_t)(guest_id + 1U);
    g_wt_spm.ns_entry_caller = *caller;
    return 1;
}

static void wt_ffm_gateway_exit(void)
{
    g_wt_spm.ns_entry_caller = 0;
}

/* Runs the partitions until the message on slot is answered; a client that
 * cannot wait leaves it to the service, which still sees it through. */
static int wt_ffm_gateway_wait(psa_client_id_t caller, int32_t slot,
                               int32_t kind)
{
    wt_spm_run();
    if (wt_spm_done((uint8_t)slot, caller, kind) == 1) {
        return 1;
    }
    wt_spm_abandon((uint8_t)slot);
    return 0;
}

int32_t wt_ffm_gateway_connect(uint32_t sid, uint32_t version)
{
    psa_client_id_t caller;
    int32_t ret;

    if (!wt_ffm_gateway_enter(&caller)) {
        return (int32_t)PSA_NULL_HANDLE;
    }
    ret = wt_spm_connect_begin(caller, sid, version);
    if (ret >= 0) {
        ret = wt_ffm_gateway_wait(caller, ret, PSA_IPC_CONNECT) ?
              (int32_t)wt_spm_connect_finish((uint8_t)ret) :
              (int32_t)PSA_ERROR_GENERIC_ERROR;
    }
    wt_ffm_gateway_exit();
    return ret;
}

static int32_t wt_ffm_gateway_call_in(psa_client_id_t caller, int32_t handle,
                                      int32_t type,
                                      wt_ffm_veneer_iovec_t* ns_iovec)
{
    wt_ffm_veneer_iovec_t iovec;
    wt_spm_vec_t vec[WT_SPM_VECS];
    wt_guest_id_t guest = (wt_guest_id_t)(-caller - 1);
    int32_t slot;
    psa_status_t status;
    uint32_t i;
    int ok;

    iovec.in_count = 0U;
    iovec.out_count = 0U;
    ok = ns_iovec != NULL &&
         wt_arch_ns_check_writable(ns_iovec, sizeof(*ns_iovec));
    if (ok) {
        /* One read: a racing guest write cannot change what is checked. */
        iovec = *ns_iovec;
        ok = iovec.in_count <= PSA_MAX_IOVEC &&
             iovec.out_count <= PSA_MAX_IOVEC;
    }
    (void)memset(vec, 0, sizeof(vec));
    for (i = 0U; ok && i < PSA_MAX_IOVEC; i++) {
        if (i < iovec.in_count) {
            vec[i].base = (void*)(uintptr_t)iovec.in[i].base;
            vec[i].len = iovec.in[i].len;
        }
        if (i < iovec.out_count) {
            vec[PSA_MAX_IOVEC + i].base = iovec.out[i].base;
            vec[PSA_MAX_IOVEC + i].len = iovec.out[i].len;
        }
        ok = (vec[i].len == 0U ||
              wt_arch_ns_check_read(guest, vec[i].base, vec[i].len)) &&
             (vec[PSA_MAX_IOVEC + i].len == 0U ||
              wt_arch_ns_check_write(guest, vec[PSA_MAX_IOVEC + i].base,
                                     vec[PSA_MAX_IOVEC + i].len));
    }
    if (!ok) {
        /* FF-M: memory the caller cannot access is a PROGRAMMER ERROR. */
        wt_spm_call_refuse(caller, (psa_handle_t)handle);
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    slot = wt_spm_call_begin(caller, (psa_handle_t)handle, type, vec,
                             iovec.in_count, iovec.out_count);
    if (slot < 0) {
        return slot;
    }
    if (!wt_ffm_gateway_wait(caller, slot, PSA_IPC_CALL)) {
        return (int32_t)PSA_ERROR_GENERIC_ERROR;
    }
    status = wt_spm_call_finish((uint8_t)slot, vec);
    for (i = 0U; i < iovec.out_count; i++) {
        ns_iovec->out[i].len = (uint32_t)vec[PSA_MAX_IOVEC + i].len;
    }
    return (int32_t)status;
}

int32_t wt_ffm_gateway_call(int32_t handle, int32_t type,
                            wt_ffm_veneer_iovec_t* ns_iovec)
{
    psa_client_id_t caller;
    int32_t status;

    if (!wt_ffm_gateway_enter(&caller)) {
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    status = wt_ffm_gateway_call_in(caller, handle, type, ns_iovec);
    wt_ffm_gateway_exit();
    return status;
}

void wt_ffm_gateway_close(int32_t handle)
{
    psa_client_id_t caller;
    int32_t slot;

    if (!wt_ffm_gateway_enter(&caller)) {
        return;
    }
    slot = wt_spm_close_begin(caller, (psa_handle_t)handle);
    if (slot >= 0 && slot != (int32_t)WT_SPM_NO_SLOT &&
            wt_ffm_gateway_wait(caller, slot, PSA_IPC_DISCONNECT)) {
        wt_spm_close_finish((uint8_t)slot);
    }
    wt_ffm_gateway_exit();
}

uint32_t wt_ffm_gateway_framework_version(void)
{
    return g_wt_spm_framework_version;
}

uint32_t wt_ffm_gateway_service_version(uint32_t sid)
{
    uint32_t guest_id = wt_arch_active_guest_id();

    if (guest_id >= (uint32_t)WT_MAX_GUESTS) {
        return PSA_VERSION_NONE;
    }
    return wt_spm_service_version(-(psa_client_id_t)(guest_id + 1U), sid);
}
