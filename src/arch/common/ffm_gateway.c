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

/* Architecture-neutral NS-client gateway for the FF-M API: caller identity
 * from the active guest, the single-snapshot NS iovec discipline, and the
 * neutral FF-M entry points. The architecture layer owns the NS entry
 * mechanism (Armv8-M: the cmse_nonsecure_entry veneers) and the NS-range
 * checks (wt_arch_ns_check_*); this file carries no such dependency. */

#include "wolftrust/ffm_gateway.h"

#include "wolftrust/arch.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/platform.h"
#include "wolftrust/types.h"

extern volatile uint32_t g_wt_ffm_call_trace;

void wt_ffm_gateway_install(void)
{
    wt_ffm_boot_set_memcheck(wt_arch_ns_check_read, wt_arch_ns_check_write);
}

/* Caller identity and NS-window validation follow the same pattern as the
 * vnet NS veneers. Never trust a guest-supplied VM id. */
static int wt_ffm_gateway_caller(psa_client_id_t* caller)
{
    uint32_t guest_id = wt_arch_active_guest_id();

    if (guest_id >= (uint32_t)WT_MAX_GUESTS) {
        return 0;
    }
    *caller = -(psa_client_id_t)(guest_id + 1U);
    return 1;
}

/* The FF-M core is not re-entrant and the port masks Non-secure exceptions
 * for an entry, so a nested entry means that mask failed: stop. */
static void wt_ffm_gateway_enter(wt_ffm_runtime_t* runtime,
                                 psa_client_id_t caller)
{
    if (runtime->ns_entry_caller != 0) {
        wt_platform_panic();
    }
    runtime->ns_entry_caller = caller;
}

static void wt_ffm_gateway_exit(wt_ffm_runtime_t* runtime)
{
    runtime->ns_entry_caller = 0;
}

int32_t wt_ffm_gateway_connect(uint32_t sid, uint32_t version)
{
    wt_ffm_runtime_t* runtime = wt_ffm_boot_runtime_mut();
    psa_client_id_t caller;
    int32_t handle;

    if (!wt_ffm_gateway_caller(&caller)) {
        return (int32_t)PSA_NULL_HANDLE;
    }
    wt_ffm_gateway_enter(runtime, caller);
    handle = (int32_t)wt_ffm_connect(runtime, caller, sid, version);
    wt_ffm_gateway_exit(runtime);
    return handle;
}

static int32_t wt_ffm_gateway_call_in(wt_ffm_runtime_t* runtime,
                                      psa_client_id_t caller, int32_t handle,
                                      int32_t type,
                                      wt_ffm_veneer_iovec_t* ns_iovec)
{
    wt_ffm_veneer_iovec_t iovec;
    psa_invec in_vec[WT_FFM_VENEER_IOVEC_MAX];
    psa_outvec out_vec[WT_FFM_VENEER_IOVEC_MAX];
    int32_t status;
    uint32_t i;

    if (ns_iovec == NULL ||
            !wt_arch_ns_check_writable(ns_iovec, sizeof(*ns_iovec))) {
        g_wt_ffm_call_trace = (2UL << 28) |
            ((uint32_t)(uintptr_t)ns_iovec & 0x0FFFFFFFUL);
        wt_ffm_call_refuse(runtime, caller,
                           (psa_handle_t)handle);
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    /* Single read into a local copy: the struct's own fields are not
     * re-read after this, so a racing NS write cannot change the vector
     * base/length wt_ffm_call validates and copies from. */
    iovec = *ns_iovec;
    if (iovec.in_count > WT_FFM_VENEER_IOVEC_MAX ||
            iovec.out_count > WT_FFM_VENEER_IOVEC_MAX) {
        wt_ffm_call_refuse(runtime, caller,
                           (psa_handle_t)handle);
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    for (i = 0U; i < iovec.in_count; i++) {
        in_vec[i].base = iovec.in[i].base;
        in_vec[i].len = iovec.in[i].len;
    }
    for (i = 0U; i < iovec.out_count; i++) {
        out_vec[i].base = iovec.out[i].base;
        out_vec[i].len = iovec.out[i].len;
    }
    status = (int32_t)wt_ffm_call(runtime, caller,
                                  (psa_handle_t)handle,
                                  type, in_vec, iovec.in_count,
                                  out_vec, iovec.out_count);
    for (i = 0U; i < iovec.out_count; i++) {
        ns_iovec->out[i].len = (uint32_t)out_vec[i].len;
    }
    return status;
}

int32_t wt_ffm_gateway_call(int32_t handle, int32_t type,
                          wt_ffm_veneer_iovec_t* ns_iovec)
{
    wt_ffm_runtime_t* runtime = wt_ffm_boot_runtime_mut();
    psa_client_id_t caller;
    int32_t status;

    if (!wt_ffm_gateway_caller(&caller)) {
        g_wt_ffm_call_trace = 1UL << 28;
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    wt_ffm_gateway_enter(runtime, caller);
    status = wt_ffm_gateway_call_in(runtime, caller, handle, type, ns_iovec);
    wt_ffm_gateway_exit(runtime);
    return status;
}

void wt_ffm_gateway_close(int32_t handle)
{
    wt_ffm_runtime_t* runtime = wt_ffm_boot_runtime_mut();
    psa_client_id_t caller;

    if (!wt_ffm_gateway_caller(&caller)) {
        return;
    }
    wt_ffm_gateway_enter(runtime, caller);
    (void)wt_ffm_close(runtime, caller, (psa_handle_t)handle);
    wt_ffm_gateway_exit(runtime);
}

uint32_t wt_ffm_gateway_framework_version(void)
{
    return wt_ffm_framework_version(wt_ffm_boot_runtime_mut());
}

uint32_t wt_ffm_gateway_service_version(uint32_t sid)
{
    psa_client_id_t caller;

    if (!wt_ffm_gateway_caller(&caller)) {
        return PSA_VERSION_NONE;
    }
    return wt_ffm_service_version(wt_ffm_boot_runtime_mut(), caller, sid);
}
