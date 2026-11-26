/* psa_binding.c
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

#include "psa_binding.h"

static const wt_psa_host_identity_t* g_identity;
static void* g_identity_context;

static psa_client_id_t wt_psa_client(void)
{
    return g_identity == NULL ? 0 :
           g_identity->current_client(g_identity_context);
}

static int32_t wt_psa_partition(void)
{
    return g_identity == NULL ? 0 :
           g_identity->current_partition(g_identity_context);
}

static void wt_psa_check(int ret)
{
    if (ret != WT_SPM_OK) {
        wt_spm_host_panic(wt_psa_partition());
    }
}

int wt_psa_host_bind(const wt_psa_host_identity_t* identity, void* context)
{
    if (identity == NULL || identity->current_client == NULL ||
            identity->current_partition == NULL) {
        return WT_SPM_E_ARGUMENT;
    }
    g_identity = identity;
    g_identity_context = context;
    return WT_SPM_OK;
}

void wt_psa_host_unbind(void)
{
    g_identity = NULL;
    g_identity_context = NULL;
}

uint32_t psa_framework_version(void)
{
    return g_wt_spm_framework_version;
}

uint32_t psa_version(uint32_t sid)
{
    return wt_spm_service_version(wt_psa_client(), sid);
}

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    return wt_spm_host_connect(wt_psa_client(), sid, version);
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    return wt_spm_host_call(wt_psa_client(), handle, type, in_vec, in_len,
                            out_vec, out_len);
}

void psa_close(psa_handle_t handle)
{
    wt_psa_check(wt_spm_host_close(wt_psa_client(), handle));
}

psa_signal_t psa_wait(psa_signal_t signal_mask, uint32_t timeout)
{
    psa_signal_t asserted = 0U;

    (void)timeout;
    return wt_spm_host_wait(wt_psa_partition(), signal_mask, &asserted) ==
           WT_SPM_OK ? asserted : 0U;
}

psa_status_t psa_get(psa_signal_t signal, psa_msg_t* msg)
{
    return wt_spm_host_get(wt_psa_partition(), signal, msg);
}

void psa_set_rhandle(psa_handle_t msg_handle, void* rhandle)
{
    wt_psa_check(wt_spm_host_set_rhandle(wt_psa_partition(), msg_handle,
                                         rhandle));
}

size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx,
                void* buffer, size_t num_bytes)
{
    return wt_spm_host_read(wt_psa_partition(), msg_handle, invec_idx,
                            buffer, num_bytes);
}

size_t psa_skip(psa_handle_t msg_handle, uint32_t invec_idx,
                size_t num_bytes)
{
    return wt_spm_host_skip(wt_psa_partition(), msg_handle, invec_idx,
                            num_bytes);
}

void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx,
               const void* buffer, size_t num_bytes)
{
    wt_psa_check(wt_spm_host_write(wt_psa_partition(), msg_handle,
                                   outvec_idx, buffer, num_bytes));
}

void psa_reply(psa_handle_t msg_handle, psa_status_t status)
{
    wt_psa_check(wt_spm_host_reply(wt_psa_partition(), msg_handle, status));
}

void psa_notify(int32_t partition_id)
{
    wt_psa_check(wt_spm_notify(partition_id));
}

void psa_clear(void)
{
    wt_psa_check(wt_spm_host_clear(wt_psa_partition()));
}

void psa_eoi(psa_signal_t irq_signal)
{
    wt_psa_check(wt_spm_host_eoi(wt_psa_partition(), irq_signal));
}

void psa_panic(void)
{
    wt_spm_host_panic(wt_psa_partition());
    for (;;) {
    }
}
