/* tpm_relay_service.c
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

#include "wolftrust/services/tpm_relay.h"
#include "wolftrust/services/msg_relay.h"

/* The one in-flight frame, kept off the partition stack in its own band. */
static uint8_t g_tpm_request[WT_TPM_FRAME_MAX];
static uint8_t g_tpm_response[WT_TPM_FRAME_MAX];
static wt_msg_relay_t g_tpm_relay =
    WT_MSG_RELAY_INIT(WT_MSG_RELAY_MODE_ONESHOT,
    g_tpm_request, g_tpm_response, WT_TPM_FRAME_MAX);

#if defined(WT_INTERFACE_NEG_PROBE) && (WT_INTERFACE_NEG_PROBE == 1)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_tpm_relay_restart_probe)
#endif

void wt_tpm_relay_set_client(int32_t app_client_id)
{
    wt_msg_relay_set_client(&g_tpm_relay, app_client_id);
}

void wt_tpm_relay_set_transport(wt_spm_transport_fn fn)
{
    wt_msg_relay_set_transport(&g_tpm_relay, fn);
}

void wt_tpm_relay_set_local_provider(wt_tpm_local_provider_fn provider,
                                     void* context)
{
    wt_msg_relay_set_provider(&g_tpm_relay, provider, context);
}

int wt_tpm_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                          int32_t partition_id)
{
    (void)context;
    return wt_msg_relay_dispatch(&g_tpm_relay, runtime, partition_id);
}
