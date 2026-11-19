/* pkcs11_relay_service.c
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

#include "wolftrust/services/pkcs11_relay.h"
#include "wolftrust/services/msg_relay.h"

/* The staged request and response live in the band, not on the stack. */
static uint8_t g_pkcs11_request[WT_PKCS11_MESSAGE_MAX];
static uint8_t g_pkcs11_response[WT_PKCS11_MESSAGE_MAX];
static wt_msg_relay_t g_pkcs11_relay = WT_MSG_RELAY_INIT(
    WT_MSG_RELAY_MODE_CHUNKED, g_pkcs11_request,
    g_pkcs11_response, WT_PKCS11_MESSAGE_MAX);

#if defined(WT_INTERFACE_NEG_PROBE) && (WT_INTERFACE_NEG_PROBE == 1)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_pkcs11_relay_restart_probe)
#endif

void wt_pkcs11_relay_set_client(int32_t app_client_id)
{
    wt_msg_relay_set_client(&g_pkcs11_relay, app_client_id);
}

void wt_pkcs11_relay_set_transport(wt_spm_transport_fn fn)
{
    wt_msg_relay_set_transport(&g_pkcs11_relay, fn);
}

void wt_pkcs11_relay_set_local_provider(
    wt_pkcs11_local_provider_fn provider, void* context)
{
    wt_msg_relay_set_provider(&g_pkcs11_relay, provider, context);
}

int wt_pkcs11_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                             int32_t partition_id)
{
    (void)context;
    return wt_msg_relay_dispatch(&g_pkcs11_relay, runtime, partition_id);
}
