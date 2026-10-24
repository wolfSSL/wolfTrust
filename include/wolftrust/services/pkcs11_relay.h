/* pkcs11_relay.h
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

#ifndef WOLFTRUST_SERVICES_PKCS11_RELAY_H
#define WOLFTRUST_SERVICES_PKCS11_RELAY_H

#include "wolftrust/ffm.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/spm_gate.h"

typedef int (*wt_pkcs11_local_provider_fn)(uint8_t* request,
                                           size_t request_len,
                                           uint8_t* response,
                                           size_t response_cap,
                                           size_t* response_len,
                                           void* context);

void wt_pkcs11_relay_set_roles(int32_t app_client_id,
                               int32_t provider_client_id);
void wt_pkcs11_relay_set_local_provider(
    wt_pkcs11_local_provider_fn provider, void* context);
void wt_pkcs11_relay_set_transport(wt_spm_transport_fn fn);
int wt_pkcs11_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                             int32_t partition_id);

#if defined(WT_PKCS11_NEG_PROBE) && (WT_PKCS11_NEG_PROBE == 1)
int wt_pkcs11_relay_restart_probe(int restarted);
#endif

#endif /* WOLFTRUST_SERVICES_PKCS11_RELAY_H */
