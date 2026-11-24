/* msg_relay.h
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

#ifndef WOLFTRUST_SERVICES_MSG_RELAY_H
#define WOLFTRUST_SERVICES_MSG_RELAY_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/msg_relay_abi.h"

/* Runs one request in the serving partition; the request buffer is scratch. */
typedef int (*wt_msg_provider_fn)(uint8_t* request, size_t request_len,
                                  uint8_t* response, size_t response_cap,
                                  size_t* response_len, void* context);

#define WT_MSG_RELAY_MODE_ONESHOT 1U
#define WT_MSG_RELAY_MODE_CHUNKED 2U

/* One relay instance. The engine holds no state of its own: the instance and
 * both buffers live in the owning partition's data band. */
typedef struct wt_msg_relay {
    uint8_t* request;
    uint8_t* response;
    wt_spm_transport_fn transport;
    wt_msg_provider_fn provider;
    void* provider_context;
    uint32_t capacity;
    uint32_t request_len;
    uint32_t request_used;
    uint32_t response_len;
    int32_t app_client;
    uint8_t mode;
    uint8_t state;
} wt_msg_relay_t;

#define WT_MSG_RELAY_INIT(mode, request, response, capacity) { \
    (request), (response), wt_spm_transport_direct, NULL, NULL, \
    (capacity), 0U, 0U, 0U, 0, (mode), 0U }

/* Bind the SPM-stamped Non-secure caller (guest N is -(N+1)). */
void wt_msg_relay_set_client(wt_msg_relay_t* relay, int32_t app_client_id);
/* Direct gate calls on the host, SVC on target; NULL restores direct. */
void wt_msg_relay_set_transport(wt_msg_relay_t* relay, wt_spm_transport_fn fn);
void wt_msg_relay_set_provider(wt_msg_relay_t* relay,
                               wt_msg_provider_fn provider, void* context);
/* One pass of the service loop: wait, get, serve one op, reply. */
int wt_msg_relay_dispatch(wt_msg_relay_t* relay, wt_ffm_runtime_t* runtime,
                          int32_t partition_id);

#endif /* WOLFTRUST_SERVICES_MSG_RELAY_H */
