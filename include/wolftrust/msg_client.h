/* msg_client.h
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

#ifndef WOLFTRUST_MSG_CLIENT_H
#define WOLFTRUST_MSG_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "psa/client.h"
#include "wolftrust/msg_relay_abi.h"

/* A Non-secure caller of one SPM-mediated message service. The connection
 * opens on first use and reopens on the call after a lost one. */
typedef struct wt_msg_client {
    uint32_t sid;
    uint32_t version;
    uint32_t message_max;
    psa_handle_t handle;
} wt_msg_client_t;

#define WT_MSG_CLIENT_INIT(sid, version, message_max) { \
    (sid), (version), (message_max), PSA_NULL_HANDLE }

/* Sends one request and returns its response; never replays a failed call. */
int wt_msg_client_call(wt_msg_client_t* client, const uint8_t* request,
                       size_t request_len, uint8_t* response,
                       size_t response_cap, size_t* response_len);
void wt_msg_client_close(wt_msg_client_t* client);

#endif /* WOLFTRUST_MSG_CLIENT_H */
