/* pkcs11_psa_transport.c
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

#include "wolftrust/pkcs11_psa_transport.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/msg_client.h"

static wt_msg_client_t g_pkcs11_client = WT_MSG_CLIENT_INIT(
    WT_PKCS11_SERVICE_SID, WT_PKCS11_SERVICE_VERSION, WT_PKCS11_MESSAGE_MAX);

void wt_pkcs11_psa_close(void)
{
    wt_msg_client_close(&g_pkcs11_client);
}

int wt_pkcs11_psa_call(const uint8_t* request, size_t request_len,
                       uint8_t* response, size_t response_cap,
                       size_t* response_len)
{
    return wt_msg_client_call(&g_pkcs11_client, request, request_len,
                              response, response_cap, response_len);
}
