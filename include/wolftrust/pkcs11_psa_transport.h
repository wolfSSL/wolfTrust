/* pkcs11_psa_transport.h
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

#ifndef WOLFTRUST_PKCS11_PSA_TRANSPORT_H
#define WOLFTRUST_PKCS11_PSA_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

typedef int (*wt_pkcs11_dispatch_fn)(uint8_t* request,
                                     size_t request_len, uint8_t* response,
                                     size_t response_cap,
                                     size_t* response_len, void* context);

/* Submit one serialized PKCS#11 request and wait for its serialized response.
 * The buffers are copied through SERVICE_PKCS11. They are never shared with
 * the provider guest. */
int wt_pkcs11_psa_call(const uint8_t* request, size_t request_len,
                       uint8_t* response, size_t response_cap,
                       size_t* response_len);

/* Serve one pending request from the provider guest. Returns
 * WT_PKCS11_E_EMPTY when no request is ready. */
int wt_pkcs11_psa_provider_step(uint8_t* request, size_t request_cap,
                                uint8_t* response, size_t response_cap,
                                wt_pkcs11_dispatch_fn dispatch,
                                void* context);

void wt_pkcs11_psa_close(void);

#endif /* WOLFTRUST_PKCS11_PSA_TRANSPORT_H */
