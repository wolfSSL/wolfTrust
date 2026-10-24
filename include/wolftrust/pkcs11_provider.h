/* pkcs11_provider.h
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

#ifndef WOLFTRUST_PKCS11_PROVIDER_H
#define WOLFTRUST_PKCS11_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#ifndef WT_PKCS11_PIN_MAX_FAILURES
#define WT_PKCS11_PIN_MAX_FAILURES 3U
#endif

int wt_pkcs11_provider_dispatch(uint8_t* request, size_t request_len,
                                uint8_t* response, size_t response_cap,
                                size_t* response_len, void* context);

#endif /* WOLFTRUST_PKCS11_PROVIDER_H */
