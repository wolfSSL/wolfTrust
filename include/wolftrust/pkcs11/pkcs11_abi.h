/* pkcs11_abi.h
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

#ifndef WOLFTRUST_PKCS11_PKCS11_ABI_H
#define WOLFTRUST_PKCS11_PKCS11_ABI_H

#include <stdint.h>

/* SERVICE_PKCS11 is an FF-M copied-transfer relay. The application submits
 * serialized PKCS#11 calls and the provider fetches them. Neither side maps
 * the other guest's memory. */
#define WT_PKCS11_SERVICE_SID       4105U
#define WT_PKCS11_SERVICE_VERSION   1U

#define WT_PKCS11_MESSAGE_MAX       4096U
#define WT_PKCS11_LIST_MAX          64U
#define WT_PKCS11_CHUNK_MAX         992U

#define WT_PKCS11_OP_APP_BEGIN      1
#define WT_PKCS11_OP_APP_WRITE      2
#define WT_PKCS11_OP_APP_COMMIT     3
#define WT_PKCS11_OP_APP_POLL       4
#define WT_PKCS11_OP_APP_READ       5
#define WT_PKCS11_OP_APP_ABORT      6
#define WT_PKCS11_OP_PROVIDER_FETCH 7
#define WT_PKCS11_OP_PROVIDER_READ  8
#define WT_PKCS11_OP_PROVIDER_BEGIN 9
#define WT_PKCS11_OP_PROVIDER_WRITE 10
#define WT_PKCS11_OP_PROVIDER_COMMIT 11
#define WT_PKCS11_OP_PROVIDER_ABORT 12

#define WT_PKCS11_E_EMPTY           (-2200)
#define WT_PKCS11_E_BUSY            (-2201)

typedef struct wt_pkcs11_length {
    uint32_t length;
} wt_pkcs11_length_t;

typedef struct wt_pkcs11_range {
    uint32_t offset;
    uint32_t length;
} wt_pkcs11_range_t;

typedef struct wt_pkcs11_chunk {
    uint32_t offset;
    uint32_t length;
    uint8_t data[WT_PKCS11_CHUNK_MAX];
} wt_pkcs11_chunk_t;

#endif /* WOLFTRUST_PKCS11_PKCS11_ABI_H */
