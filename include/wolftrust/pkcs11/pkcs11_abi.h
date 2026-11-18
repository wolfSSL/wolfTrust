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

#include "wolftrust/msg_relay_abi.h"

/* SERVICE_PKCS11 runs serialized calls inside its Secure partition.
 * Messages larger than the FF-M transfer budget use bounded chunks. */
#define WT_PKCS11_SERVICE_SID       4105U
#define WT_PKCS11_SERVICE_VERSION   1U

#define WT_PKCS11_MESSAGE_MAX       4096U
#define WT_PKCS11_LIST_MAX          64U
#define WT_PKCS11_CHUNK_MAX         WT_MSG_CHUNK_MAX

#define WT_PKCS11_OP_APP_BEGIN      WT_MSG_OP_BEGIN
#define WT_PKCS11_OP_APP_WRITE      WT_MSG_OP_WRITE
#define WT_PKCS11_OP_APP_READ       WT_MSG_OP_READ
#define WT_PKCS11_OP_APP_ABORT      WT_MSG_OP_ABORT
#define WT_PKCS11_OP_APP_EXECUTE    WT_MSG_OP_EXECUTE

typedef wt_msg_length_t wt_pkcs11_length_t;
typedef wt_msg_range_t wt_pkcs11_range_t;
typedef wt_msg_chunk_t wt_pkcs11_chunk_t;

#endif /* WOLFTRUST_PKCS11_PKCS11_ABI_H */
