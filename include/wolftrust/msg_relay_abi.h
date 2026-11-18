/* msg_relay_abi.h
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

#ifndef WOLFTRUST_MSG_RELAY_ABI_H
#define WOLFTRUST_MSG_RELAY_ABI_H

#include <stdint.h>

/* Wire ABI of the SPM-mediated message services (TPM 2.0, PKCS#11). A message
 * that fits one copied transfer is one TRANSACT; a larger one is chunked. */
#define WT_MSG_TRANSFER_MAX 1024U
#define WT_MSG_CHUNK_MAX    992U

#define WT_MSG_OP_BEGIN     1
#define WT_MSG_OP_WRITE     2
#define WT_MSG_OP_TRANSACT  3
#define WT_MSG_OP_READ      5
#define WT_MSG_OP_ABORT     6
#define WT_MSG_OP_EXECUTE   13

typedef struct wt_msg_length {
    uint32_t length;
} wt_msg_length_t;

typedef struct wt_msg_range {
    uint32_t offset;
    uint32_t length;
} wt_msg_range_t;

typedef struct wt_msg_chunk {
    uint32_t offset;
    uint32_t length;
    uint8_t data[WT_MSG_CHUNK_MAX];
} wt_msg_chunk_t;

#endif /* WOLFTRUST_MSG_RELAY_ABI_H */
