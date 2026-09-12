/* ffa_abi.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_ABI_H
#define WOLFTRUST_ARCH_AARCH64_FFA_ABI_H

#include <stdint.h>

/* Arm FF-A v1.2 function ids, status codes, and ids (DEN0077A). This is the
 * only file that may spell an FF-A function id. */

#define WT_FFA_VERSION_MAJOR          1u
#define WT_FFA_VERSION_MINOR          2u
#define WT_FFA_VERSION_1_2            0x00010002u
#define WT_FFA_VERSION_MAKE(maj, min) ((uint32_t)(((maj) << 16) | (min)))
#define WT_FFA_VERSION_MAJOR_OF(v)    (((v) >> 16) & 0x7FFFu)
#define WT_FFA_VERSION_MINOR_OF(v)    ((v) & 0xFFFFu)

#define WT_FFA_FID32_FIRST            0x84000060u
#define WT_FFA_FID32_LAST             0x840000FFu
#define WT_FFA_FID64_FIRST            0xC4000060u
#define WT_FFA_FID64_LAST             0xC40000FFu

#define WT_FFA_ERROR                  0x84000060u
#define WT_FFA_SUCCESS32              0x84000061u
#define WT_FFA_SUCCESS64              0xC4000061u
#define WT_FFA_INTERRUPT              0x84000062u
#define WT_FFA_VERSION                0x84000063u
#define WT_FFA_FEATURES               0x84000064u
#define WT_FFA_RX_RELEASE             0x84000065u
#define WT_FFA_RXTX_MAP32             0x84000066u
#define WT_FFA_RXTX_MAP64             0xC4000066u
#define WT_FFA_RXTX_UNMAP             0x84000067u
#define WT_FFA_PARTITION_INFO_GET     0x84000068u
#define WT_FFA_ID_GET                 0x84000069u
#define WT_FFA_MSG_WAIT               0x8400006Bu
#define WT_FFA_YIELD                  0x8400006Cu
#define WT_FFA_RUN                    0x8400006Du
#define WT_FFA_MSG_SEND_DIRECT_REQ32  0x8400006Fu
#define WT_FFA_MSG_SEND_DIRECT_REQ64  0xC400006Fu
#define WT_FFA_MSG_SEND_DIRECT_RESP32 0x84000070u
#define WT_FFA_MSG_SEND_DIRECT_RESP64 0xC4000070u
#define WT_FFA_NORMAL_WORLD_RESUME    0x8400007Cu
#define WT_FFA_NOTIFICATION_BITMAP_CREATE 0x8400007Du
#define WT_FFA_RX_ACQUIRE             0x84000084u
#define WT_FFA_SPM_ID_GET             0x84000085u
#define WT_FFA_MSG_SEND2              0x84000086u
#define WT_FFA_CONSOLE_LOG32          0x8400008Au
#define WT_FFA_CONSOLE_LOG64          0xC400008Au
#define WT_FFA_PARTITION_INFO_GET_REGS 0xC400008Bu
#define WT_FFA_MSG_SEND_DIRECT_REQ2   0xC400008Du
#define WT_FFA_MSG_SEND_DIRECT_RESP2  0xC400008Eu

#define WT_FFA_NOT_SUPPORTED          (-1)
#define WT_FFA_INVALID_PARAMETERS     (-2)
#define WT_FFA_NO_MEMORY              (-3)
#define WT_FFA_BUSY                   (-4)
#define WT_FFA_INTERRUPTED            (-5)
#define WT_FFA_DENIED                 (-6)
#define WT_FFA_RETRY                  (-7)
#define WT_FFA_ABORTED                (-8)
#define WT_FFA_NO_DATA                (-9)
#define WT_FFA_NOT_READY              (-10)

/* Partition ids: bit 15 set = allocated by the SPM (SPMC, SPMD, then SPs);
 * bit 15 clear = Normal-world endpoints, id 0 = the primary NS endpoint. */
#define WT_FFA_ID_NS_PRIMARY          0x0000u
#define WT_FFA_ID_SPMC                0x8000u
#define WT_FFA_ID_SPMD                0x8001u
#define WT_FFA_ID_SP_FIRST            0x8002u

/* FFA_FEATURES: w1 bit 31 set = function id queried, clear = feature id. */
#define WT_FFA_FEATURES_IS_FID(w1)    (((w1) & 0x80000000u) != 0u)

static inline int wt_ffa_fid_in_range(uint32_t fid)
{
    return ((fid >= WT_FFA_FID32_FIRST) && (fid <= WT_FFA_FID32_LAST)) ||
           ((fid >= WT_FFA_FID64_FIRST) && (fid <= WT_FFA_FID64_LAST));
}

/* Compatibility of caller x.y with callee a.b (13.2.1): same major and a
 * caller minor no greater than the callee's. */
static inline int wt_ffa_version_compatible(uint32_t caller, uint32_t callee)
{
    return (WT_FFA_VERSION_MAJOR_OF(caller) == WT_FFA_VERSION_MAJOR_OF(callee)) &&
           (WT_FFA_VERSION_MINOR_OF(caller) <= WT_FFA_VERSION_MINOR_OF(callee));
}

/* The callee always reports its own version to a well-formed request (13.2.2);
 * bit 31 set is malformed and gets NOT_SUPPORTED. */
static inline int32_t wt_ffa_version_reply(uint32_t input, uint32_t ours)
{
    if ((input & 0x80000000u) != 0u) {
        return (int32_t)WT_FFA_NOT_SUPPORTED;
    }
    return (int32_t)ours;
}

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_ABI_H */
