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
/* DEN0140 memory management. DONATE/LEND/SHARE/RETRIEVE_REQ have SMC32 and
 * SMC64 conventions; RETRIEVE_RESP/RELINQUISH/RECLAIM are SMC32 only.
 * FRAG_RX 0x8400007A / FRAG_TX 0x8400007B are deferred until fragmentation. */
#define WT_FFA_MEM_DONATE32           0x84000071u
#define WT_FFA_MEM_DONATE64           0xC4000071u
#define WT_FFA_MEM_LEND32             0x84000072u
#define WT_FFA_MEM_LEND64             0xC4000072u
#define WT_FFA_MEM_SHARE32            0x84000073u
#define WT_FFA_MEM_SHARE64            0xC4000073u
#define WT_FFA_MEM_RETRIEVE_REQ32     0x84000074u
#define WT_FFA_MEM_RETRIEVE_REQ64     0xC4000074u
#define WT_FFA_MEM_RETRIEVE_RESP      0x84000075u
#define WT_FFA_MEM_RELINQUISH         0x84000076u
#define WT_FFA_MEM_RECLAIM            0x84000077u
#define WT_FFA_NORMAL_WORLD_RESUME    0x8400007Cu
#define WT_FFA_NOTIFICATION_BITMAP_CREATE 0x8400007Du
#define WT_FFA_NOTIFICATION_BITMAP_DESTROY 0x8400007Eu
#define WT_FFA_NOTIFICATION_BIND      0x8400007Fu
#define WT_FFA_NOTIFICATION_UNBIND    0x84000080u
#define WT_FFA_NOTIFICATION_SET       0x84000081u
#define WT_FFA_NOTIFICATION_GET       0x84000082u
#define WT_FFA_NOTIFICATION_INFO_GET32 0x84000083u
#define WT_FFA_NOTIFICATION_INFO_GET64 0xC4000083u
#define WT_FFA_RX_ACQUIRE             0x84000084u
#define WT_FFA_SPM_ID_GET             0x84000085u
#define WT_FFA_MSG_SEND2              0x84000086u
#define WT_FFA_MEM_PERM_GET32          0x84000088u
#define WT_FFA_MEM_PERM_GET64          0xC4000088u
#define WT_FFA_MEM_PERM_SET32          0x84000089u
#define WT_FFA_MEM_PERM_SET64          0xC4000089u
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
/* The PSA framework endpoint at the NS physical instance: the SPMC answers a
 * Normal-world client's register-only FrameworkVersion/ServiceVersion/Connect/
 * Close as this receiver, without a backing partition. */
#define WT_FFA_ID_PSA                 0x80FDu
/* The memory-sharing boot self-test borrower: the SPMC shares a page to this
 * endpoint and an S-EL0 partition retrieves it through the SVC gate. */
#define WT_FFA_ID_MEM_BORROWER        0x80FBu

/* FFA_PARTITION_INFO_GET w5 flags: bit 0 set returns only the partition count
 * in w2, so the caller needs no RX buffer. */
#define WT_FFA_PARTINFO_FLAG_COUNT    (1u << 0)
/* wolfTrust test echo partition and its request payload; both exist only in
 * WT_EL3_TEST_DRIVER=1 builds and never in a production image. */
#define WT_FFA_ID_ECHO                0x80FEu
#define WT_FFA_TEST_PAYLOAD           0x1234ABCDu

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

/* From FF-A 1.1 the callee reports its version only to a compatible caller
 * (13.2.2); a malformed (bit 31) or incompatible request is NOT_SUPPORTED. */
static inline int32_t wt_ffa_version_reply(uint32_t input, uint32_t ours)
{
    if (((input & 0x80000000u) != 0u) ||
        !wt_ffa_version_compatible(input, ours)) {
        return (int32_t)WT_FFA_NOT_SUPPORTED;
    }
    return (int32_t)ours;
}

/* One caller's negotiated version (13.2): it may renegotiate until it makes
 * any other FF-A call, after which only the version it settled on is accepted.
 * A caller that never negotiated is held to ours. */
typedef struct wt_ffa_version_state {
    uint32_t version;
    uint8_t locked;
} wt_ffa_version_state_t;

static inline void wt_ffa_version_lock(wt_ffa_version_state_t* st, uint32_t ours)
{
    if (st->locked == 0u) {
        if (st->version == 0u) {
            st->version = ours;
        }
        st->locked = 1u;
    }
}

static inline int32_t wt_ffa_version_negotiate(wt_ffa_version_state_t* st,
                                               uint32_t input, uint32_t ours)
{
    int32_t reply = wt_ffa_version_reply(input, ours);

    if (reply == (int32_t)WT_FFA_NOT_SUPPORTED) {
        return reply;
    }
    if (st->locked != 0u) {
        return (input == st->version) ? reply : (int32_t)WT_FFA_NOT_SUPPORTED;
    }
    st->version = input;
    return reply;
}

/* FFA_FEATURES feature ids (13.3, Table 13.14) and the properties this
 * implementation reports. No notifications exist, so the schedule receiver
 * interrupt is reserved and never raised. */
#define WT_FFA_FEATURE_NPI            0x1u
#define WT_FFA_FEATURE_SRI            0x2u
#define WT_FFA_FEATURE_MEI            0x3u
#define WT_FFA_SRI_INTID              8u
/* FFA_MEM_RETRIEVE_REQ: bit 1 in (caller) and out (SPMC) = NS bit is used. */
#define WT_FFA_FEATURES_RETRIEVE_NS_BIT 0x2u

/* FFA_PARTITION_INFO_GET_REGS answers in x0-x17 although it is asked in
 * x0-x3, so a relayer decides a reply's width from what it forwarded too. */
static inline int wt_ffa_reply_is_ext(uint32_t forwarded, uint32_t reply)
{
    return (reply == WT_FFA_MSG_SEND_DIRECT_RESP2) ||
           ((forwarded == WT_FFA_PARTITION_INFO_GET_REGS) &&
            (reply == WT_FFA_SUCCESS64));
}

/* Registers a relayed message occupies: x0-x7, or x0-x17 for REQ2/RESP2. */
#define WT_FFA_MSG_REGS     8u
#define WT_FFA_MSG_REGS_EXT 18u

static inline unsigned int wt_ffa_msg_reg_count(uint64_t x0)
{
    uint32_t fid = (uint32_t)x0;

    return ((fid == WT_FFA_MSG_SEND_DIRECT_REQ2) ||
            (fid == WT_FFA_MSG_SEND_DIRECT_RESP2)) ? WT_FFA_MSG_REGS_EXT
                                                   : WT_FFA_MSG_REGS;
}

/* A 32-bit function id carries w1-w7 only (SMCCC): a relayer hands the
 * receiver the low halves and never leaks the sender's upper register bits. */
static inline void wt_ffa_regs_normalize(uint64_t* x)
{
    unsigned int i;

    if (((uint32_t)x[0] & 0x40000000u) == 0u) {
        for (i = 1u; i < 8u; i++) {
            x[i] &= 0xFFFFFFFFull;
        }
    }
}

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_ABI_H */
