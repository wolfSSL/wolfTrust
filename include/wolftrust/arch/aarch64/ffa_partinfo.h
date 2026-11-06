/* ffa_partinfo.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_PARTINFO_H
#define WOLFTRUST_ARCH_AARCH64_FFA_PARTINFO_H

#include <stddef.h>
#include <stdint.h>

#include "wolftrust/arch/aarch64/ffa_manifest.h"

/* FFA_PARTITION_INFO_GET partition information descriptors (DEN0077A 1.2 6.1,
 * Table 6.1) written into a caller's RX buffer (7.2). A descriptor is the
 * partition id, its execution-context count, and a properties word; from FF-A
 * 1.1 it also carries the partition UUID. */

#define WT_FFA_PARTINFO_DESC_V10        8u   /* id + context count + props */
#define WT_FFA_PARTINFO_DESC_V11        24u  /* the above plus the 16-byte UUID */

/* WT_FFA_PARTINFO_FLAG_COUNT (w5 bit 0, count-only) lives in ffa_abi.h. */

/* Partition properties (Table 6.2): FFA_MSG_SEND_DIRECT_REQ receipt/sending,
 * indirect messaging, notification receipt, AArch64 execution state, and
 * FFA_MSG_SEND_DIRECT_REQ2 receipt/sending. */
#define WT_FFA_PARTINFO_PROP_DIRECT_RECV 0x1u
#define WT_FFA_PARTINFO_PROP_DIRECT_SEND 0x2u
#define WT_FFA_PARTINFO_PROP_INDIRECT    0x4u
#define WT_FFA_PARTINFO_PROP_NOTIF       0x8u
#define WT_FFA_PARTINFO_PROP_AARCH64     0x100u
#define WT_FFA_PARTINFO_PROP_REQ2_RECV   0x200u
#define WT_FFA_PARTINFO_PROP_REQ2_SEND   0x400u
/* The v1.0 descriptor defines only bits 2:0 of the properties (Table 18.22). */
#define WT_FFA_PARTINFO_PROP_V10_MASK    0x7u

typedef struct wt_ffa_partinfo_entry {
    uint16_t id;
    uint16_t exec_contexts;
    uint32_t properties;
    uint8_t uuid[16];
} wt_ffa_partinfo_entry_t;

/* Descriptor size for a caller at the given negotiated FF-A version: 8 bytes
 * before 1.1, 24 from 1.1 (the UUID was added to the descriptor). */
uint32_t wt_ffa_partinfo_desc_size(uint32_t caller_version);

/* Discovery records for one manifest partition under the live endpoint id of
 * the partition running in its domain; none when id is 0 (nothing runs there).
 * One record per exported UUID, all with that id (6.2.2). Its services are
 * reached through the PSA framework endpoint and the FF-M gate, never by FF-A
 * messaging to its own id, so a record advertises only the AArch64 execution
 * state it runs in at S-EL0 (Table 6.2 bit 8). Returns 0 with
 * *out_n records written to out, WT_FFA_NO_MEMORY when out cannot hold them,
 * or WT_FFA_INVALID_PARAMETERS for a partition exporting no UUID or too many. */
int wt_ffa_partinfo_from_manifest(const wt_ffa_partition_manifest_t* part,
                                  uint16_t id, wt_ffa_partinfo_entry_t* out,
                                  size_t cap, size_t* out_n);

/* The properties listed for id, OR-ed over its records (one per UUID): 0 with
 * *props set, or INVALID_PARAMETERS when no record has that id. */
int wt_ffa_partinfo_props_of(const wt_ffa_partinfo_entry_t* parts, size_t n,
                             uint16_t id, uint32_t* props);

/* Whether an endpoint with these properties takes (receive != 0) or may send
 * a direct request of kind fid: bits 0/1 for FFA_MSG_SEND_DIRECT_REQ32/64,
 * bits 9/10 for FFA_MSG_SEND_DIRECT_REQ2 (Table 6.2). 0, or DENIED (Tables
 * 15.8 and 15.16). */
int wt_ffa_direct_req_allowed(uint32_t props, uint32_t fid, int receive);

/* FFA_MSG_SEND2 from sender (Table 5.1: indirect messaging support covers
 * sending as well as receiving): the Normal world always, a partition only if
 * parts lists it with the indirect-messaging property. 0, or DENIED (Table
 * 15.4). */
int wt_ffa_msg2_sender_allowed(const wt_ffa_partinfo_entry_t* parts, size_t n,
                               uint16_t sender);

/* A partition-to-partition direct request of kind fid (7.4.2 rule 2): the
 * sender must be listed in parts and advertise sending it (DENIED otherwise),
 * the receiver listed (INVALID_PARAMETERS otherwise) and advertise taking it
 * (DENIED otherwise). 0 when both hold. */
int wt_ffa_direct_req_authorize(const wt_ffa_partinfo_entry_t* parts, size_t n,
                                uint16_t sender, uint16_t receiver,
                                uint32_t fid);

/* Write the descriptors matching uuid16 into rx (7.2/6.1). A Nil UUID (all
 * zero) matches every partition; otherwise only those whose UUID equals it,
 * and the descriptors' UUID field is then zero (Table 6.1). flags bit 0
 * returns only the count (no descriptors written); the SBZ bits 31:1 are
 * ignored. On success 0 is returned with *out_count set and *out_desc_size
 * set to the per-descriptor size (0 for a count-only request). The producer
 * zeroes every descriptor byte it does not fill (7.2.2); a v1.0 caller's
 * descriptor carries only the property bits Table 18.22 defines.
 * WT_FFA_NO_MEMORY if rx cannot hold the matching descriptors. */
int wt_ffa_partinfo_write(uint8_t* rx, size_t rx_size, uint32_t caller_version,
                          const wt_ffa_partinfo_entry_t* parts, size_t n,
                          const uint8_t* uuid16, uint32_t flags,
                          uint32_t* out_count, uint32_t* out_desc_size);

/* FFA_PARTITION_INFO_GET (13.8) over parts: x = the call's registers (UUID in
 * w1-w4, flags in w5), caller_version = the FF-A version the caller negotiated
 * (the descriptor layout follows it, 18.5.3). A count needs no buffer;
 * descriptors go to the RX buffer of the caller's mailbox mb and take its
 * ownership. BUSY when that RX buffer is not mapped or not free (Table 13.36);
 * INVALID_PARAMETERS for a UUID nothing matches, found before the RX buffer
 * changes hands. */
struct wt_ffa_mailbox;
int wt_ffa_partinfo_get(const uint64_t* x, uint32_t caller_version,
                        struct wt_ffa_mailbox* mb,
                        const wt_ffa_partinfo_entry_t* parts, size_t n,
                        uint32_t* count, uint32_t* size);

/* FFA_PARTITION_INFO_GET_REGS (13.9): up to five matching descriptors per
 * call in out[3..17], three registers each (id, contexts and properties; then
 * the UUID, zero for a specific-UUID query), from the start index on. out[2]
 * packs the last index, the index of the last descriptor returned, the tag and
 * the descriptor size. The list never changes, so the tag is zero.
 * INVALID_PARAMETERS for a UUID nothing matches, a start index past the end,
 * or a nonzero tag at start 0 (MBZ); RETRY for a nonzero tag after it. */
#define WT_FFA_PARTINFO_REGS_PER_CALL 5u
int wt_ffa_partinfo_regs(const wt_ffa_partinfo_entry_t* parts, size_t n,
                         const uint8_t* uuid16, uint16_t start, uint16_t tag,
                         uint64_t* out18);

/* The same call decoded from its registers x (UUID in x1/x2, start index and
 * tag in x3 bits 15:0 and 31:16, bits 63:32 SBZ), for either instance. */
int wt_ffa_partinfo_regs_call(const wt_ffa_partinfo_entry_t* parts, size_t n,
                              const uint64_t* x, uint64_t* out18);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_PARTINFO_H */
