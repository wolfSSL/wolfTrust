/* ffa_mem.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_MEM_H
#define WOLFTRUST_ARCH_AARCH64_FFA_MEM_H

#include <stddef.h>
#include <stdint.h>

/* Arm FF-A Memory Management (DEN0140) v1.0-v1.2 transaction descriptors: the
 * lend/donate/share memory transaction descriptor and its endpoint access,
 * composite, and constituent sub-descriptors, plus the relayer validation a
 * 1.2 SPMC runs before it acts on a transaction. Pure functions over
 * caller-provided buffers; the FF-A function ids live in ffa_abi.h. */

#define WT_FFA_MEM_PAGE_SIZE            0x1000u

/* Fixed byte sizes of the v1.1 descriptor layout. */
#define WT_FFA_MEM_TXN_HDR_SIZE         48u  /* transaction descriptor header */
/* The FF-A v1.0 header (DEN0140 Table 4.17) has no access descriptor size or
 * offset: its 16-byte access descriptors follow at 32, and bytes [24, 28) are
 * reserved. A v1.0 caller's descriptors use it (DEN0077A 18.5.3). */
#define WT_FFA_MEM_TXN_HDR_SIZE_V10     32u
#define WT_FFA_MEM_ACCESS_SIZE          16u  /* endpoint memory access descriptor */
/* FF-A 1.2 grew it by 16 implementation-defined bytes ahead of the reserved
 * tail; a descriptor names its own size, so both layouts are accepted. */
#define WT_FFA_MEM_ACCESS_SIZE_V12      32u
#define WT_FFA_MEM_ACC_OFF_IMPDEF       8u   /* v1.2 only: 16 bytes */
#define WT_FFA_MEM_IMPDEF_SIZE          16u
#define WT_FFA_MEM_COMPOSITE_HDR_SIZE   16u  /* composite memory region header */
#define WT_FFA_MEM_CONSTITUENT_SIZE     16u  /* constituent memory region descriptor */

/* Transaction descriptor field offsets (Table 5.19). */
#define WT_FFA_MEM_TXN_OFF_SENDER       0u   /* u16 sender endpoint id */
#define WT_FFA_MEM_TXN_OFF_ATTRS        2u   /* u16 memory region attributes */
#define WT_FFA_MEM_TXN_OFF_FLAGS        4u   /* u32 flags */
#define WT_FFA_MEM_TXN_OFF_HANDLE       8u   /* u64 handle */
#define WT_FFA_MEM_TXN_OFF_TAG          16u  /* u64 tag */
#define WT_FFA_MEM_TXN_OFF_ACC_SIZE     24u  /* u32 size of each access descriptor */
#define WT_FFA_MEM_TXN_OFF_ACC_COUNT    28u  /* u32 access descriptor count */
#define WT_FFA_MEM_TXN_OFF_ACC_OFFSET   32u  /* u32 offset to the access array */
/* [36, 48) reserved (SBZ). */
#define WT_FFA_MEM_ACC_OFFSET_ALIGN     16u  /* the access array offset's alignment */

/* Endpoint memory access descriptor field offsets (Table 5.16). */
#define WT_FFA_MEM_ACC_OFF_RECEIVER     0u   /* u16 receiver endpoint id */
#define WT_FFA_MEM_ACC_OFF_PERMS        2u   /* u8 access permissions */
#define WT_FFA_MEM_ACC_OFF_FLAGS        3u   /* u8 access descriptor flags */
#define WT_FFA_MEM_ACC_OFF_COMP_OFF     4u   /* u32 offset to the composite descriptor */
/* [8, 16) reserved (SBZ). */

/* Access descriptor flags byte (DEN0140 1.10.1): MBZ in a lend/donate/share;
 * in a retrieve request bit 0 marks an entry that names another borrower. */
#define WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL (1u << 0)

/* Composite memory region header field offsets (Table 5.13). */
#define WT_FFA_MEM_COMP_OFF_PAGES       0u   /* u32 total page count */
#define WT_FFA_MEM_COMP_OFF_COUNT       4u   /* u32 constituent count */
/* [8, 16) reserved (SBZ). */

/* Constituent memory region descriptor field offsets (Table 5.11). */
#define WT_FFA_MEM_CONS_OFF_ADDR        0u   /* u64 page-aligned base address */
#define WT_FFA_MEM_CONS_OFF_PAGES       8u   /* u32 page count */
/* [12, 16) reserved (SBZ). */

/* Memory access permissions byte (Table 5.14). */
#define WT_FFA_MEM_PERM_DATA_MASK       0x3u
#define WT_FFA_MEM_PERM_DATA_NOT_SPEC   0x0u
#define WT_FFA_MEM_PERM_DATA_RO         0x1u
#define WT_FFA_MEM_PERM_DATA_RW         0x2u
#define WT_FFA_MEM_PERM_DATA_RSVD       0x3u
#define WT_FFA_MEM_PERM_INSTR_SHIFT     2u
#define WT_FFA_MEM_PERM_INSTR_MASK      0xCu
#define WT_FFA_MEM_PERM_INSTR_NOT_SPEC  0x0u
#define WT_FFA_MEM_PERM_INSTR_NX        (0x1u << WT_FFA_MEM_PERM_INSTR_SHIFT)
#define WT_FFA_MEM_PERM_INSTR_X         (0x2u << WT_FFA_MEM_PERM_INSTR_SHIFT)
#define WT_FFA_MEM_PERM_RSVD_MASK       0xF0u  /* bits[7:4] SBZ */

/* Transaction descriptor flags (Table 5.20/5.21). Bits[4:3] carry the
 * transaction type only in a retrieve response; they are zero in a send. */
#define WT_FFA_MEM_FLAG_ZERO            (1u << 0)
#define WT_FFA_MEM_FLAG_TIME_SLICE      (1u << 1)
/* Retrieve request only: zero the memory after the borrower relinquishes. */
#define WT_FFA_MEM_FLAG_ZERO_AFTER      (1u << 2)
/* Retrieve request only (FF-A 1.2): the caller names just itself although the
 * transaction has several borrowers. */
#define WT_FFA_MEM_FLAG_BYPASS_BORROWERS (1u << 10)
/* Every retrieve request flag Table 1.22 defines; bits[31:11] are SBZ. */
#define WT_FFA_MEM_FLAG_RETRIEVE_MASK   0x7FFu
#define WT_FFA_MEM_FLAG_TYPE_SHIFT      3u
#define WT_FFA_MEM_FLAG_TYPE_MASK       (0x3u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_TYPE_SHARE      (0x1u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_TYPE_LEND       (0x2u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_TYPE_DONATE     (0x3u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_ALIGN_MASK      (0x1Fu << 5)  /* bits[9:5] alignment hint */
/* Flag bits a retrieve request may set besides its type, zero-after, and
 * bypass flags. Time slicing (DEN0140 4.1.3) is not implemented, so its flag
 * is refused in every call. */
#define WT_FFA_MEM_FLAG_SEND_MASK       (WT_FFA_MEM_FLAG_ZERO | \
                                         WT_FFA_MEM_FLAG_ALIGN_MASK)

/* Memory region attributes (Table 5.18). */
#define WT_FFA_MEM_ATTR_SHARE_MASK      0x3u
#define WT_FFA_MEM_ATTR_SHARE_NON       0x0u
#define WT_FFA_MEM_ATTR_SHARE_RSVD      0x1u
#define WT_FFA_MEM_ATTR_SHARE_OUTER     0x2u
#define WT_FFA_MEM_ATTR_SHARE_INNER     0x3u
#define WT_FFA_MEM_ATTR_CACHE_SHIFT     2u
#define WT_FFA_MEM_ATTR_CACHE_MASK      (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT)
#define WT_FFA_MEM_ATTR_CACHE_NC        (0x1u << WT_FFA_MEM_ATTR_CACHE_SHIFT)
#define WT_FFA_MEM_ATTR_CACHE_WB        (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT)
#define WT_FFA_MEM_ATTR_TYPE_SHIFT      4u
#define WT_FFA_MEM_ATTR_TYPE_MASK       (0x3u << WT_FFA_MEM_ATTR_TYPE_SHIFT)
#define WT_FFA_MEM_ATTR_TYPE_DEVICE     (0x1u << WT_FFA_MEM_ATTR_TYPE_SHIFT)
#define WT_FFA_MEM_ATTR_TYPE_NORMAL     (0x2u << WT_FFA_MEM_ATTR_TYPE_SHIFT)
#define WT_FFA_MEM_ATTR_NS              (1u << 6)   /* non-secure memory */
#define WT_FFA_MEM_ATTR_RSVD_MASK       0xFF80u     /* bits[15:7] SBZ */
/* What the relayer's stage 1 tables map every borrower with. */
#define WT_FFA_MEM_ATTR_RELAYER         (WT_FFA_MEM_ATTR_TYPE_NORMAL | \
                                         WT_FFA_MEM_ATTR_CACHE_WB | \
                                         WT_FFA_MEM_ATTR_SHARE_INNER)

/* The memory management operation, derived from the FF-A function id by the
 * caller. Ordered to match the transaction-type field encoding (Table 5.21). */
typedef enum wt_ffa_mem_op {
    WT_FFA_MEM_OP_SHARE  = 1,
    WT_FFA_MEM_OP_LEND   = 2,
    WT_FFA_MEM_OP_DONATE = 3
} wt_ffa_mem_op_t;

/* One address range contributed to a transaction. */
typedef struct wt_ffa_mem_constituent {
    uint64_t address;
    uint32_t page_count;
} wt_ffa_mem_constituent_t;

/* A constituent captured for a live handle, with the borrower's permissions
 * and the security state, so the relayer can map it into the borrower and
 * unmap it on relinquish/reclaim. B4.3 shares a single region; multi-borrower
 * and fragmented sharing are deferred. */
#define WT_FFA_MEM_MAX_REGIONS          4u

typedef struct wt_ffa_mem_region {
    uint64_t base;
    uint32_t page_count;
    uint8_t  permissions;  /* FF-A access permissions byte (Table 5.14) */
    uint8_t  ns;           /* 1 if the shared memory is Non-secure */
} wt_ffa_mem_region_t;

/* Parsed and validated header of a memory transaction descriptor. */
typedef struct wt_ffa_mem_txn {
    uint64_t handle;
    uint64_t tag;
    uint32_t flags;
    uint32_t receiver_count;
    uint32_t access_desc_size;
    uint32_t access_offset;
    uint32_t composite_offset;
    uint32_t total_page_count;
    uint32_t constituent_count;
    uint16_t sender;
    uint16_t attributes;
} wt_ffa_mem_txn_t;

/* Relinquish descriptor (Table 5.24): handle, flags, endpoint count, then the
 * endpoint id array. */
#define WT_FFA_MEM_RELINQ_OFF_HANDLE    0u   /* u64 */
#define WT_FFA_MEM_RELINQ_OFF_FLAGS     8u   /* u32 */
#define WT_FFA_MEM_RELINQ_OFF_COUNT     12u  /* u32 endpoint count */
#define WT_FFA_MEM_RELINQ_OFF_ENDPOINTS 16u  /* u16 each */
#define WT_FFA_MEM_RELINQ_HDR_SIZE      16u
/* The zero-memory bit, the one flag FFA_MEM_RELINQUISH and FFA_MEM_RECLAIM
 * act on: bit[1] (time slicing) is refused, bits[31:2] are SBZ. */
#define WT_FFA_MEM_RELINQ_FLAG_MASK     0x1u
#define WT_FFA_MEM_RELINQ_FLAG_ZERO     0x1u

/* Inputs to build a single-receiver lend/donate/share descriptor; handle is
 * zero in a request and the allocated handle in a retrieve response. */
typedef struct wt_ffa_mem_build {
    const wt_ffa_mem_constituent_t* constituents;
    uint64_t tag;
    uint64_t handle;
    uint32_t flags;
    uint32_t constituent_count;
    wt_ffa_mem_op_t op;
    uint16_t sender;
    uint16_t receiver;
    uint16_t attributes;
    uint8_t  permissions;
    /* 0 selects the size of the reader's version: 16 bytes through FF-A 1.1,
     * 32 from 1.2 (DEN0077A 18.5.3); appended so older initializers hold. */
    uint8_t  access_desc_size;
    /* 16 implementation-defined bytes for a v1.2 descriptor, or NULL. */
    const uint8_t* impdef;
    /* The reader's FF-A version: 1.0 selects the v1.0 layout, 0 or any later
     * version Table 1.20. */
    uint32_t version;
} wt_ffa_mem_build_t;

/* Memory region attributes bits[5:0] (DEN0140 Table 1.18): the type is not
 * the reserved b'11, a Normal cacheability and shareability are not marked
 * must-not-be-used, and the bits a Device or unspecified type leaves reserved
 * are zero. Returns 0 or WT_FFA_INVALID_PARAMETERS (1.10.4.2 item 5). */
int wt_ffa_mem_attributes_check(uint16_t attributes);

/* The attributes the borrowers of a lend or share map with, from the valid
 * attributes its sender stated (DEN0140 1.10.4.2): an unspecified type leaves
 * them to the relayer, which maps only WT_FFA_MEM_ATTR_RELAYER. Returns 0 with
 * *out set, WT_FFA_DENIED for more permissive attributes than that (item 1),
 * or WT_FFA_INVALID_PARAMETERS for less permissive ones it cannot map, such
 * as Device, non-cacheable, or non-shareable memory (item 5). */
int wt_ffa_mem_send_attributes(uint16_t attributes, uint16_t* out);

/* Lay out a single-receiver memory transaction descriptor for op into buf
 * (header, one endpoint access descriptor, composite header, constituents).
 * The handle is left zero (the relayer allocates it). Returns 0 with *out_len
 * set to the encoded length, or WT_FFA_INVALID_PARAMETERS on a bad request,
 * or WT_FFA_NO_MEMORY if buf cannot hold the descriptor. */
int wt_ffa_mem_txn_build(uint8_t* buf, size_t len,
                         const wt_ffa_mem_build_t* in, size_t* out_len);

/* Relayer validation of a lend/donate/share transaction descriptor for op
 * (DEN0140 Ch.2): the header is well formed and inside buf, the flags ask for
 * no time slicing (the parsed flags keep only the zero-memory bit, the rest
 * being SBZ), the sender equals
 * expect_sender, every receiver descriptor references one composite whose
 * constituents are page-aligned, non-zero, non-overlapping, in range, and sum
 * to the declared page count, and the permissions and attributes are legal.
 * On success 0 is returned and *out holds the parsed header. Otherwise a
 * WT_FFA_* negative: DENIED for a wrong sender, NOT_SUPPORTED for an access
 * descriptor size this SPMC cannot parse, NO_MEMORY for more constituents than
 * WT_FFA_MEM_MAX_REGIONS, INVALID_PARAMETERS for any malformed field. */
int wt_ffa_mem_txn_validate(const uint8_t* buf, size_t len, wt_ffa_mem_op_t op,
                            uint16_t expect_sender, wt_ffa_mem_txn_t* out);

/* wt_ffa_mem_txn_validate for a descriptor laid out for FF-A version: a 1.0
 * caller's in the v1.0 layout, any later one's in Table 1.20. */
int wt_ffa_mem_txn_validate_at(const uint8_t* buf, size_t len,
                               wt_ffa_mem_op_t op, uint16_t expect_sender,
                               uint32_t version, wt_ffa_mem_txn_t* out);

/* wt_ffa_mem_txn_validate for a lend/donate/share the relayer is asked to
 * start: its Handle field is zero as well (DEN0140 1.11.1), since this SPMC
 * allocates every handle and takes none from a Hypervisor. A descriptor sent
 * in fragments carries its reserved handle in registers, not here. */
int wt_ffa_mem_send_validate(const uint8_t* buf, size_t len, wt_ffa_mem_op_t op,
                             uint16_t expect_sender, wt_ffa_mem_txn_t* out);
int wt_ffa_mem_send_validate_at(const uint8_t* buf, size_t len,
                                wt_ffa_mem_op_t op, uint16_t expect_sender,
                                uint32_t version, wt_ffa_mem_txn_t* out);

/* Read receiver index's endpoint id and permissions from a descriptor that
 * wt_ffa_mem_txn_validate has accepted. */
int wt_ffa_mem_receiver(const uint8_t* buf, size_t len,
                        const wt_ffa_mem_txn_t* txn, uint32_t index,
                        uint16_t* out_id, uint8_t* out_perms);

/* Read constituent index from a descriptor that wt_ffa_mem_txn_validate has
 * accepted. */
int wt_ffa_mem_constituent(const uint8_t* buf, size_t len,
                           const wt_ffa_mem_txn_t* txn, uint32_t index,
                           wt_ffa_mem_constituent_t* out);

/* Collect the constituents of receiver_index from an accepted descriptor into
 * a mapping list: each region's base, page count, the receiver's permissions,
 * and the security state from the transaction attributes. Returns 0 with
 * *out_n set, WT_FFA_INVALID_PARAMETERS for a bad argument, or WT_FFA_NO_MEMORY
 * if the descriptor has more constituents than max. */
int wt_ffa_mem_regions_from_txn(const uint8_t* buf, size_t len,
                                const wt_ffa_mem_txn_t* txn,
                                uint32_t receiver_index,
                                wt_ffa_mem_region_t* out, uint32_t max,
                                uint32_t* out_n);

/* Lay out a single-receiver memory retrieve request for handle: a transaction
 * descriptor header plus one endpoint access descriptor and no composite.
 * Returns 0 with *out_len set, or WT_FFA_NO_MEMORY. The plain form writes the
 * 16-byte FF-A 1.1 access descriptor, _at the header and access descriptor of
 * version (the 32-byte v1.0 header for a v1.0 reader). */
int wt_ffa_mem_retrieve_req_build(uint8_t* buf, size_t len, uint64_t handle,
                                  uint16_t sender, uint16_t receiver,
                                  uint8_t permissions, size_t* out_len);
int wt_ffa_mem_retrieve_req_build_at(uint8_t* buf, size_t len, uint64_t handle,
                                     uint16_t sender, uint16_t receiver,
                                     uint8_t permissions, uint32_t version,
                                     size_t* out_len);

/* Parse a memory retrieve request: the handle, the sender (owner), and the
 * single receiver. Returns 0, WT_FFA_NOT_SUPPORTED for an access descriptor
 * size this SPMC cannot parse or more than one receiver, or
 * WT_FFA_INVALID_PARAMETERS for a malformed descriptor. */
int wt_ffa_mem_retrieve_req_parse(const uint8_t* buf, size_t len,
                                  uint64_t* out_handle, uint16_t* out_sender,
                                  uint16_t* out_receiver);

/* Lay out a relinquish descriptor naming one endpoint. Returns 0 with *out_len
 * set, WT_FFA_INVALID_PARAMETERS for a reserved flag, or WT_FFA_NO_MEMORY. */
int wt_ffa_mem_relinquish_build(uint8_t* buf, size_t len, uint64_t handle,
                                uint32_t flags, uint16_t endpoint,
                                size_t* out_len);

/* wt_ffa_mem_relinquish_parse that also returns the descriptor's flags. */
int wt_ffa_mem_relinquish_parse_ex(const uint8_t* buf, size_t len,
                                   uint64_t* out_handle, uint16_t* out_endpoint,
                                   uint32_t* out_flags);

/* Everything a retrieve request states, for the relayer to hold against the
 * transaction it names (11.4.2), including the ranges one receiver may name
 * in a composite of its own. */
typedef struct wt_ffa_mem_retrieve_req {
    uint64_t handle;
    uint64_t tag;
    uint32_t flags;
    uint32_t receiver_count;
    uint32_t access_desc_size;
    uint16_t sender;
    uint16_t attributes;
    uint16_t receivers[3];
    uint8_t  permissions[3];
    uint8_t  impdef[3][16];
    uint8_t  access_flags[3];
    /* The address ranges entry range_index names for its own mapping
     * (DEN0140 1.11.3.2); range_count is 0 when every entry leaves them to
     * the relayer. */
    uint32_t range_count;
    uint32_t range_index;
    wt_ffa_mem_constituent_t ranges[WT_FFA_MEM_MAX_REGIONS];
} wt_ffa_mem_retrieve_req_t;

int wt_ffa_mem_retrieve_req_parse_ex(const uint8_t* buf, size_t len,
                                     wt_ffa_mem_retrieve_req_t* out);
/* wt_ffa_mem_retrieve_req_parse_ex for a request laid out for FF-A version. */
int wt_ffa_mem_retrieve_req_parse_at(const uint8_t* buf, size_t len,
                                     uint32_t version,
                                     wt_ffa_mem_retrieve_req_t* out);

/* FFA_MEM_RECLAIM flags (Table 2.31): 0, or WT_FFA_INVALID_PARAMETERS for the
 * time-slicing bit; bits[31:2] are SBZ and ignored. */
int wt_ffa_mem_reclaim_flags_check(uint32_t flags);

/* Parse a relinquish descriptor with exactly one endpoint. Returns 0,
 * WT_FFA_NOT_SUPPORTED for more than one endpoint, or
 * WT_FFA_INVALID_PARAMETERS for a malformed descriptor. */
int wt_ffa_mem_relinquish_parse(const uint8_t* buf, size_t len,
                                uint64_t* out_handle, uint16_t* out_endpoint);

/* FFA_RXTX_MAP buffer geometry (7.2.1): each of TX and RX is pages 4 KB pages,
 * page-aligned, distinct, and non-overlapping. Returns 0 or
 * WT_FFA_INVALID_PARAMETERS. */
#define WT_FFA_RXTX_MIN_PAGES           1u
#define WT_FFA_RXTX_MAX_PAGES           64u
int wt_ffa_rxtx_validate(uint64_t tx, uint64_t rx, uint32_t pages);

/* One endpoint's RX/TX pair and who owns its RX buffer (7.2.2): the producer
 * acquires RX before it writes, the endpoint hands it back with RX_RELEASE.
 * rx_full is one of the WT_FFA_RX_* states below. */
#define WT_FFA_RX_EMPTY  0u
#define WT_FFA_RX_OWNED  1u
/* Full with a partition message, still the producer's until the endpoint
 * retrieves its RX-full notification (7.2.2.4.2 rule 2.1.1). */
#define WT_FFA_RX_POSTED 2u
typedef struct wt_ffa_mailbox {
    uint64_t tx;
    uint64_t rx;
    uint32_t pages;
    uint8_t mapped;
    uint8_t rx_full;
} wt_ffa_mailbox_t;

/* The page count in an FFA_RXTX_MAP w3; bits[31:6] are SBZ, which the callee
 * ignores (Table 13.25, 11.2). */
#define WT_FFA_RXTX_PAGE_COUNT(w3)      ((uint32_t)(w3) & 0x3Fu)

/* w3 is the raw FFA_RXTX_MAP page-count word. DENIED when a pair is already
 * mapped, INVALID_PARAMETERS for bad geometry. */
int wt_ffa_mailbox_map(wt_ffa_mailbox_t* mb, uint64_t tx, uint64_t rx,
                       uint32_t w3);
/* INVALID_PARAMETERS when no pair is mapped. */
int wt_ffa_mailbox_unmap(wt_ffa_mailbox_t* mb);
/* Non-zero when [base, base + size) holds a page of mb's mapped pair. */
int wt_ffa_mailbox_overlaps(const wt_ffa_mailbox_t* mb, uint64_t base,
                            uint64_t size);
/* Where a memory management call's descriptor of len bytes sits: the caller's
 * TX buffer (DEN0140 2.1.1.2 items 1-2), as no dynamically allocated buffer is
 * supported (4.1.1.3), so addr and pages (w3/x3, w4) are zero. Returns 0 with
 * *out_tx set, or INVALID_PARAMETERS for a buffer address or size, no mapped
 * pair, or a descriptor longer than the TX buffer. */
int wt_ffa_mem_tx_buffer(const wt_ffa_mailbox_t* mb, uint64_t addr,
                         uint32_t pages, uint32_t len, uint64_t* out_tx);
/* DENIED when no pair is mapped, BUSY while RX is full. The endpoint owns
 * the framework message written next (7.2.2.4.2 rule 2.2). */
int wt_ffa_mailbox_rx_acquire(wt_ffa_mailbox_t* mb);
/* As rx_acquire, for an FFA_MSG_SEND2 partition message: RX is posted. */
int wt_ffa_mailbox_rx_post(wt_ffa_mailbox_t* mb);
/* A completed FFA_NOTIFICATION_GET whose framework bitmap carried an RX-full
 * notification hands a posted RX buffer to the endpoint. */
void wt_ffa_mailbox_rx_claim(wt_ffa_mailbox_t* mb, uint64_t framework);
/* DENIED unless the endpoint owns RX (Table 13.22). */
int wt_ffa_mailbox_rx_release(wt_ffa_mailbox_t* mb);

/* Memory transaction handle registry (handle lifetime state). A handle names a
 * transaction from allocation until reclaim; DEN0140 5.10.2 sets bit[63] of a
 * handle allocated by the SPMC to zero. */
#define WT_FFA_MEM_MAX_HANDLES          8u
#define WT_FFA_MEM_HANDLE_INVALID       0xFFFFFFFFFFFFFFFFull

typedef enum wt_ffa_mem_state {
    WT_FFA_MEM_STATE_FREE = 0,
    WT_FFA_MEM_STATE_SHARED,
    WT_FFA_MEM_STATE_LENT,
    WT_FFA_MEM_STATE_DONATED
} wt_ffa_mem_state_t;

/* A transaction names up to this many borrowers (10.2: memory may be shared
 * with or lent to several endpoints at once). */
#define WT_FFA_MEM_MAX_BORROWERS        3u

typedef struct wt_ffa_mem_borrower {
    uint16_t id;
    uint8_t  permissions;  /* what the owner granted this borrower */
    uint8_t  retrieved;
    uint8_t  mapping;      /* relayer cookie: how the retrieve mapped it */
    /* What the owner attached for this borrower (FF-A 1.2); its retrieve
     * request must repeat it. Zero for a 16-byte access descriptor. */
    uint8_t  impdef[16];
    uint8_t  ever_retrieved; /* set by the first retrieve, kept on relinquish */
} wt_ffa_mem_borrower_t;

typedef struct wt_ffa_mem_handle_entry {
    uint64_t handle;
    uint64_t tag;
    wt_ffa_mem_region_t regions[WT_FFA_MEM_MAX_REGIONS];
    wt_ffa_mem_borrower_t borrowers[WT_FFA_MEM_MAX_BORROWERS];
    uint32_t owner_cookie; /* relayer cookie: the owner's own mapping */
    uint16_t owner;
    uint16_t borrower;     /* the first borrower */
    uint16_t attributes;   /* Table 1.18 bits[5:0] every borrower maps with */
    uint8_t  state;
    uint8_t  retrieved;    /* borrowers currently holding the region */
    uint8_t  region_count;
    uint8_t  borrower_count;
} wt_ffa_mem_handle_entry_t;

typedef struct wt_ffa_mem_registry {
    wt_ffa_mem_handle_entry_t entries[WT_FFA_MEM_MAX_HANDLES];
    uint64_t next_handle;
} wt_ffa_mem_registry_t;

void wt_ffa_mem_registry_init(wt_ffa_mem_registry_t* reg);

/* Take the next handle for a transaction whose descriptor is still arriving
 * in fragments (DEN0140 4.1.2): the same handle names the region once
 * wt_ffa_mem_share_register_as binds it. */
uint64_t wt_ffa_mem_handle_reserve(wt_ffa_mem_registry_t* reg);

/* wt_ffa_mem_share_register with a handle reserved earlier. */
int wt_ffa_mem_share_register_as(wt_ffa_mem_registry_t* reg,
                                 wt_ffa_mem_op_t op, uint16_t owner,
                                 uint16_t borrower,
                                 const wt_ffa_mem_region_t* regions,
                                 uint32_t n, uint64_t handle);

/* Reassembly of a transaction descriptor sent in fragments (DEN0140 4.1.2),
 * bounded by the largest descriptor the relayer takes in one piece. */
#define WT_FFA_MEM_FRAG_MAX WT_FFA_MEM_PAGE_SIZE

typedef struct wt_ffa_mem_frag {
    uint8_t buf[WT_FFA_MEM_FRAG_MAX];
    uint64_t handle;
    uint32_t total;
    uint32_t received;
    uint16_t sender;
    uint8_t op;
    uint8_t active;
    uint8_t aborted;
} wt_ffa_mem_frag_t;

/* Start reassembly with the first fragment of a descriptor of total bytes.
 * Returns 0, WT_FFA_INVALID_PARAMETERS for a fragment that is empty or not
 * shorter than total, or WT_FFA_NO_MEMORY past WT_FFA_MEM_FRAG_MAX. */
int wt_ffa_mem_frag_begin(wt_ffa_mem_frag_t* f, uint64_t handle,
                          uint16_t sender, uint8_t op, const uint8_t* frag,
                          uint32_t frag_len, uint32_t total);

/* Append the next fragment; *done is set once the descriptor is whole.
 * Returns 0, or WT_FFA_INVALID_PARAMETERS for another handle or sender, an
 * empty fragment, or one past the declared total. */
int wt_ffa_mem_frag_add(wt_ffa_mem_frag_t* f, uint64_t handle,
                        uint16_t sender, const uint8_t* frag,
                        uint32_t frag_len, int* done);

void wt_ffa_mem_frag_reset(wt_ffa_mem_frag_t* f);

/* The descriptor length the first fragment's own headers describe (a retrieve
 * request when retrieve is non-zero, else a lend/share/donate), so a declared
 * total that disagrees is refused before any fragment is taken. Returns 1 with
 * *size set, or 0 when the fragment is too short to tell or its access array
 * is one the full parse refuses (that parse then answers the request). */
int wt_ffa_mem_frag_expected(const uint8_t* frag, uint32_t frag_len,
                             int retrieve, uint64_t* size);
/* wt_ffa_mem_frag_expected for a descriptor laid out for FF-A version. */
int wt_ffa_mem_frag_expected_at(const uint8_t* frag, uint32_t frag_len,
                                int retrieve, uint32_t version, uint64_t* size);

/* Allocate a unique handle for a validated transaction, with no captured
 * region set. Returns 0 with *out_handle set, or WT_FFA_NO_MEMORY when the
 * registry is full. */
int wt_ffa_mem_handle_alloc(wt_ffa_mem_registry_t* reg, wt_ffa_mem_op_t op,
                            uint16_t owner, uint16_t borrower,
                            uint64_t* out_handle);

/* Allocate a handle and capture the region set to map into the borrower on
 * retrieve. Returns 0 with *out_handle set, WT_FFA_INVALID_PARAMETERS for a bad
 * argument or a region count over WT_FFA_MEM_MAX_REGIONS, or WT_FFA_NO_MEMORY
 * when the registry is full. */
int wt_ffa_mem_share_register(wt_ffa_mem_registry_t* reg, wt_ffa_mem_op_t op,
                              uint16_t owner, uint16_t borrower,
                              const wt_ffa_mem_region_t* regions, uint32_t n,
                              uint64_t* out_handle);

/* The implementation-defined bytes of receiver index (zeros for a 16-byte
 * access descriptor). */
int wt_ffa_mem_receiver_impdef(const uint8_t* buf, size_t len,
                               const wt_ffa_mem_txn_t* txn, uint32_t index,
                               uint8_t* out16);

/* Record the tag the owner attached (a retrieve request must repeat it) and
 * the relayer's own cookie for the transaction. */
void wt_ffa_mem_handle_set_meta(wt_ffa_mem_registry_t* reg, uint64_t handle,
                                uint64_t tag, uint32_t owner_cookie);

/* Record the attributes (wt_ffa_mem_send_attributes) the borrowers of a live
 * handle map with; a retrieve request is held against them. */
void wt_ffa_mem_handle_set_attributes(wt_ffa_mem_registry_t* reg,
                                      uint64_t handle, uint16_t attributes);

/* Name a further borrower of a live handle nobody has retrieved yet. Returns 0,
 * WT_FFA_INVALID_PARAMETERS for an unknown handle, the owner, or a repeat, or
 * WT_FFA_NO_MEMORY past WT_FFA_MEM_MAX_BORROWERS. */
int wt_ffa_mem_handle_add_borrower(wt_ffa_mem_registry_t* reg, uint64_t handle,
                                   uint16_t borrower, uint8_t permissions);

/* The borrower record of a live handle, or NULL. */
wt_ffa_mem_borrower_t* wt_ffa_mem_handle_borrower(wt_ffa_mem_registry_t* reg,
                                                  uint64_t handle,
                                                  uint16_t borrower);

/* Non-zero when [base, base + pages) overlaps memory a live handle holds. */
int wt_ffa_mem_registry_overlaps(const wt_ffa_mem_registry_t* reg,
                                 uint64_t base, uint32_t pages);

/* Copy the region set captured for a live handle into out (up to max). Returns
 * 0 with *out_n set, WT_FFA_INVALID_PARAMETERS for an unknown handle or bad
 * argument, or WT_FFA_NO_MEMORY if the handle has more regions than max. */
int wt_ffa_mem_handle_regions(const wt_ffa_mem_registry_t* reg, uint64_t handle,
                              wt_ffa_mem_region_t* out, uint32_t max,
                              uint32_t* out_n);

/* Look up a live handle. Returns 0 with *out set, or WT_FFA_INVALID_PARAMETERS
 * for an unknown handle. */
int wt_ffa_mem_handle_lookup(const wt_ffa_mem_registry_t* reg, uint64_t handle,
                             const wt_ffa_mem_handle_entry_t** out);

/* Free a handle unconditionally (a donate consumes it once retrieved). */
int wt_ffa_mem_handle_free(wt_ffa_mem_registry_t* reg, uint64_t handle);

/* A borrower retrieves a handle once. Returns 0, WT_FFA_INVALID_PARAMETERS for
 * an unknown handle, or WT_FFA_DENIED for the wrong borrower or a second
 * retrieve. */
int wt_ffa_mem_handle_retrieve(wt_ffa_mem_registry_t* reg, uint64_t handle,
                               uint16_t borrower);

/* A borrower relinquishes a retrieved handle. Returns 0, or a WT_FFA_* negative
 * for an unknown handle, the wrong borrower, or a handle not retrieved. */
int wt_ffa_mem_handle_relinquish(wt_ffa_mem_registry_t* reg, uint64_t handle,
                                 uint16_t borrower);

/* The owner reclaims a relinquished handle, freeing it for reuse refusal.
 * Returns 0, WT_FFA_INVALID_PARAMETERS for an unknown handle, or WT_FFA_DENIED
 * for the wrong owner or a still-retrieved handle. */
int wt_ffa_mem_handle_reclaim(wt_ffa_mem_registry_t* reg, uint64_t handle,
                              uint16_t owner);

/* The transaction-type flag (Table 1.23 bits[4:3]) of a live handle's state. */
uint32_t wt_ffa_mem_type_flag(uint8_t state);

/* Hold receiver's parsed retrieve request against the transaction its handle
 * names (DEN0140 2.4.1.2): every named endpoint is a borrower whose
 * implementation-defined bytes it repeats, no borrower is named twice and
 * each of them is named (1.11.3.3), or with the bypass flag the receiver
 * alone, the Non-retrieval Borrower flag is clear in the receiver's own entry
 * and set in every other (Table 1.17), the tag, flags, and transaction type
 * agree, attributes it states are the transaction's own (1.10.4.2), and every
 * other borrower named carries the data access the lender gave it. Returns 0,
 * WT_FFA_INVALID_PARAMETERS for a field the request got wrong or attributes
 * less permissive than the transaction's (item 5), or WT_FFA_DENIED for Device
 * memory (only Normal memory is ever sent), more permissive attributes, or
 * another borrower's data access that is not the lender's. */
int wt_ffa_mem_retrieve_req_check(const wt_ffa_mem_handle_entry_t* e,
                                  const wt_ffa_mem_retrieve_req_t* rq,
                                  uint16_t receiver);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_MEM_H */
