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

/* Arm FF-A Memory Management (DEN0140) v1.1/v1.2 transaction descriptors: the
 * lend/donate/share memory transaction descriptor and its endpoint access,
 * composite, and constituent sub-descriptors, plus the relayer validation a
 * 1.2 SPMC runs before it acts on a transaction. Pure functions over
 * caller-provided buffers; the FF-A function ids live in ffa_abi.h. */

#define WT_FFA_MEM_PAGE_SIZE            0x1000u

/* Fixed byte sizes of the v1.1 descriptor layout. */
#define WT_FFA_MEM_TXN_HDR_SIZE         48u  /* transaction descriptor header */
#define WT_FFA_MEM_ACCESS_SIZE          16u  /* endpoint memory access descriptor */
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
/* [36, 48) reserved, must be zero. */

/* Endpoint memory access descriptor field offsets (Table 5.16). */
#define WT_FFA_MEM_ACC_OFF_RECEIVER     0u   /* u16 receiver endpoint id */
#define WT_FFA_MEM_ACC_OFF_PERMS        2u   /* u8 access permissions */
#define WT_FFA_MEM_ACC_OFF_FLAGS        3u   /* u8 access descriptor flags */
#define WT_FFA_MEM_ACC_OFF_COMP_OFF     4u   /* u32 offset to the composite descriptor */
/* [8, 16) reserved, must be zero. */

/* Composite memory region header field offsets (Table 5.13). */
#define WT_FFA_MEM_COMP_OFF_PAGES       0u   /* u32 total page count */
#define WT_FFA_MEM_COMP_OFF_COUNT       4u   /* u32 constituent count */
/* [8, 16) reserved, must be zero. */

/* Constituent memory region descriptor field offsets (Table 5.11). */
#define WT_FFA_MEM_CONS_OFF_ADDR        0u   /* u64 page-aligned base address */
#define WT_FFA_MEM_CONS_OFF_PAGES       8u   /* u32 page count */
/* [12, 16) reserved, must be zero. */

/* Memory access permissions byte (Table 5.14). */
#define WT_FFA_MEM_PERM_DATA_MASK       0x3u
#define WT_FFA_MEM_PERM_DATA_NOT_SPEC   0x0u
#define WT_FFA_MEM_PERM_DATA_RO         0x1u
#define WT_FFA_MEM_PERM_DATA_RW         0x2u
#define WT_FFA_MEM_PERM_DATA_RSVD       0x3u
#define WT_FFA_MEM_PERM_INSTR_SHIFT     2u
#define WT_FFA_MEM_PERM_INSTR_MASK      0xCu
#define WT_FFA_MEM_PERM_INSTR_NOT_SPEC  0x0u
#define WT_FFA_MEM_PERM_INSTR_X         (0x1u << WT_FFA_MEM_PERM_INSTR_SHIFT)
#define WT_FFA_MEM_PERM_INSTR_NX        (0x2u << WT_FFA_MEM_PERM_INSTR_SHIFT)
#define WT_FFA_MEM_PERM_RSVD_MASK       0xF0u  /* bits[7:4] must be zero */

/* Transaction descriptor flags (Table 5.20/5.21). Bits[4:3] carry the
 * transaction type only in a retrieve response; they are zero in a send. */
#define WT_FFA_MEM_FLAG_ZERO            (1u << 0)
#define WT_FFA_MEM_FLAG_TIME_SLICE      (1u << 1)
#define WT_FFA_MEM_FLAG_TYPE_SHIFT      3u
#define WT_FFA_MEM_FLAG_TYPE_MASK       (0x3u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_TYPE_SHARE      (0x1u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_TYPE_LEND       (0x2u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_TYPE_DONATE     (0x3u << WT_FFA_MEM_FLAG_TYPE_SHIFT)
#define WT_FFA_MEM_FLAG_ALIGN_MASK      (0x1Fu << 5)  /* bits[9:5] alignment hint */
/* Flag bits a sender may set in a lend/donate/share request. */
#define WT_FFA_MEM_FLAG_SEND_MASK       (WT_FFA_MEM_FLAG_ZERO | \
                                         WT_FFA_MEM_FLAG_TIME_SLICE | \
                                         WT_FFA_MEM_FLAG_ALIGN_MASK)

/* Memory region attributes (Table 5.18). */
#define WT_FFA_MEM_ATTR_SHARE_MASK      0x3u
#define WT_FFA_MEM_ATTR_SHARE_NON       0x0u
#define WT_FFA_MEM_ATTR_SHARE_OUTER     0x2u
#define WT_FFA_MEM_ATTR_SHARE_INNER     0x3u
#define WT_FFA_MEM_ATTR_CACHE_SHIFT     2u
#define WT_FFA_MEM_ATTR_CACHE_MASK      (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT)
#define WT_FFA_MEM_ATTR_TYPE_SHIFT      4u
#define WT_FFA_MEM_ATTR_TYPE_MASK       (0x3u << WT_FFA_MEM_ATTR_TYPE_SHIFT)
#define WT_FFA_MEM_ATTR_TYPE_DEVICE     (0x1u << WT_FFA_MEM_ATTR_TYPE_SHIFT)
#define WT_FFA_MEM_ATTR_TYPE_NORMAL     (0x2u << WT_FFA_MEM_ATTR_TYPE_SHIFT)
#define WT_FFA_MEM_ATTR_NS              (1u << 6)   /* non-secure memory */
#define WT_FFA_MEM_ATTR_RSVD_MASK       0xFF80u     /* bits[15:7] must be zero */

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

/* Inputs to build a single-receiver lend/donate/share descriptor. */
typedef struct wt_ffa_mem_build {
    const wt_ffa_mem_constituent_t* constituents;
    uint64_t tag;
    uint32_t flags;
    uint32_t constituent_count;
    wt_ffa_mem_op_t op;
    uint16_t sender;
    uint16_t receiver;
    uint16_t attributes;
    uint8_t  permissions;
} wt_ffa_mem_build_t;

/* Lay out a single-receiver memory transaction descriptor for op into buf
 * (header, one endpoint access descriptor, composite header, constituents).
 * The handle is left zero (the relayer allocates it). Returns 0 with *out_len
 * set to the encoded length, or WT_FFA_INVALID_PARAMETERS on a bad request,
 * or WT_FFA_NO_MEMORY if buf cannot hold the descriptor. */
int wt_ffa_mem_txn_build(uint8_t* buf, size_t len,
                         const wt_ffa_mem_build_t* in, size_t* out_len);

/* Relayer validation of a lend/donate/share transaction descriptor for op
 * (DEN0140 Ch.2): the header is well formed and inside buf, the sender equals
 * expect_sender, every receiver descriptor references one composite whose
 * constituents are page-aligned, non-zero, non-overlapping, in range, and sum
 * to the declared page count, and the permissions and attributes are legal.
 * On success 0 is returned and *out holds the parsed header. Otherwise a
 * WT_FFA_* negative: DENIED for a wrong sender, NOT_SUPPORTED for an access
 * descriptor size this SPMC cannot parse, INVALID_PARAMETERS for any malformed
 * field. */
int wt_ffa_mem_txn_validate(const uint8_t* buf, size_t len, wt_ffa_mem_op_t op,
                            uint16_t expect_sender, wt_ffa_mem_txn_t* out);

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

/* FFA_RXTX_MAP buffer geometry (7.2.1): each of TX and RX is pages 4 KB pages,
 * page-aligned, distinct, and non-overlapping. Returns 0 or
 * WT_FFA_INVALID_PARAMETERS. */
#define WT_FFA_RXTX_MIN_PAGES           1u
#define WT_FFA_RXTX_MAX_PAGES           64u
int wt_ffa_rxtx_validate(uint64_t tx, uint64_t rx, uint32_t pages);

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

typedef struct wt_ffa_mem_handle_entry {
    uint64_t handle;
    uint16_t owner;
    uint16_t borrower;
    uint8_t  state;
    uint8_t  retrieved;
} wt_ffa_mem_handle_entry_t;

typedef struct wt_ffa_mem_registry {
    wt_ffa_mem_handle_entry_t entries[WT_FFA_MEM_MAX_HANDLES];
    uint64_t next_handle;
} wt_ffa_mem_registry_t;

void wt_ffa_mem_registry_init(wt_ffa_mem_registry_t* reg);

/* Allocate a unique handle for a validated transaction. Returns 0 with
 * *out_handle set, or WT_FFA_NO_MEMORY when the registry is full. */
int wt_ffa_mem_handle_alloc(wt_ffa_mem_registry_t* reg, wt_ffa_mem_op_t op,
                            uint16_t owner, uint16_t borrower,
                            uint64_t* out_handle);

/* Look up a live handle. Returns 0 with *out set, or WT_FFA_INVALID_PARAMETERS
 * for an unknown handle. */
int wt_ffa_mem_handle_lookup(const wt_ffa_mem_registry_t* reg, uint64_t handle,
                             const wt_ffa_mem_handle_entry_t** out);

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

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_MEM_H */
