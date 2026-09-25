/* spm_mem.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_SPM_MEM_H
#define WOLFTRUST_ARCH_AARCH64_SPM_MEM_H

#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/ffm_domain.h"

#include <stddef.h>
#include <stdint.h>

/* The SPMC's FF-A memory-sharing relayer (DEN0140): validates a lend or share,
 * allocates the handle, and opens a window onto the region in the borrowing
 * partition's stage-1 table; relinquish closes it, reclaim frees the handle.
 * A partition's table changes only through these transactions. */

struct wt_co;

/* A partition that may take part in memory transactions: its endpoint id, its
 * coroutine (the caller identity at the SVC gate), and its mutable domain. */
typedef struct wt_spm_mem_binding {
    struct wt_co* co;
    wt_secure_domain_t* dom;
    uint16_t id;
    uint8_t live;
} wt_spm_mem_binding_t;

void wt_spm_mem_init(void);
/* The Non-secure memory a Normal-world sender may name. */
void wt_spm_mem_ns_window(uint64_t base, uint64_t size);

int wt_spm_mem_bind(uint16_t id, struct wt_co* co, wt_secure_domain_t* dom);

/* The binding of the calling partition, or NULL if it has none. */
const wt_spm_mem_binding_t* wt_spm_mem_binding(const struct wt_co* co);

/* Release everything the partition holds (wt_spm_mem_endpoint_teardown) and
 * forget its binding, so a coroutine reused later starts unbound. */
void wt_spm_mem_unbind(const struct wt_co* co);

/* Owner side: validate desc as a lend or share from sender and register it.
 * Returns 0 with *out_handle set, or a WT_FFA_* negative. */
int wt_spm_mem_share(const uint8_t* desc, size_t len, wt_ffa_mem_op_t op,
                     uint16_t sender, uint64_t* out_handle);

/* A descriptor sent in fragments (DEN0140 4.1.2). begin takes the first
 * fragment of a lend, share, donate (op = wt_ffa_mem_op_t) or retrieve request
 * (WT_SPM_MEM_FRAG_OP_RETRIEVE) and returns the handle that ties the rest to
 * it; next appends one, returning the bytes held in *offset and *done once the
 * descriptor is whole. frag_share completes a whole lend/share/donate under
 * that handle; a whole retrieve request is read with frag_desc and handed to
 * wt_spm_mem_retrieve by the caller, which then releases it. */
#define WT_SPM_MEM_FRAG_OP_RETRIEVE 0xFFu
int wt_spm_mem_frag_begin(uint8_t op, uint16_t sender, const uint8_t* frag,
                          uint32_t frag_len, uint32_t total, uint64_t* handle);
int wt_spm_mem_frag_next(uint64_t handle, uint16_t sender, const uint8_t* frag,
                         uint32_t frag_len, uint32_t* offset, int* done);
const uint8_t* wt_spm_mem_frag_desc(uint64_t handle, uint16_t sender,
                                    uint32_t* len, uint8_t* op);
void wt_spm_mem_frag_release(uint64_t handle, uint16_t sender);
int wt_spm_mem_frag_share(uint64_t handle, uint16_t sender);
/* A lend, share, or donate from the Normal world's TX buffer: its whole
 * descriptor, or first fragment when frag_len < total, is copied once into
 * Secure memory and then sent as wt_spm_mem_share or begun as
 * wt_spm_mem_frag_begin would. WT_FFA_NO_MEMORY past WT_FFA_MEM_FRAG_MAX. */
int wt_spm_mem_ns_send(wt_ffa_mem_op_t op, const uint8_t* tx,
                       uint32_t frag_len, uint32_t total, uint64_t* handle);
/* The sender unmapped the TX buffer its fragments come through: its next
 * FFA_MEM_FRAG_TX is answered WT_FFA_ABORTED and the transfer ends. */
void wt_spm_mem_frag_abort(uint16_t sender);

/* Borrower side: parse the retrieve request in req, check receiver is the
 * declared borrower and the request names the owner, write the retrieve
 * response descriptor into resp, map the region into the borrower's table, and
 * mark the handle retrieved. Returns 0 with *out_resp_len set, or a WT_FFA_*
 * negative with nothing changed. */
int wt_spm_mem_retrieve(const uint8_t* req, size_t len, uint16_t receiver,
                        uint8_t* resp, size_t resp_cap, size_t* out_resp_len);

/* Borrower side: parse the relinquish descriptor in rel, check it names the
 * caller, unmap the region, and mark the handle relinquished. */
int wt_spm_mem_relinquish(const uint8_t* rel, size_t len, uint16_t endpoint);

/* Owner side: free a handle no borrower holds; flags is the FFA_MEM_RECLAIM
 * flags word (bit 0 zeroes the memory first). */
int wt_spm_mem_reclaim(uint64_t handle, uint16_t owner, uint32_t flags);

/* Non-zero when [base, base + size) holds a page some memory transaction still
 * covers: no RX/TX pair may be mapped over it. */
int wt_spm_mem_in_transaction(uint64_t base, uint64_t size);

/* Non-zero when the Normal world still owns all of [base, base + size): it lies
 * in the window and no partition holds a page of it (one donated or lent). */
int wt_spm_mem_ns_owns(uint64_t base, uint64_t size);

/* Non-zero when the Normal world may still read (write = 0) or write
 * [base, base + size) of its window, the check every copy the SPMC makes on
 * its behalf passes: never a page it lent or donated, or one a partition now
 * owns; a page it shares only as the share left it. An empty span passes. */
int wt_spm_mem_ns_access(uint64_t base, uint64_t size, int write);

/* Provided by the SVC glue and the Normal-world dispatcher: non-zero when
 * [base, base + size) holds a page of an RX/TX pair a partition, or the Normal
 * world, has mapped with the SPMC. */
int wt_spm_mailbox_overlaps(uint64_t base, uint64_t size);
int wt_spm_ns_mailbox_overlaps(uint64_t base, uint64_t size);

/* FFA_MEM_PERM_GET/SET permission word (DEN0140 Tables 2.36 and 2.40):
 * bits[1:0] data access, bit[2] set = not executable. */
#define WT_FFA_PERM_DATA_MASK 0x3u
#define WT_FFA_PERM_DATA_NONE 0x0u
#define WT_FFA_PERM_DATA_RW   0x1u
#define WT_FFA_PERM_DATA_RO   0x3u
#define WT_FFA_PERM_XN        0x4u

/* Memory a partition may access, for the calls below: pages its manifest
 * names, and pages a donate made its own (DEN0140 2.4.1.2 item 12) that its
 * table still gives it and no live transaction covers. Its own memory is
 * those pages less the image every partition runs and memory a manifest
 * shares with another partition. */

/* FFA_MEM_PERM_GET (DEN0140 2.8) for a partition confined to dom: its
 * permissions on the page at va in *perm. Returns 0 or
 * WT_FFA_INVALID_PARAMETERS for an unaligned address or a page it may not
 * access (Table 2.37). */
int wt_spm_mem_perm_get(const wt_secure_domain_t* dom, uint64_t va,
                        uint32_t* perm);

/* FFA_MEM_PERM_SET (DEN0140 2.9) for a partition confined to dom whose RX/TX
 * pair is mb: re-permission pages pages at va. Returns 0, or
 * WT_FFA_INVALID_PARAMETERS (Table 2.41) for a bad encoding, alignment, or
 * count, a page that is not its own, or memory whose permissions are not the
 * partition's to change: memory a transaction covers, code every partition
 * runs, its mapped RX/TX pair, and, for read-only, the writable manifest
 * memory of a partition the relayer does not bind (an FF-M partition), which
 * the FF-M gate writes at S-EL1 through the partition's own table. The caller
 * answers DENIED outside the partition's initialization. */
int wt_spm_mem_perm_set(const wt_secure_domain_t* dom,
                        const wt_ffa_mailbox_t* mb, uint64_t va,
                        uint32_t pages, uint32_t perm);

/* Non-zero when the page at va may be one of an FFA_RXTX_MAP pair for the
 * partition confined to dom: its own Secure Normal memory, shared with no other
 * partition, that it may write and no memory transaction covers (DEN0077A
 * 7.2.2.2 rule 3: a pair shared with the SPMC is never visible to the Normal
 * world). */
int wt_spm_mem_rxtx_ok(const wt_secure_domain_t* dom, uint64_t va);

/* A bound partition faulted and is terminated: unmap everything it retrieved
 * (zeroing what its retrieve asked to be zeroed), end what it owns and no
 * borrower holds, leave what a borrower still holds to end with that borrower,
 * never give the partition access back (DEN0140 1.3.1 rule 9), and drop any
 * descriptor it was still sending in fragments. */
void wt_spm_mem_endpoint_teardown(const struct wt_co* co);

#endif /* WOLFTRUST_ARCH_AARCH64_SPM_MEM_H */
