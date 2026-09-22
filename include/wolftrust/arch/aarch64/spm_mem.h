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

#endif /* WOLFTRUST_ARCH_AARCH64_SPM_MEM_H */
