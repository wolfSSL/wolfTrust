/* spm_mem.c
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

/* The SPMC memory-sharing relayer. A borrower's table is prebuilt from its
 * domain's region set, so a retrieve appends the shared region to that set and
 * re-programs the domain (a fresh table with its own ASID, the shared range
 * non-global); relinquish drops the region and re-programs back to the
 * original table. No TLB maintenance is needed across the switch. */

#include "wolftrust/arch/aarch64/spm_mem.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/arch.h"
#include "wolftrust/types.h"

#define WT_SPM_MEM_MAX_BIND 4u

static wt_ffa_mem_registry_t g_reg;
static wt_spm_mem_binding_t g_bind[WT_SPM_MEM_MAX_BIND];

void wt_spm_mem_init(void)
{
    unsigned int i;

    wt_ffa_mem_registry_init(&g_reg);
    for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
        g_bind[i].co = NULL;
        g_bind[i].dom = NULL;
        g_bind[i].id = 0u;
        g_bind[i].base_count = 0u;
        g_bind[i].live = 0u;
    }
}

static wt_spm_mem_binding_t* bind_by_id(uint16_t id)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
        if ((g_bind[i].live != 0u) && (g_bind[i].id == id)) {
            return &g_bind[i];
        }
    }
    return NULL;
}

int wt_spm_mem_bind(uint16_t id, struct wt_co* co, wt_secure_domain_t* dom)
{
    wt_spm_mem_binding_t* b;
    unsigned int i;

    if ((co == NULL) || (dom == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    b = bind_by_id(id);
    if (b == NULL) {
        for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
            if (g_bind[i].live == 0u) {
                b = &g_bind[i];
                break;
            }
        }
    }
    if (b == NULL) {
        return WT_FFA_NO_MEMORY;
    }
    b->co = co;
    b->dom = dom;
    b->id = id;
    b->base_count = (uint8_t)dom->region_count;
    b->live = 1u;
    return 0;
}

const wt_spm_mem_binding_t* wt_spm_mem_binding(const struct wt_co* co)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
        if ((g_bind[i].live != 0u) && (g_bind[i].co == co)) {
            return &g_bind[i];
        }
    }
    return NULL;
}

int wt_spm_mem_share(const uint8_t* desc, size_t len, wt_ffa_mem_op_t op,
                     uint16_t sender, uint64_t* out_handle)
{
    wt_ffa_mem_txn_t txn;
    wt_ffa_mem_region_t regs[WT_FFA_MEM_MAX_REGIONS];
    uint32_t n = 0u;
    uint16_t receiver = 0u;
    uint8_t perms = 0u;
    int ret;

    if (out_handle == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_txn_validate(desc, len, op, sender, &txn);
    if (ret == 0) {
        ret = wt_ffa_mem_receiver(desc, len, &txn, 0u, &receiver, &perms);
    }
    if (ret == 0) {
        ret = wt_ffa_mem_regions_from_txn(desc, len, &txn, 0u, regs,
                                          WT_FFA_MEM_MAX_REGIONS, &n);
    }
    if (ret == 0) {
        ret = wt_ffa_mem_share_register(&g_reg, op, sender, receiver, regs, n,
                                        out_handle);
    }
    return ret;
}

/* The borrower's stage-1 attributes for a region: read-only only when the
 * owner granted RO, otherwise read-write; never executable; Non-secure when
 * the shared memory is. */
static uint32_t region_attributes(const wt_ffa_mem_region_t* r)
{
    uint32_t attrs = WT_MEM_ATTR_READ;

    if ((r->permissions & WT_FFA_MEM_PERM_DATA_MASK) != WT_FFA_MEM_PERM_DATA_RO) {
        attrs |= WT_MEM_ATTR_WRITE;
    }
    if (r->ns != 0u) {
        attrs |= WT_TABLES_ATTR_NS;
    }
    return attrs;
}

static uint32_t type_flag(uint8_t state)
{
    uint32_t flag;

    switch (state) {
        case (uint8_t)WT_FFA_MEM_STATE_LENT:
            flag = WT_FFA_MEM_FLAG_TYPE_LEND;
            break;
        case (uint8_t)WT_FFA_MEM_STATE_DONATED:
            flag = WT_FFA_MEM_FLAG_TYPE_DONATE;
            break;
        default:
            flag = WT_FFA_MEM_FLAG_TYPE_SHARE;
            break;
    }
    return flag;
}

int wt_spm_mem_retrieve(const uint8_t* req, size_t len, uint16_t receiver,
                        uint8_t* resp, size_t resp_cap, size_t* out_resp_len)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_spm_mem_binding_t* b;
    wt_ffa_mem_region_t regs[WT_FFA_MEM_MAX_REGIONS];
    wt_ffa_mem_constituent_t cons[WT_FFA_MEM_MAX_REGIONS];
    wt_ffa_mem_build_t in;
    uint64_t handle = 0u;
    uint16_t sender = 0u;
    uint16_t req_receiver = 0u;
    uint32_t n = 0u;
    uint32_t i;
    size_t count;
    int ret;

    if ((resp == NULL) || (out_resp_len == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_retrieve_req_parse(req, len, &handle, &sender,
                                        &req_receiver);
    if (ret != 0) {
        return ret;
    }
    if (req_receiver != receiver) {
        return WT_FFA_DENIED;
    }
    ret = wt_ffa_mem_handle_lookup(&g_reg, handle, &e);
    if (ret != 0) {
        return ret;
    }
    if (e->owner != sender) {
        return WT_FFA_DENIED;
    }
    b = bind_by_id(receiver);
    if (b == NULL) {
        return WT_FFA_DENIED;
    }
    ret = wt_ffa_mem_handle_regions(&g_reg, handle, regs,
                                    WT_FFA_MEM_MAX_REGIONS, &n);
    if (ret != 0) {
        return ret;
    }
    count = b->dom->region_count;
    if ((n < 1u) || ((count + n) > WT_MAX_MEMORY_REGIONS)) {
        return WT_FFA_NO_MEMORY;
    }
    for (i = 0u; i < n; i++) {
        cons[i].address = regs[i].base;
        cons[i].page_count = regs[i].page_count;
    }
    in.constituents = cons;
    in.constituent_count = n;
    in.tag = 0u;
    in.handle = handle;
    in.flags = type_flag(e->state);
    in.op = WT_FFA_MEM_OP_SHARE;
    in.sender = e->owner;
    in.receiver = receiver;
    in.attributes = (uint16_t)(WT_FFA_MEM_ATTR_TYPE_NORMAL |
                               (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT) |
                               WT_FFA_MEM_ATTR_SHARE_INNER |
                               ((regs[0].ns != 0u) ? WT_FFA_MEM_ATTR_NS : 0u));
    in.permissions = regs[0].permissions;
    ret = wt_ffa_mem_txn_build(resp, resp_cap, &in, out_resp_len);
    if (ret != 0) {
        return ret;
    }
    ret = wt_ffa_mem_handle_retrieve(&g_reg, handle, receiver);
    if (ret != 0) {
        return ret;
    }
    b->base_count = (uint8_t)count;
    for (i = 0u; i < n; i++) {
        b->dom->regions[count + i].base = (uintptr_t)regs[i].base;
        b->dom->regions[count + i].size =
            (size_t)regs[i].page_count * WT_FFA_MEM_PAGE_SIZE;
        b->dom->regions[count + i].attributes = region_attributes(&regs[i]);
    }
    b->dom->region_count = count + n;
    wt_arch_program_sp_thread_domain(b->dom->regions, b->dom->region_count);
    return 0;
}

int wt_spm_mem_relinquish(const uint8_t* rel, size_t len, uint16_t endpoint)
{
    wt_spm_mem_binding_t* b;
    uint64_t handle = 0u;
    uint16_t ep = 0u;
    int ret;

    ret = wt_ffa_mem_relinquish_parse(rel, len, &handle, &ep);
    if (ret != 0) {
        return ret;
    }
    if (ep != endpoint) {
        return WT_FFA_DENIED;
    }
    b = bind_by_id(endpoint);
    if (b == NULL) {
        return WT_FFA_DENIED;
    }
    ret = wt_ffa_mem_handle_relinquish(&g_reg, handle, endpoint);
    if (ret != 0) {
        return ret;
    }
    b->dom->region_count = b->base_count;
    wt_arch_program_sp_thread_domain(b->dom->regions, b->dom->region_count);
    return 0;
}

int wt_spm_mem_reclaim(uint64_t handle, uint16_t owner)
{
    return wt_ffa_mem_handle_reclaim(&g_reg, handle, owner);
}
