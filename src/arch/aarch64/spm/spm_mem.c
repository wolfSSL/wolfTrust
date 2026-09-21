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

/* The SPMC memory-sharing relayer. Every page that can be shared is already in
 * every partition's table as an EL1-only entry, so a retrieve flips the
 * borrower's entries to EL0 in place and a relinquish flips them back; a lend
 * does the reverse to the owner. No table is rebuilt and the pool never grows;
 * each flip invalidates that table's ASID. */

#include "wolftrust/arch/aarch64/spm_mem.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/arch.h"
#include "wolftrust/types.h"

#include <string.h>

#define WT_SPM_MEM_MAX_BIND 8u
/* Borrower mapping cookie: the entry existed before the grant. */
#define WT_SPM_MEM_MAP_WAS_MAPPED 0x1u
/* Owner cookie, above the send flags it keeps: a borrower asked for the memory
 * to be zeroed, which happens once no borrower maps it any more. */
#define WT_SPM_MEM_COOKIE_ZERO_PENDING 0x80000000u

static wt_ffa_mem_registry_t g_reg;
static wt_spm_mem_binding_t g_bind[WT_SPM_MEM_MAX_BIND];
static uint64_t g_ns_base;
static uint64_t g_ns_limit;

void wt_spm_mem_init(void)
{
    unsigned int i;

    wt_ffa_mem_registry_init(&g_reg);
    for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
        g_bind[i].co = NULL;
        g_bind[i].dom = NULL;
        g_bind[i].id = 0u;
        g_bind[i].live = 0u;
    }
}

void wt_spm_mem_ns_window(uint64_t base, uint64_t size)
{
    g_ns_base = base;
    g_ns_limit = base + size;
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

static int id_is_secure(uint16_t id)
{
    return (id & 0x8000u) != 0u;
}

/* Only memory the sender owns outright may be sent (10.10): Non-secure memory
 * inside the window the SPMC maps, or a partition's own writable data pages.
 * The SPMC's own sends are its boot self-test. */
static int sender_owns(uint16_t sender, const wt_ffa_mem_region_t* r)
{
    const wt_spm_mem_binding_t* b;
    uint64_t size = (uint64_t)r->page_count * WT_FFA_MEM_PAGE_SIZE;
    uint64_t at;

    if (sender == WT_FFA_ID_SPMC) {
        return 1;
    }
    if (!id_is_secure(sender)) {
        return ((r->base >= g_ns_base) && (r->base < g_ns_limit) &&
                (size <= (g_ns_limit - r->base))) ? 1 : 0;
    }
    b = bind_by_id(sender);
    if (b == NULL) {
        return 0;
    }
    for (at = r->base; at < (r->base + size); at += WT_FFA_MEM_PAGE_SIZE) {
        if (wt_domain_page_writable(b->dom->regions, b->dom->region_count,
                                    (uintptr_t)at) == 0) {
            return 0;
        }
    }
    return 1;
}

/* A partition that is not bound may be named but can never retrieve. */
static int receiver_known(uint16_t id)
{
    return ((bind_by_id(id) != NULL) || (wt_spm_sp_by_ffa_id(id) != NULL)) ? 1 : 0;
}

/* A lend takes the owner's own access away until it reclaims (10.10.1); only a
 * partition's access is the SPMC's to take. */
static void owner_access(const wt_ffa_mem_handle_entry_t* e, int give)
{
    const wt_spm_mem_binding_t* b = bind_by_id(e->owner);
    int was_mapped = 1;
    uint32_t i;

    /* Lend and donate both take the owner's own access away; a share leaves
     * it. Donate never gives it back (there is no reclaim). */
    if ((b == NULL) || (e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED)) {
        return;
    }
    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        if (give != 0) {
            (void)wt_domain_grant(b->dom->regions, b->dom->region_count,
                                  (uintptr_t)e->regions[i].base,
                                  e->regions[i].page_count,
                                  WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE,
                                  &was_mapped);
        }
        else {
            (void)wt_domain_revoke(b->dom->regions, b->dom->region_count,
                                   (uintptr_t)e->regions[i].base,
                                   e->regions[i].page_count, 1);
        }
    }
}

/* The access permissions a sender may state (Table 5.14 usage): instruction
 * access is always the relayer's to fill in (it only ever answers
 * not-executable); a share or lend names the data access it grants, a donate
 * hands over full ownership and names none. */
static int send_permissions_ok(wt_ffa_mem_op_t op, uint8_t perms)
{
    uint8_t data = perms & WT_FFA_MEM_PERM_DATA_MASK;

    if ((perms & WT_FFA_MEM_PERM_INSTR_MASK) != WT_FFA_MEM_PERM_INSTR_NOT_SPEC) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (op == WT_FFA_MEM_OP_DONATE) {
        return (data == WT_FFA_MEM_PERM_DATA_NOT_SPEC) ? 0
                                                       : WT_FFA_INVALID_PARAMETERS;
    }
    return ((data == WT_FFA_MEM_PERM_DATA_RO) ||
            (data == WT_FFA_MEM_PERM_DATA_RW)) ? 0 : WT_FFA_INVALID_PARAMETERS;
}

int wt_spm_mem_share(const uint8_t* desc, size_t len, wt_ffa_mem_op_t op,
                     uint16_t sender, uint64_t* out_handle)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_txn_t txn;
    wt_ffa_mem_region_t regs[WT_FFA_MEM_MAX_REGIONS];
    uint32_t n = 0u;
    uint32_t i;
    uint16_t receiver = 0u;
    uint8_t perms = 0u;
    int ret;

    if (out_handle == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_txn_validate(desc, len, op, sender, &txn);
    if ((ret == 0) && (txn.receiver_count > WT_FFA_MEM_MAX_BORROWERS)) {
        ret = WT_FFA_NO_MEMORY;
    }
    for (i = 0u; (ret == 0) && (i < txn.receiver_count); i++) {
        ret = wt_ffa_mem_receiver(desc, len, &txn, i, &receiver, &perms);
        /* A borrower is a partition the SPMC can map into, never the sender. */
        if ((ret == 0) &&
            ((receiver == sender) || (receiver_known(receiver) == 0))) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
        if (ret == 0) {
            ret = send_permissions_ok(op, perms);
        }
    }
    if (ret == 0) {
        ret = wt_ffa_mem_regions_from_txn(desc, len, &txn, 0u, regs,
                                          WT_FFA_MEM_MAX_REGIONS, &n);
    }
    for (i = 0u; (ret == 0) && (i < n); i++) {
        regs[i].ns = id_is_secure(sender) ? 0u : 1u;
        /* A donate makes the receiver the owner, with full data access. */
        if (op == WT_FFA_MEM_OP_DONATE) {
            regs[i].permissions = (uint8_t)(WT_FFA_MEM_PERM_DATA_RW |
                                            WT_FFA_MEM_PERM_INSTR_NX);
        }
        if ((sender_owns(sender, &regs[i]) == 0) ||
            (wt_ffa_mem_registry_overlaps(&g_reg, regs[i].base,
                                          regs[i].page_count) != 0)) {
            ret = WT_FFA_DENIED;
        }
    }
    if (ret == 0) {
        ret = wt_ffa_mem_receiver(desc, len, &txn, 0u, &receiver, &perms);
    }
    if (ret == 0) {
        ret = wt_ffa_mem_share_register(&g_reg, op, sender, receiver, regs, n,
                                        out_handle);
    }
    for (i = 1u; (ret == 0) && (i < txn.receiver_count); i++) {
        ret = wt_ffa_mem_receiver(desc, len, &txn, i, &receiver, &perms);
        if (ret == 0) {
            ret = wt_ffa_mem_handle_add_borrower(&g_reg, *out_handle, receiver,
                                                 perms);
        }
        if (ret != 0) {
            (void)wt_ffa_mem_handle_reclaim(&g_reg, *out_handle, sender);
        }
    }
    if (ret == 0) {
        /* The cookie keeps the owner's flags: it may ask for the memory to be
         * zeroed before a borrower sees it. */
        wt_ffa_mem_handle_set_meta(&g_reg, *out_handle, txn.tag, txn.flags);
        if (wt_ffa_mem_handle_lookup(&g_reg, *out_handle, &e) == 0) {
            owner_access(e, 0);
        }
    }
    return ret;
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

/* What the borrower asked for against what the owner granted it (11.4.2):
 * it may ask for less, never for more, and never for execution. */
static int effective_permissions(uint8_t granted, uint8_t asked, uint8_t* out)
{
    uint8_t data = asked & WT_FFA_MEM_PERM_DATA_MASK;
    uint8_t granted_data = granted & WT_FFA_MEM_PERM_DATA_MASK;

    if ((data == WT_FFA_MEM_PERM_DATA_RSVD) ||
        ((asked & WT_FFA_MEM_PERM_INSTR_MASK) == WT_FFA_MEM_PERM_INSTR_MASK)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((asked & WT_FFA_MEM_PERM_INSTR_MASK) == WT_FFA_MEM_PERM_INSTR_X) {
        return WT_FFA_DENIED;
    }
    if (data == WT_FFA_MEM_PERM_DATA_NOT_SPEC) {
        data = granted_data;
    }
    if ((data == WT_FFA_MEM_PERM_DATA_RW) &&
        (granted_data != WT_FFA_MEM_PERM_DATA_RW)) {
        return WT_FFA_DENIED;
    }
    *out = (uint8_t)(data | WT_FFA_MEM_PERM_INSTR_NX);
    return 0;
}

/* Retrieve flags bits 9:5: with the valid bit clear the hint is MBZ; with it
 * set, n asks for a 2n x 4 KB boundary. Partitions see memory at its physical
 * address, so a region either already sits on that boundary or cannot. */
#define WT_FFA_MEM_FLAG_ALIGN_VALID (1u << 9)
#define WT_FFA_MEM_FLAG_ALIGN_SHIFT 5u

static int alignment_hint_ok(const wt_ffa_mem_handle_entry_t* e, uint32_t flags)
{
    uint32_t hint = (flags >> WT_FFA_MEM_FLAG_ALIGN_SHIFT) & 0xFu;
    uint64_t boundary;
    uint32_t i;

    if ((flags & WT_FFA_MEM_FLAG_ALIGN_VALID) == 0u) {
        return (hint == 0u) ? 0 : WT_FFA_INVALID_PARAMETERS;
    }
    boundary = (hint == 0u) ? WT_FFA_MEM_PAGE_SIZE
                            : ((uint64_t)hint * 2u * WT_FFA_MEM_PAGE_SIZE);
    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        if ((e->regions[i].base % boundary) != 0u) {
            return WT_FFA_DENIED;
        }
    }
    return 0;
}

static void zero_regions(const wt_ffa_mem_handle_entry_t* e)
{
    uint32_t i;

    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        (void)memset((void*)(uintptr_t)e->regions[i].base, 0,
                     (size_t)e->regions[i].page_count * WT_FFA_MEM_PAGE_SIZE);
    }
}

int wt_spm_mem_retrieve(const uint8_t* req, size_t len, uint16_t receiver,
                        uint8_t* resp, size_t resp_cap, size_t* out_resp_len)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_borrower_t* borrower;
    wt_spm_mem_binding_t* b;
    wt_ffa_mem_retrieve_req_t rq;
    wt_ffa_mem_constituent_t cons[WT_FFA_MEM_MAX_REGIONS];
    wt_ffa_mem_build_t in;
    uint32_t attributes;
    uint32_t type;
    uint32_t i;
    uint32_t done = 0u;
    uint8_t perms = 0u;
    uint8_t asked = 0u;
    int named = 0;
    int was_mapped = 0;
    int zero = 0;
    int ret;

    if ((resp == NULL) || (out_resp_len == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_retrieve_req_parse_ex(req, len, &rq);
    if (ret != 0) {
        return ret;
    }
    for (i = 0u; i < rq.receiver_count; i++) {
        if (rq.receivers[i] == receiver) {
            asked = rq.permissions[i];
            named = 1;
        }
    }
    if (named == 0) {
        return WT_FFA_DENIED;
    }
    ret = wt_ffa_mem_handle_lookup(&g_reg, rq.handle, &e);
    if (ret != 0) {
        return ret;
    }
    if (e->owner != rq.sender) {
        return WT_FFA_DENIED;
    }
    borrower = wt_ffa_mem_handle_borrower(&g_reg, rq.handle, receiver);
    b = bind_by_id(receiver);
    if ((borrower == NULL) || (b == NULL) || (borrower->retrieved != 0u)) {
        return WT_FFA_DENIED;
    }
    type = rq.flags & WT_FFA_MEM_FLAG_TYPE_MASK;
    if ((rq.tag != e->tag) ||
        ((rq.flags & ~(WT_FFA_MEM_FLAG_SEND_MASK | WT_FFA_MEM_FLAG_TYPE_MASK |
                       WT_FFA_MEM_FLAG_ZERO_AFTER)) != 0u) ||
        ((type != 0u) && (type != type_flag(e->state))) ||
        ((rq.attributes & WT_FFA_MEM_ATTR_RSVD_MASK) != 0u) ||
        ((rq.attributes & WT_FFA_MEM_ATTR_TYPE_MASK) ==
         WT_FFA_MEM_ATTR_TYPE_DEVICE)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = effective_permissions(borrower->permissions, asked, &perms);
    if (ret != 0) {
        return ret;
    }
    /* The zero-memory flags are MBZ for shared memory (Table 5.22); a
     * read-only borrower cannot have lent memory wiped either. */
    if ((rq.flags & (WT_FFA_MEM_FLAG_ZERO | WT_FFA_MEM_FLAG_ZERO_AFTER)) != 0u) {
        if (e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if ((perms & WT_FFA_MEM_PERM_DATA_MASK) == WT_FFA_MEM_PERM_DATA_RO) {
            return WT_FFA_DENIED;
        }
        /* Bit 0 from a borrower means: only if the owner asked for the wipe. */
        if (((rq.flags & WT_FFA_MEM_FLAG_ZERO) != 0u) &&
            ((e->owner_cookie & WT_FFA_MEM_FLAG_ZERO) == 0u)) {
            return WT_FFA_DENIED;
        }
    }
    ret = alignment_hint_ok(e, rq.flags);
    if (ret != 0) {
        return ret;
    }
    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        cons[i].address = e->regions[i].base;
        cons[i].page_count = e->regions[i].page_count;
    }
    (void)memset(&in, 0, sizeof(in));
    in.constituents = cons;
    in.constituent_count = (uint32_t)e->region_count;
    in.tag = e->tag;
    in.handle = rq.handle;
    zero = ((e->owner_cookie & WT_FFA_MEM_FLAG_ZERO) != 0u) ? 1 : 0;
    in.flags = type_flag(e->state) | ((zero != 0) ? WT_FFA_MEM_FLAG_ZERO : 0u);
    in.op = WT_FFA_MEM_OP_SHARE;
    in.sender = e->owner;
    in.receiver = receiver;
    in.attributes = (uint16_t)(WT_FFA_MEM_ATTR_TYPE_NORMAL |
                               (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT) |
                               WT_FFA_MEM_ATTR_SHARE_INNER |
                               ((e->regions[0].ns != 0u) ? WT_FFA_MEM_ATTR_NS : 0u));
    in.permissions = perms;
    in.access_desc_size = (uint8_t)rq.access_desc_size;
    ret = wt_ffa_mem_txn_build(resp, resp_cap, &in, out_resp_len);
    if (ret != 0) {
        return ret;
    }
    /* Zero while the pages are still the SPMC's alone to write. */
    if (zero != 0) {
        zero_regions(e);
    }
    attributes = WT_MEM_ATTR_READ;
    if ((perms & WT_FFA_MEM_PERM_DATA_MASK) == WT_FFA_MEM_PERM_DATA_RW) {
        attributes |= WT_MEM_ATTR_WRITE;
    }
    if (e->regions[0].ns != 0u) {
        attributes |= WT_TABLES_ATTR_NS;
    }
    for (i = 0u; (ret == 0) && (i < (uint32_t)e->region_count); i++) {
        if (wt_domain_grant(b->dom->regions, b->dom->region_count,
                            (uintptr_t)e->regions[i].base,
                            e->regions[i].page_count, attributes,
                            &was_mapped) != WT_TABLES_OK) {
            ret = WT_FFA_NO_MEMORY;
        }
        else {
            done++;
        }
    }
    if (ret != 0) {
        for (i = 0u; i < done; i++) {
            (void)wt_domain_revoke(b->dom->regions, b->dom->region_count,
                                   (uintptr_t)e->regions[i].base,
                                   e->regions[i].page_count, was_mapped);
        }
        return ret;
    }
    borrower->mapping = (uint8_t)((was_mapped != 0) ? WT_SPM_MEM_MAP_WAS_MAPPED : 0u);
    ret = wt_ffa_mem_handle_retrieve(&g_reg, rq.handle, receiver);
    /* A donate hands ownership over for good: the region is now the receiver's
     * own writable memory (the owner's access was dropped at donate time), so
     * the transaction is consumed and there is nothing to reclaim. */
    if ((ret == 0) && (e->state == (uint8_t)WT_FFA_MEM_STATE_DONATED)) {
        (void)wt_ffa_mem_handle_free(&g_reg, rq.handle);
    }
    return ret;
}

int wt_spm_mem_relinquish(const uint8_t* rel, size_t len, uint16_t endpoint)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_borrower_t* borrower;
    wt_spm_mem_binding_t* b;
    uint64_t handle = 0u;
    uint32_t flags = 0u;
    uint32_t cookie;
    uint32_t i;
    uint16_t ep = 0u;
    int ret;

    ret = wt_ffa_mem_relinquish_parse_ex(rel, len, &handle, &ep, &flags);
    if (ret != 0) {
        return ret;
    }
    if (ep != endpoint) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_handle_lookup(&g_reg, handle, &e);
    if (ret != 0) {
        return ret;
    }
    borrower = wt_ffa_mem_handle_borrower(&g_reg, handle, endpoint);
    b = bind_by_id(endpoint);
    if ((borrower == NULL) || (b == NULL) || (borrower->retrieved == 0u)) {
        return WT_FFA_DENIED;
    }
    /* The zero-memory flag is MBZ for shared memory (Table 11.26); of lent
     * memory only a sole writer may have it wiped. */
    if ((flags & WT_FFA_MEM_RELINQ_FLAG_ZERO) != 0u) {
        if (e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if ((borrower->permissions & WT_FFA_MEM_PERM_DATA_MASK) ==
            WT_FFA_MEM_PERM_DATA_RO) {
            return WT_FFA_DENIED;
        }
    }
    ret = wt_ffa_mem_handle_relinquish(&g_reg, handle, endpoint);
    if (ret != 0) {
        return ret;
    }
    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        (void)wt_domain_revoke(b->dom->regions, b->dom->region_count,
                               (uintptr_t)e->regions[i].base,
                               e->regions[i].page_count,
                               ((borrower->mapping &
                                 WT_SPM_MEM_MAP_WAS_MAPPED) != 0u) ? 1 : 0);
    }
    /* The flag here, not the one at retrieve, decides; with several borrowers
     * the wipe waits until the last of them has been unmapped (Table 11.26). */
    cookie = e->owner_cookie;
    if ((flags & WT_FFA_MEM_RELINQ_FLAG_ZERO) != 0u) {
        cookie |= WT_SPM_MEM_COOKIE_ZERO_PENDING;
    }
    if (((cookie & WT_SPM_MEM_COOKIE_ZERO_PENDING) != 0u) && (e->retrieved == 0u)) {
        zero_regions(e);
        cookie &= ~WT_SPM_MEM_COOKIE_ZERO_PENDING;
    }
    wt_ffa_mem_handle_set_meta(&g_reg, handle, e->tag, cookie);
    return 0;
}

int wt_spm_mem_reclaim(uint64_t handle, uint16_t owner, uint32_t flags)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_handle_entry_t snapshot;
    int ret;

    if ((flags & ~WT_FFA_MEM_RELINQ_FLAG_MASK) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_handle_lookup(&g_reg, handle, &e);
    if (ret != 0) {
        return ret;
    }
    snapshot = *e;
    ret = wt_ffa_mem_handle_reclaim(&g_reg, handle, owner);
    if (ret != 0) {
        return ret;
    }
    if ((flags & WT_FFA_MEM_RELINQ_FLAG_ZERO) != 0u) {
        zero_regions(&snapshot);
    }
    owner_access(&snapshot, 1);
    return 0;
}
