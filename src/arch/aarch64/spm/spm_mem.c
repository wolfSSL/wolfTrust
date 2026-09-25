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
/* Borrower mapping cookie: region i's entry existed before the grant. */
#define WT_SPM_MEM_MAP_REGION(i)  (1u << (i))
/* Borrower mapping cookie: the retrieve granted read-only data access. */
#define WT_SPM_MEM_MAP_RO         0x10u
/* Borrower mapping cookie: the retrieve asked for a wipe once the borrower
 * lets go, which a relinquish may override but a fault cannot. */
#define WT_SPM_MEM_MAP_ZERO_AFTER 0x20u
/* Owner cookie, above the send flags it keeps: a borrower asked for the memory
 * to be zeroed, which happens once no borrower maps it any more. */
#define WT_SPM_MEM_COOKIE_ZERO_PENDING 0x80000000u
/* Owner cookie: the owner itself only reads some of the memory, so nothing may
 * wipe it or hand out write access to it. */
#define WT_SPM_MEM_COOKIE_OWNER_RO     0x40000000u
/* Owner cookie: the owner faulted while a borrower held the memory; the last
 * borrower to let go ends the transaction. */
#define WT_SPM_MEM_COOKIE_OWNER_GONE   0x20000000u
/* Owner cookie: a share named the owner itself read-only, so it keeps only
 * read access until it reclaims. */
#define WT_SPM_MEM_COOKIE_SELF_RO      0x10000000u
/* No endpoint memory access descriptor index. */
#define WT_SPM_MEM_NO_INDEX            0xFFFFFFFFu

#if WT_FFA_MEM_MAX_REGIONS > 4u
#error "the borrower mapping cookie holds one bit per region, four at most"
#endif

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

/* The FF-A version endpoint id negotiated, which the descriptors it sends and
 * receives follow (DEN0077A 18.5.3); the SPMC's own is 1.2. */
static uint32_t caller_version(uint16_t id)
{
    const wt_spm_mem_binding_t* b;

    if (!id_is_secure(id)) {
        return wt_spm_ns_ffa_version();
    }
    b = bind_by_id(id);
    return (b != NULL) ? wt_spm_sp_ffa_version(b->co) : WT_FFA_VERSION_1_2;
}

static int ranges_overlap(uint64_t base, uint64_t size, uintptr_t other,
                          size_t other_size)
{
    return (base < ((uint64_t)other + (uint64_t)other_size)) &&
           ((uint64_t)other < (base + size));
}

/* The image every partition executes. */
static int platform_shared(uint64_t base, uint64_t size)
{
    wt_memory_region_t shared[4];
    size_t n = wt_platform_sp_shared_regions(shared, 4u);
    size_t i;

    for (i = 0u; i < n; i++) {
        if (ranges_overlap(base, size, shared[i].base, shared[i].size)) {
            return 1;
        }
    }
    return 0;
}

/* The image every partition executes and memory a manifest marks shared are
 * no one partition's own, even where its table reaches them at EL0. */
static int common_memory(const wt_secure_domain_t* dom, uint64_t base,
                         uint64_t size)
{
    size_t i;

    if (platform_shared(base, size) != 0) {
        return 1;
    }
    for (i = 0u; i < dom->region_count; i++) {
        if (((dom->regions[i].attributes & WT_MEMORY_ATTR_SHARED) != 0u) &&
            ranges_overlap(base, size, dom->regions[i].base,
                           dom->regions[i].size)) {
            return 1;
        }
    }
    return 0;
}

/* A partition whose table holds a page of the Normal world's window as its
 * own, even one it made no-access or lends on, was donated it or borrows it,
 * so the page is no longer the Normal world's (1.3.1 rules 5 and 6). */
static int ns_page_held(uint64_t at)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
        if ((g_bind[i].live != 0u) &&
            (wt_domain_page_claimed(g_bind[i].dom->regions,
                                    g_bind[i].dom->region_count,
                                    (uintptr_t)at) != 0)) {
            return 1;
        }
    }
    return 0;
}

int wt_spm_mem_ns_owns(uint64_t base, uint64_t size)
{
    uint64_t at;

    if ((size == 0u) || (base < g_ns_base) || (base >= g_ns_limit) ||
        (size > (g_ns_limit - base))) {
        return 0;
    }
    for (at = base & ~(uint64_t)(WT_FFA_MEM_PAGE_SIZE - 1u); at < (base + size);
         at += WT_FFA_MEM_PAGE_SIZE) {
        if (ns_page_held(at) != 0) {
            return 0;
        }
    }
    return 1;
}

/* The live transaction one of whose regions holds the page at, or NULL. */
static const wt_ffa_mem_handle_entry_t* covering_entry(uint64_t at)
{
    const wt_ffa_mem_handle_entry_t* e;
    unsigned int i;
    uint32_t r;

    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        e = &g_reg.entries[i];
        if (e->state == (uint8_t)WT_FFA_MEM_STATE_FREE) {
            continue;
        }
        for (r = 0u; r < (uint32_t)e->region_count; r++) {
            if ((at >= e->regions[r].base) &&
                ((at - e->regions[r].base) <
                 ((uint64_t)e->regions[r].page_count * WT_FFA_MEM_PAGE_SIZE))) {
                return e;
            }
        }
    }
    return NULL;
}

/* A lender keeps no access and a donor no ownership (Table 1.3 Owner-LA and
 * !Owner-NA); a share leaves the owner its access (Owner-SA), read-only where
 * the share named it so (1.11.3.1). */
int wt_spm_mem_ns_access(uint64_t base, uint64_t size, int write)
{
    const wt_ffa_mem_handle_entry_t* e;
    uint64_t at;
    int ok;

    if (size == 0u) {
        return 1;
    }
    ok = ((base >= g_ns_base) && (base < g_ns_limit) &&
          (size <= (g_ns_limit - base))) ? 1 : 0;
    for (at = base & ~(uint64_t)(WT_FFA_MEM_PAGE_SIZE - 1u);
         (ok != 0) && (at < (base + size)); at += WT_FFA_MEM_PAGE_SIZE) {
        e = covering_entry(at);
        if (e == NULL) {
            ok = (ns_page_held(at) == 0) ? 1 : 0;
        }
        else {
            ok = ((e->owner == WT_FFA_ID_NS_PRIMARY) &&
                  (e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED) &&
                  ((write == 0) ||
                   ((e->owner_cookie & WT_SPM_MEM_COOKIE_SELF_RO) == 0u)))
                     ? 1 : 0;
        }
    }
    return ok;
}

/* Only memory the sender owns outright may be sent (10.10): Non-secure memory
 * inside the window the SPMC maps that no partition holds, or Normal pages a
 * partition reaches at EL0, all in one security state (*ns). A Device page is
 * DENIED: a borrower's Normal mapping of it would be more permissive than the
 * sender's (1.10.4.2 item 1). The result is the least access it has over the
 * range (WT_DOMAIN_ACCESS_*). The SPMC's own sends are its boot self-test. */
static int sender_owns(uint16_t sender, const wt_ffa_mem_region_t* r,
                       uint8_t* ns)
{
    const wt_spm_mem_binding_t* b;
    uint64_t size = (uint64_t)r->page_count * WT_FFA_MEM_PAGE_SIZE;
    uint64_t at;
    uint8_t page_ns;
    int access = WT_DOMAIN_ACCESS_RW;
    int page;

    *ns = 0u;
    if (sender == WT_FFA_ID_SPMC) {
        return WT_DOMAIN_ACCESS_RW;
    }
    /* With no Hypervisor the Normal-world kernel is the relayer for its own
     * mappings and takes its access away itself (DEN0140 1.4.1). */
    if (!id_is_secure(sender)) {
        *ns = 1u;
        return (wt_spm_mem_ns_owns(r->base, size) != 0) ? WT_DOMAIN_ACCESS_RW
                                                        : WT_DOMAIN_ACCESS_NONE;
    }
    b = bind_by_id(sender);
    if ((b == NULL) || (common_memory(b->dom, r->base, size) != 0)) {
        return WT_DOMAIN_ACCESS_NONE;
    }
    for (at = r->base;
         (at < (r->base + size)) && (access != WT_DOMAIN_ACCESS_NONE);
         at += WT_FFA_MEM_PAGE_SIZE) {
        page = wt_domain_page_access(b->dom->regions, b->dom->region_count,
                                     (uintptr_t)at);
        page_ns = (uint8_t)wt_domain_page_ns(b->dom->regions,
                                             b->dom->region_count,
                                             (uintptr_t)at);
        if (at == r->base) {
            *ns = page_ns;
        }
        else if (page_ns != *ns) {
            page = WT_DOMAIN_ACCESS_NONE;
        }
        if (page < access) {
            access = page;
        }
    }
    return access;
}

/* Any partition the SPMC runs is an endpoint it manages (1.11.3.3); one not
 * bound never retrieves, and its owner reclaims. One out of service never
 * retrieves either, so a transaction naming it is refused (Table 2.5). */
static int receiver_state(uint16_t id)
{
    const wt_spm_mem_binding_t* b = bind_by_id(id);
    const struct wt_co* co = (b != NULL) ? b->co : wt_spm_sp_by_ffa_id(id);

    if ((b == NULL) && (co == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    return (int)wt_spm_sp_unavailable(co);
}

#define WT_SPM_MEM_OWNER_HOLD     0
#define WT_SPM_MEM_OWNER_RELEASE  1
#define WT_SPM_MEM_OWNER_WITHDRAW 2

/* A lend or donate takes the owner's own access away until it reclaims
 * (10.10.1), and a share it named itself read-only in lowers it to reading
 * (2.3.1.2 item 10); a reclaim puts back each page exactly as it was (1.10.2
 * item 4), withdrawing even that reading while it wipes. Only a partition's
 * access is the SPMC's to take. */
static void owner_access(const wt_ffa_mem_handle_entry_t* e, int how)
{
    const wt_spm_mem_binding_t* b = bind_by_id(e->owner);
    int keep_read = (e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED) ? 1 : 0;
    uint32_t i;

    if ((b == NULL) || ((keep_read != 0) &&
                        ((e->owner_cookie & WT_SPM_MEM_COOKIE_SELF_RO) == 0u))) {
        return;
    }
    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        if (how == WT_SPM_MEM_OWNER_RELEASE) {
            (void)wt_domain_owner_release(b->dom->regions,
                                          b->dom->region_count,
                                          (uintptr_t)e->regions[i].base,
                                          e->regions[i].page_count);
        }
        else if (how == WT_SPM_MEM_OWNER_WITHDRAW) {
            (void)wt_domain_owner_withdraw(b->dom->regions,
                                           b->dom->region_count,
                                           (uintptr_t)e->regions[i].base,
                                           e->regions[i].page_count);
        }
        else {
            (void)wt_domain_owner_hold(b->dom->regions, b->dom->region_count,
                                       (uintptr_t)e->regions[i].base,
                                       e->regions[i].page_count, keep_read);
        }
    }
}

/* The zeros go out to memory, not just the SPMC's cache (1.11.4.1). */
static void zero_regions(const wt_ffa_mem_handle_entry_t* e)
{
    uint64_t size;
    uint32_t i;

    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        size = (uint64_t)e->regions[i].page_count * WT_FFA_MEM_PAGE_SIZE;
        (void)memset((void*)(uintptr_t)e->regions[i].base, 0, (size_t)size);
        wt_mmu_dcache_clean_inval(e->regions[i].base, size);
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

static int mem_share(const uint8_t* desc, size_t len, wt_ffa_mem_op_t op,
                     uint16_t sender, uint64_t reserved, uint64_t* out_handle)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_borrower_t* named;
    wt_ffa_mem_txn_t txn;
    wt_ffa_mem_region_t regs[WT_FFA_MEM_MAX_REGIONS];
    uint32_t n = 0u;
    uint32_t i;
    uint32_t self = WT_SPM_MEM_NO_INDEX;
    uint32_t first = WT_SPM_MEM_NO_INDEX;
    int owner_ro = 0;
    int self_ro = 0;
    uint16_t receiver = 0u;
    uint16_t attributes = 0u;
    uint8_t perms = 0u;
    int access = WT_DOMAIN_ACCESS_NONE;
    int ret;

    if (out_handle == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_send_validate_at(desc, len, op, sender,
                                      caller_version(sender), &txn);
    if ((ret == 0) && (txn.receiver_count > WT_FFA_MEM_MAX_BORROWERS)) {
        ret = WT_FFA_NO_MEMORY;
    }
    for (i = 0u; (ret == 0) && (i < txn.receiver_count); i++) {
        ret = wt_ffa_mem_receiver(desc, len, &txn, i, &receiver, &perms);
        /* A share may name the lender itself, once, with the data access it
         * keeps while the memory is shared (1.11.3.1). */
        if ((ret == 0) && (receiver == sender) &&
            (op == WT_FFA_MEM_OP_SHARE) && (self == WT_SPM_MEM_NO_INDEX)) {
            self = i;
            self_ro = ((perms & WT_FFA_MEM_PERM_DATA_MASK) ==
                       WT_FFA_MEM_PERM_DATA_RO) ? 1 : 0;
            ret = send_permissions_ok(op, perms);
            continue;
        }
        if ((ret == 0) && (first == WT_SPM_MEM_NO_INDEX)) {
            first = i;
        }
        /* No SP-to-NS-Endpoint send is a DEN0140 Table 1.7 combination; rule
         * 4 of 2.1.1.2, 2.2.1.2, and 2.3.1.2 makes one of Secure memory DENIED. */
        if ((ret == 0) && id_is_secure(sender) && !id_is_secure(receiver)) {
            ret = WT_FFA_DENIED;
        }
        /* A borrower is a partition the SPMC can map into, never the sender. */
        if ((ret == 0) && (receiver == sender)) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
        if (ret == 0) {
            ret = receiver_state(receiver);
        }
        if (ret == 0) {
            ret = send_permissions_ok(op, perms);
        }
    }
    if ((ret == 0) && (first == WT_SPM_MEM_NO_INDEX)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    /* Memory that becomes one receiver's alone (a donate, a lend to a single
     * borrower) has its type chosen by that receiver; a share or a lend to
     * several names it (Table 5.18 usage). */
    if ((ret == 0) &&
        ((op == WT_FFA_MEM_OP_DONATE) ||
         ((op == WT_FFA_MEM_OP_LEND) && (txn.receiver_count == 1u))) &&
        ((txn.attributes & WT_FFA_MEM_ATTR_TYPE_MASK) != 0u)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        ret = wt_ffa_mem_regions_from_txn(desc, len, &txn, first, regs,
                                          WT_FFA_MEM_MAX_REGIONS, &n);
    }
    for (i = 0u; (ret == 0) && (i < n); i++) {
        access = sender_owns(sender, &regs[i], &regs[i].ns);
        if (access == WT_DOMAIN_ACCESS_RO) {
            owner_ro = 1;
        }
        /* A mapped RX/TX pair is the SPMC's to write and read until it is
         * unmapped (DEN0077A 7.2.2.2), so it is never the sender's to hand on;
         * and one memory region has one security state (Table 1.19). */
        if ((access == WT_DOMAIN_ACCESS_NONE) ||
            (regs[i].ns != regs[0].ns) ||
            (wt_ffa_mem_registry_overlaps(&g_reg, regs[i].base,
                                          regs[i].page_count) != 0) ||
            (wt_spm_mailbox_overlaps(regs[i].base,
                                     (uint64_t)regs[i].page_count *
                                         WT_FFA_MEM_PAGE_SIZE) != 0)) {
            ret = WT_FFA_DENIED;
        }
    }
    /* A donate makes the receiver the owner with the owner's own data access,
     * which the one permission a retrieve maps every region with must not
     * exceed anywhere (1.10.2 item 2). */
    for (i = 0u; (ret == 0) && (op == WT_FFA_MEM_OP_DONATE) && (i < n); i++) {
        regs[i].permissions = (uint8_t)(((owner_ro != 0)
                                             ? WT_FFA_MEM_PERM_DATA_RO
                                             : WT_FFA_MEM_PERM_DATA_RW) |
                                        WT_FFA_MEM_PERM_INSTR_NX);
    }
    if (ret == 0) {
        ret = wt_ffa_mem_send_attributes(txn.attributes, &attributes);
    }
    /* An owner that only reads the memory cannot have it wiped, nor hand out
     * write access it does not hold, to a borrower or to itself (Table 5.20,
     * 10.10.2, 1.10.2 item 1). */
    if ((ret == 0) && (owner_ro != 0)) {
        if ((txn.flags & WT_FFA_MEM_FLAG_ZERO) != 0u) {
            ret = WT_FFA_DENIED;
        }
        for (i = 0u; (ret == 0) && (i < txn.receiver_count); i++) {
            ret = wt_ffa_mem_receiver(desc, len, &txn, i, &receiver, &perms);
            if ((ret == 0) && ((perms & WT_FFA_MEM_PERM_DATA_MASK) ==
                               WT_FFA_MEM_PERM_DATA_RW)) {
                ret = WT_FFA_DENIED;
            }
        }
    }
    if (ret == 0) {
        ret = wt_ffa_mem_receiver(desc, len, &txn, first, &receiver, &perms);
    }
    if ((ret == 0) && (reserved != 0u)) {
        ret = wt_ffa_mem_share_register_as(&g_reg, op, sender, receiver, regs,
                                           n, reserved);
        if (ret == 0) {
            *out_handle = reserved;
        }
    }
    else if (ret == 0) {
        ret = wt_ffa_mem_share_register(&g_reg, op, sender, receiver, regs, n,
                                        out_handle);
    }
    for (i = first + 1u; (ret == 0) && (i < txn.receiver_count); i++) {
        if (i == self) {
            continue;
        }
        ret = wt_ffa_mem_receiver(desc, len, &txn, i, &receiver, &perms);
        if (ret == 0) {
            ret = wt_ffa_mem_handle_add_borrower(&g_reg, *out_handle, receiver,
                                                 perms);
        }
        if (ret != 0) {
            (void)wt_ffa_mem_handle_reclaim(&g_reg, *out_handle, sender);
        }
    }
    for (i = 0u; (ret == 0) && (i < txn.receiver_count); i++) {
        ret = wt_ffa_mem_receiver(desc, len, &txn, i, &receiver, &perms);
        named = (ret == 0) ? wt_ffa_mem_handle_borrower(&g_reg, *out_handle,
                                                         receiver) : NULL;
        if (named != NULL) {
            ret = wt_ffa_mem_receiver_impdef(desc, len, &txn, i, named->impdef);
        }
    }
    if (ret == 0) {
        /* The cookie keeps the owner's flags: it may ask for the memory to be
         * zeroed before a borrower sees it. */
        wt_ffa_mem_handle_set_meta(&g_reg, *out_handle, txn.tag,
                                   txn.flags |
                                       ((owner_ro != 0)
                                            ? WT_SPM_MEM_COOKIE_OWNER_RO
                                            : 0u) |
                                       ((self_ro != 0)
                                            ? WT_SPM_MEM_COOKIE_SELF_RO
                                            : 0u));
        wt_ffa_mem_handle_set_attributes(&g_reg, *out_handle, attributes);
        if (wt_ffa_mem_handle_lookup(&g_reg, *out_handle, &e) == 0) {
            owner_access(e, WT_SPM_MEM_OWNER_HOLD);
            /* Once, with the owner's access gone and before any borrower can
             * map the memory (Table 1.21 bit[0]). */
            if ((txn.flags & WT_FFA_MEM_FLAG_ZERO) != 0u) {
                zero_regions(e);
            }
        }
    }
    return ret;
}

/* Bits[31:3] are SBZ and ignored (Table 2.40). No access (b'00) maps the page
 * away from EL0 whatever bit[2] says: S-EL1 keeps writing it, so
 * SCTLR_EL1.WXN makes it execute-never (2.8.0.0.1). */
static int perm_to_attributes(uint32_t perm, uint32_t* attributes)
{
    uint32_t data = perm & WT_FFA_PERM_DATA_MASK;

    if (data == WT_FFA_PERM_DATA_NONE) {
        *attributes = 0u;
        return 0;
    }
    if ((data == WT_FFA_PERM_DATA_RW) && ((perm & WT_FFA_PERM_XN) != 0u)) {
        *attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
        return 0;
    }
    if (data == WT_FFA_PERM_DATA_RO) {
        *attributes = WT_MEM_ATTR_READ;
        if ((perm & WT_FFA_PERM_XN) == 0u) {
            *attributes |= WT_MEM_ATTR_EXEC;
        }
        return 0;
    }
    return WT_FFA_INVALID_PARAMETERS;
}

/* Non-zero when a page of [base, base + size) lies in a region dom's manifest
 * makes writable. */
static int manifest_writable(const wt_secure_domain_t* dom, uint64_t base,
                             uint64_t size)
{
    size_t i;

    for (i = 0u; i < dom->region_count; i++) {
        if (((dom->regions[i].attributes & WT_MEM_ATTR_WRITE) != 0u) &&
            ranges_overlap(base, size, dom->regions[i].base,
                           dom->regions[i].size)) {
            return 1;
        }
    }
    return 0;
}

static int manifest_covers(const wt_secure_domain_t* dom, uint64_t at)
{
    size_t i;

    for (i = 0u; i < dom->region_count; i++) {
        if ((at >= (uint64_t)dom->regions[i].base) &&
            ((at - (uint64_t)dom->regions[i].base) <
             (uint64_t)dom->regions[i].size)) {
            return 1;
        }
    }
    return 0;
}

static const wt_spm_mem_binding_t* bind_by_dom(const wt_secure_domain_t* dom)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
        if ((g_bind[i].live != 0u) && (g_bind[i].dom == dom)) {
            return &g_bind[i];
        }
    }
    return NULL;
}

/* The page at is one the partition may access as its own memory: its
 * manifest names it, or a donate made it the receiver's (Owner-EA, DEN0140
 * 2.4.1.2 item 12), which is a page its table still gives it that no live
 * transaction covers and no manifest shares. */
static int partition_reaches(const wt_secure_domain_t* dom, uint64_t at)
{
    if (manifest_covers(dom, at) != 0) {
        return 1;
    }
    return ((bind_by_dom(dom) != NULL) &&
            (wt_domain_page_owned(dom->regions, dom->region_count,
                                  (uintptr_t)at) != 0) &&
            (common_memory(dom, at, WT_FFA_MEM_PAGE_SIZE) == 0) &&
            (wt_ffa_mem_registry_overlaps(&g_reg, at, 1u) == 0)) ? 1 : 0;
}

/* Of those, the pages that are the partition's alone: never the image every
 * partition runs or memory its manifest shares with another. */
static int partition_owns(const wt_secure_domain_t* dom, uint64_t at)
{
    return ((common_memory(dom, at, WT_FFA_MEM_PAGE_SIZE) == 0) &&
            (partition_reaches(dom, at) != 0)) ? 1 : 0;
}

int wt_spm_mem_rxtx_ok(const wt_secure_domain_t* dom, uint64_t va)
{
    if ((dom == NULL) || ((va % WT_FFA_MEM_PAGE_SIZE) != 0u) ||
        (va >= WT_TABLES_VA_LIMIT) || (partition_owns(dom, va) == 0)) {
        return 0;
    }
    return ((wt_domain_page_access(dom->regions, dom->region_count,
                                   (uintptr_t)va) == WT_DOMAIN_ACCESS_RW) &&
            (wt_domain_page_ns(dom->regions, dom->region_count,
                               (uintptr_t)va) == 0) &&
            (wt_ffa_mem_registry_overlaps(&g_reg, va, 1u) == 0)) ? 1 : 0;
}

int wt_spm_mem_perm_get(const wt_secure_domain_t* dom, uint64_t va,
                        uint32_t* perm)
{
    uint32_t attributes = 0u;

    if ((dom == NULL) || (perm == NULL) || (va >= WT_TABLES_VA_LIMIT) ||
        ((va % WT_FFA_MEM_PAGE_SIZE) != 0u) ||
        (partition_reaches(dom, va) == 0) ||
        (wt_domain_get_permissions(dom->regions, dom->region_count,
                                   (uintptr_t)va, &attributes) !=
         WT_TABLES_OK)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    *perm = WT_FFA_PERM_DATA_NONE;
    if ((attributes & WT_MEM_ATTR_WRITE) != 0u) {
        *perm = WT_FFA_PERM_DATA_RW;
    }
    else if ((attributes & WT_MEM_ATTR_READ) != 0u) {
        *perm = WT_FFA_PERM_DATA_RO;
    }
    if ((attributes & WT_MEM_ATTR_EXEC) == 0u) {
        *perm |= WT_FFA_PERM_XN;
    }
    return 0;
}

int wt_spm_mem_perm_set(const wt_secure_domain_t* dom,
                        const wt_ffa_mailbox_t* mb, uint64_t va,
                        uint32_t pages, uint32_t perm)
{
    uint64_t size = (uint64_t)pages * WT_FFA_MEM_PAGE_SIZE;
    uint64_t at;
    uint32_t attributes = 0u;
    int ret;

    if (dom == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = perm_to_attributes(perm, &attributes);
    if ((ret == 0) &&
        ((pages == 0u) || (va >= WT_TABLES_VA_LIMIT) ||
         ((va % WT_FFA_MEM_PAGE_SIZE) != 0u) ||
         (pages > ((WT_TABLES_VA_LIMIT - va) / WT_TABLES_PAGE_SIZE)))) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    for (at = va; (ret == 0) && (at < (va + size));
         at += WT_FFA_MEM_PAGE_SIZE) {
        if (partition_owns(dom, at) == 0) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
    }
    /* Table 2.41 keeps DENIED for a caller out of its initialization, so a
     * region it may not re-permission is INVALID_PARAMETERS; an owner cannot
     * change its access while a borrower may hold the memory (1.3.1 rule 7). */
    if ((ret == 0) && (wt_ffa_mem_registry_overlaps(&g_reg, va, pages) != 0)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if ((ret == 0) && (platform_shared(va, size) != 0)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    /* Pages the SPMC writes at S-EL1 through the partition's own table, where
     * an EL0 read-only page is read-only too, keep their data access: the
     * mapped RX/TX pair, and the writable manifest memory of a partition the
     * relayer does not bind, where the FF-M gate writes the buffers it names. */
    if ((ret == 0) && (wt_ffa_mailbox_overlaps(mb, va, size) != 0)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if ((ret == 0) && ((attributes & WT_MEM_ATTR_READ) != 0u) &&
        ((attributes & WT_MEM_ATTR_WRITE) == 0u) &&
        (bind_by_dom(dom) == NULL) &&
        (manifest_writable(dom, va, size) != 0)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if ((ret == 0) &&
        (wt_domain_set_permissions(dom->regions, dom->region_count,
                                   (uintptr_t)va, (size_t)pages, attributes) !=
         WT_TABLES_OK)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    return ret;
}

int wt_spm_mem_in_transaction(uint64_t base, uint64_t size)
{
    return wt_ffa_mem_registry_overlaps(&g_reg, base,
                                        (uint32_t)((size + WT_FFA_MEM_PAGE_SIZE -
                                                    1u) / WT_FFA_MEM_PAGE_SIZE));
}

int wt_spm_mem_share(const uint8_t* desc, size_t len, wt_ffa_mem_op_t op,
                     uint16_t sender, uint64_t* out_handle)
{
    return mem_share(desc, len, op, sender, 0u, out_handle);
}

/* Transactions whose descriptor is still arriving in fragments, at most one
 * per sender (DEN0140 4.1.2). The first slot is the Normal world's alone, so
 * partitions that hold theirs open can never starve it. */
#define WT_SPM_MEM_FRAG_SLOTS    3u
#define WT_SPM_MEM_FRAG_NS_SLOTS 1u
static wt_ffa_mem_frag_t g_frag[WT_SPM_MEM_FRAG_SLOTS];

static wt_ffa_mem_frag_t* frag_slot(uint64_t handle, uint16_t sender)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_MEM_FRAG_SLOTS; i++) {
        if ((g_frag[i].active != 0u) && (g_frag[i].handle == handle) &&
            (g_frag[i].sender == sender)) {
            return &g_frag[i];
        }
    }
    return NULL;
}

int wt_spm_mem_frag_begin(uint8_t op, uint16_t sender, const uint8_t* frag,
                          uint32_t frag_len, uint32_t total, uint64_t* handle)
{
    wt_ffa_mem_frag_t* slot = NULL;
    uint64_t named = 0u;
    uint64_t size = 0u;
    unsigned int first = id_is_secure(sender) ? WT_SPM_MEM_FRAG_NS_SLOTS : 0u;
    unsigned int last = id_is_secure(sender) ? WT_SPM_MEM_FRAG_SLOTS
                                             : WT_SPM_MEM_FRAG_NS_SLOTS;
    unsigned int i;
    int ret = 0;

    if ((frag == NULL) || (handle == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* A total the descriptor's own headers contradict is an invalid length,
     * not the start of a transfer. */
    if ((wt_ffa_mem_frag_expected_at(frag, frag_len,
                                     (op == WT_SPM_MEM_FRAG_OP_RETRIEVE) ? 1 : 0,
                                     caller_version(sender), &size) != 0) &&
        (size != (uint64_t)total)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* A retrieve request fragment names its region's handle up front. */
    if (op == WT_SPM_MEM_FRAG_OP_RETRIEVE) {
        if (frag_len < (WT_FFA_MEM_TXN_OFF_HANDLE + 8u)) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        for (i = 0u; i < 8u; i++) {
            named |= (uint64_t)frag[WT_FFA_MEM_TXN_OFF_HANDLE + i] << (8u * i);
        }
    }
    /* The TX buffer stays busy with an unfinished transfer, which its sender
     * may not abort (DEN0140 4.1.2 rules 6 and 9); one the relayer already
     * aborted is dropped for the new one. */
    for (i = 0u; i < WT_SPM_MEM_FRAG_SLOTS; i++) {
        if ((g_frag[i].active != 0u) && (g_frag[i].sender == sender)) {
            if (g_frag[i].aborted == 0u) {
                return WT_FFA_BUSY;
            }
            wt_ffa_mem_frag_reset(&g_frag[i]);
        }
    }
    for (i = first; (i < last) && (slot == NULL); i++) {
        if (g_frag[i].active == 0u) {
            slot = &g_frag[i];
        }
    }
    if (slot == NULL) {
        ret = WT_FFA_NO_MEMORY;
    }
    if (ret == 0) {
        *handle = (op == WT_SPM_MEM_FRAG_OP_RETRIEVE) ?
                  named : wt_ffa_mem_handle_reserve(&g_reg);
        ret = wt_ffa_mem_frag_begin(slot, *handle, sender, op, frag, frag_len,
                                    total);
    }
    return ret;
}

int wt_spm_mem_frag_next(uint64_t handle, uint16_t sender, const uint8_t* frag,
                         uint32_t frag_len, uint32_t* offset, int* done)
{
    wt_ffa_mem_frag_t* slot = frag_slot(handle, sender);
    int ret;

    if ((slot == NULL) || (offset == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* The relayer ends the transfer and says so (DEN0140 4.1.2 rule 8). */
    if (slot->aborted != 0u) {
        wt_ffa_mem_frag_reset(slot);
        return WT_FFA_ABORTED;
    }
    ret = wt_ffa_mem_frag_add(slot, handle, sender, frag, frag_len, done);
    *offset = slot->received;
    return ret;
}

const uint8_t* wt_spm_mem_frag_desc(uint64_t handle, uint16_t sender,
                                    uint32_t* len, uint8_t* op)
{
    wt_ffa_mem_frag_t* slot = frag_slot(handle, sender);

    if ((slot == NULL) || (slot->aborted != 0u) ||
        (slot->received != slot->total) || (len == NULL) || (op == NULL)) {
        return NULL;
    }
    *len = slot->total;
    *op = slot->op;
    return slot->buf;
}

void wt_spm_mem_frag_release(uint64_t handle, uint16_t sender)
{
    wt_ffa_mem_frag_reset(frag_slot(handle, sender));
}

/* Later fragments must come through the buffer the first one did (DEN0140
 * 4.1.2 rule 6), which an unmap takes away. */
void wt_spm_mem_frag_abort(uint16_t sender)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_MEM_FRAG_SLOTS; i++) {
        if ((g_frag[i].active != 0u) && (g_frag[i].sender == sender)) {
            g_frag[i].aborted = 1u;
        }
    }
}

int wt_spm_mem_frag_share(uint64_t handle, uint16_t sender)
{
    const uint8_t* desc;
    uint64_t out = 0u;
    uint32_t len = 0u;
    uint8_t op = 0u;
    int ret = WT_FFA_INVALID_PARAMETERS;

    desc = wt_spm_mem_frag_desc(handle, sender, &len, &op);
    if ((desc != NULL) && (op != WT_SPM_MEM_FRAG_OP_RETRIEVE)) {
        ret = mem_share(desc, (size_t)len, (wt_ffa_mem_op_t)op, sender, handle,
                        &out);
    }
    wt_spm_mem_frag_release(handle, sender);
    return ret;
}

/* The Normal world can rewrite its TX buffer while the SPMC reads it, so its
 * descriptor is parsed only from one Secure copy, no larger than a reassembled
 * one. */
static uint8_t g_ns_desc[WT_FFA_MEM_FRAG_MAX];

int wt_spm_mem_ns_send(wt_ffa_mem_op_t op, const uint8_t* tx,
                       uint32_t frag_len, uint32_t total, uint64_t* handle)
{
    int ret = 0;

    if ((tx == NULL) || (handle == NULL) || (frag_len == 0u) ||
        (frag_len > total)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    else if (frag_len > (uint32_t)sizeof(g_ns_desc)) {
        ret = WT_FFA_NO_MEMORY;
    }
    if (ret == 0) {
        (void)memcpy(g_ns_desc, tx, (size_t)frag_len);
        if (frag_len < total) {
            ret = wt_spm_mem_frag_begin((uint8_t)op, WT_FFA_ID_NS_PRIMARY,
                                        g_ns_desc, frag_len, total, handle);
        }
        else {
            ret = mem_share(g_ns_desc, (size_t)total, op, WT_FFA_ID_NS_PRIMARY,
                            0u, handle);
        }
    }
    return ret;
}

/* What the borrower asked for against what the owner granted it (11.4.2):
 * it may ask for less, never for more, and never for execution. */
static int effective_permissions(int exclusive, int donate, uint8_t granted,
                                 uint8_t asked, uint8_t* out)
{
    uint8_t data = asked & WT_FFA_MEM_PERM_DATA_MASK;
    uint8_t instr = asked & WT_FFA_MEM_PERM_INSTR_MASK;
    uint8_t granted_data = granted & WT_FFA_MEM_PERM_DATA_MASK;

    /* A lend or share borrower must state the data access it wants (DEN0140
     * 1.10.2 item 1, validated per 1.11.3.3). */
    if ((data == WT_FFA_MEM_PERM_DATA_RSVD) ||
        ((data == WT_FFA_MEM_PERM_DATA_NOT_SPEC) && (donate == 0)) ||
        (instr == WT_FFA_MEM_PERM_INSTR_MASK)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* A receiver states instruction access only when the memory becomes its
     * alone (a donate, or a lend to one borrower); for a share or a lend to
     * several it is the relayer's (Table 5.14 usage). */
    if ((exclusive == 0) && (instr != WT_FFA_MEM_PERM_INSTR_NOT_SPEC)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((asked & WT_FFA_MEM_PERM_INSTR_MASK) == WT_FFA_MEM_PERM_INSTR_X) {
        return WT_FFA_DENIED;
    }
    /* A donate's receiver only should state it (1.10.2 item 2): the grant
     * stands, instructions NX. */
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
 * set, n asks for a 2^n x 4 KB boundary. Partitions see memory at its physical
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
    /* Table 1.22 prints 2*n x 4KB, read as 2^n: n = 0 would be no boundary. */
    boundary = (uint64_t)WT_FFA_MEM_PAGE_SIZE << hint;
    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        if ((e->regions[i].base % boundary) != 0u) {
            return WT_FFA_DENIED;
        }
    }
    return 0;
}

/* A receiver that names the ranges to map the memory at (1.11.3.2) names
 * them for itself, with no alignment hint (Table 1.22 bits[9:5]) and covering
 * exactly the sender's pages (1.11.3.3). The relayer maps S-EL0 memory only
 * at its own address, so the ranges must be the region's pages in order. */
static int receiver_ranges_ok(const wt_ffa_mem_handle_entry_t* e,
                              const wt_ffa_mem_retrieve_req_t* rq,
                              uint16_t receiver)
{
    uint64_t want;
    uint32_t i = 0u;
    uint32_t r = 0u;
    uint32_t ioff = 0u;
    uint32_t roff = 0u;
    uint32_t step;

    if ((rq->receivers[rq->range_index] != receiver) ||
        ((rq->flags & (WT_FFA_MEM_FLAG_ALIGN_VALID |
                       (0xFu << WT_FFA_MEM_FLAG_ALIGN_SHIFT))) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    while ((i < rq->range_count) && (r < (uint32_t)e->region_count)) {
        want = e->regions[r].base + ((uint64_t)roff * WT_FFA_MEM_PAGE_SIZE);
        if ((rq->ranges[i].address + ((uint64_t)ioff * WT_FFA_MEM_PAGE_SIZE)) !=
            want) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        step = rq->ranges[i].page_count - ioff;
        if ((e->regions[r].page_count - roff) < step) {
            step = e->regions[r].page_count - roff;
        }
        ioff += step;
        roff += step;
        if (ioff == rq->ranges[i].page_count) {
            i++;
            ioff = 0u;
        }
        if (roff == e->regions[r].page_count) {
            r++;
            roff = 0u;
        }
    }
    return ((i == rq->range_count) && (r == (uint32_t)e->region_count))
               ? 0 : WT_FFA_INVALID_PARAMETERS;
}

/* Take the first count regions of e back out of a borrower's table, each to
 * the entry it held before the grant. */
static void borrower_unmap(const wt_spm_mem_binding_t* b,
                           const wt_ffa_mem_handle_entry_t* e, uint8_t mapping,
                           uint32_t count)
{
    uint32_t i;

    for (i = 0u; i < count; i++) {
        (void)wt_domain_revoke(b->dom->regions, b->dom->region_count,
                               (uintptr_t)e->regions[i].base,
                               e->regions[i].page_count,
                               ((mapping & WT_SPM_MEM_MAP_REGION(i)) != 0u) ? 1
                                                                            : 0);
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
    uint32_t version = caller_version(receiver);
    uint32_t i;
    uint32_t done = 0u;
    uint8_t mapping = 0u;
    uint8_t perms = 0u;
    uint8_t asked = 0u;
    int named = 0;
    int was_mapped = 0;
    int zero = 0;
    int ret;

    if ((resp == NULL) || (out_resp_len == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_retrieve_req_parse_at(req, len, version, &rq);
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
    /* 1.11.1: a handle not sent to this receiver is INVALID_PARAMETERS. */
    if (borrower == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((b == NULL) || (borrower->retrieved != 0u)) {
        return WT_FFA_DENIED;
    }
    ret = wt_ffa_mem_retrieve_req_check(e, &rq, receiver);
    if ((ret == 0) && (rq.range_count != 0u)) {
        ret = receiver_ranges_ok(e, &rq, receiver);
    }
    if (ret != 0) {
        return ret;
    }
    ret = effective_permissions(
        ((e->state == (uint8_t)WT_FFA_MEM_STATE_DONATED) ||
         ((e->state == (uint8_t)WT_FFA_MEM_STATE_LENT) &&
          (e->borrower_count == 1u))) ? 1 : 0,
        (e->state == (uint8_t)WT_FFA_MEM_STATE_DONATED) ? 1 : 0,
        borrower->permissions, asked, &perms);
    if (ret != 0) {
        return ret;
    }
    /* The zero-memory flags are MBZ for shared memory (Table 5.22); a
     * read-only borrower cannot have lent memory wiped either. */
    if ((rq.flags & (WT_FFA_MEM_FLAG_ZERO | WT_FFA_MEM_FLAG_ZERO_AFTER)) != 0u) {
        if (e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        /* Bit 0 is MBZ once this borrower has retrieved the region before
         * (Table 1.22): the wipe ran once, ahead of its first retrieval. */
        if (((rq.flags & WT_FFA_MEM_FLAG_ZERO) != 0u) &&
            (borrower->ever_retrieved != 0u)) {
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
    if (rq.range_count == 0u) {
        in.constituents = cons;
        in.constituent_count = (uint32_t)e->region_count;
    }
    in.tag = e->tag;
    in.handle = rq.handle;
    /* Only a first retrieval follows the wipe (Table 1.23 bit[0]). */
    zero = (((e->owner_cookie & WT_FFA_MEM_FLAG_ZERO) != 0u) &&
            (borrower->ever_retrieved == 0u)) ? 1 : 0;
    in.flags = wt_ffa_mem_type_flag(e->state) |
               ((zero != 0) ? WT_FFA_MEM_FLAG_ZERO : 0u);
    in.op = WT_FFA_MEM_OP_SHARE;
    in.sender = e->owner;
    in.receiver = receiver;
    /* A v1.0 borrower that never asked for the NS bit is not told it
     * (DEN0140 Table 1.19 row 5). */
    in.attributes = (uint16_t)(e->attributes |
                               (((e->regions[0].ns != 0u) &&
                                 (wt_spm_sp_ffa_ns_bit(b->co) != 0))
                                    ? WT_FFA_MEM_ATTR_NS : 0u));
    in.permissions = perms;
    /* The response is in the borrower's own version, whatever size its
     * request used (DEN0077A 18.5.3). */
    in.access_desc_size = 0u;
    in.impdef = borrower->impdef;
    in.version = version;
    ret = wt_ffa_mem_txn_build(resp, resp_cap, &in, out_resp_len);
    if (ret != 0) {
        return ret;
    }
    attributes = WT_MEM_ATTR_READ;
    if ((perms & WT_FFA_MEM_PERM_DATA_MASK) == WT_FFA_MEM_PERM_DATA_RW) {
        attributes |= WT_MEM_ATTR_WRITE;
    }
    else {
        mapping |= (uint8_t)WT_SPM_MEM_MAP_RO;
    }
    if ((rq.flags & WT_FFA_MEM_FLAG_ZERO_AFTER) != 0u) {
        mapping |= (uint8_t)WT_SPM_MEM_MAP_ZERO_AFTER;
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
            if (was_mapped != 0) {
                mapping |= (uint8_t)WT_SPM_MEM_MAP_REGION(i);
            }
            done++;
        }
    }
    if (ret != 0) {
        borrower_unmap(b, e, mapping, done);
        return ret;
    }
    borrower->mapping = mapping;
    ret = wt_ffa_mem_handle_retrieve(&g_reg, rq.handle, receiver);
    /* A donate hands ownership over for good: the region is now the receiver's
     * own writable memory (the owner's access was dropped at donate time), so
     * the transaction is consumed and there is nothing to reclaim. */
    if ((ret == 0) && (e->state == (uint8_t)WT_FFA_MEM_STATE_DONATED)) {
        (void)wt_ffa_mem_handle_free(&g_reg, rq.handle);
    }
    return ret;
}

/* A borrower has let go: with several borrowers a wipe waits until the last
 * of them has been unmapped, as the relayer zeroes memory only once no other
 * component maps it (DEN0140 1.11.4.1), and a transaction whose owner is gone
 * ends with it, its memory left to the SPM. */
static void borrower_released(uint64_t handle,
                              const wt_ffa_mem_handle_entry_t* e,
                              uint32_t cookie)
{
    if (((cookie & WT_SPM_MEM_COOKIE_ZERO_PENDING) != 0u) &&
        (e->retrieved == 0u)) {
        zero_regions(e);
        cookie &= ~WT_SPM_MEM_COOKIE_ZERO_PENDING;
    }
    wt_ffa_mem_handle_set_meta(&g_reg, handle, e->tag, cookie);
    if (((cookie & WT_SPM_MEM_COOKIE_OWNER_GONE) != 0u) &&
        (e->retrieved == 0u)) {
        (void)wt_ffa_mem_handle_free(&g_reg, handle);
    }
}

int wt_spm_mem_relinquish(const uint8_t* rel, size_t len, uint16_t endpoint)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_borrower_t* borrower;
    wt_spm_mem_binding_t* b;
    uint64_t handle = 0u;
    uint32_t flags = 0u;
    uint32_t cookie;
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
    /* 2.6.1.2: a caller the region was not sent to is INVALID_PARAMETERS;
     * one that has not retrieved it is DENIED. */
    if (borrower == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((b == NULL) || (borrower->retrieved == 0u)) {
        return WT_FFA_DENIED;
    }
    /* The zero-memory flag is MBZ for shared memory, and for a borrower
     * whose retrieve left it read-only access (Table 2.25). */
    if ((flags & WT_FFA_MEM_RELINQ_FLAG_ZERO) != 0u) {
        if (e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if ((borrower->mapping & WT_SPM_MEM_MAP_RO) != 0u) {
            return WT_FFA_DENIED;
        }
    }
    ret = wt_ffa_mem_handle_relinquish(&g_reg, handle, endpoint);
    if (ret != 0) {
        return ret;
    }
    borrower_unmap(b, e, borrower->mapping, (uint32_t)e->region_count);
    /* The flag here, not the one at retrieve, decides. */
    cookie = e->owner_cookie;
    if ((flags & WT_FFA_MEM_RELINQ_FLAG_ZERO) != 0u) {
        cookie |= WT_SPM_MEM_COOKIE_ZERO_PENDING;
    }
    borrower_released(handle, e, cookie);
    return 0;
}

int wt_spm_mem_reclaim(uint64_t handle, uint16_t owner, uint32_t flags)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_handle_entry_t snapshot;
    int ret;

    ret = wt_ffa_mem_reclaim_flags_check(flags);
    if (ret != 0) {
        return ret;
    }
    ret = wt_ffa_mem_handle_lookup(&g_reg, handle, &e);
    if (ret != 0) {
        return ret;
    }
    if (((flags & WT_FFA_MEM_RELINQ_FLAG_ZERO) != 0u) &&
        ((e->owner_cookie & WT_SPM_MEM_COOKIE_OWNER_RO) != 0u)) {
        return (e->owner == owner) ? WT_FFA_DENIED : WT_FFA_INVALID_PARAMETERS;
    }
    snapshot = *e;
    ret = wt_ffa_mem_handle_reclaim(&g_reg, handle, owner);
    if (ret != 0) {
        return ret;
    }
    /* The wipe comes before the owner's mapping does (Table 2.31 bit[0]), and
     * goes through S-EL1-only entries: one a share left EL0 read-only is
     * read-only at S-EL1 too. */
    if ((flags & WT_FFA_MEM_RELINQ_FLAG_ZERO) != 0u) {
        owner_access(&snapshot, WT_SPM_MEM_OWNER_WITHDRAW);
        zero_regions(&snapshot);
    }
    owner_access(&snapshot, WT_SPM_MEM_OWNER_RELEASE);
    return 0;
}

/* A borrower that faulted lets go of everything it retrieved, zeroed where
 * its retrieve asked (Table 1.22 bit[2]). */
static void borrower_teardown(const wt_spm_mem_binding_t* b, uint64_t handle)
{
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_borrower_t* borrower;
    uint32_t cookie;

    borrower = wt_ffa_mem_handle_borrower(&g_reg, handle, b->id);
    if ((borrower == NULL) || (borrower->retrieved == 0u) ||
        (wt_ffa_mem_handle_lookup(&g_reg, handle, &e) != 0) ||
        (wt_ffa_mem_handle_relinquish(&g_reg, handle, b->id) != 0)) {
        return;
    }
    borrower_unmap(b, e, borrower->mapping, (uint32_t)e->region_count);
    cookie = e->owner_cookie;
    if ((borrower->mapping & WT_SPM_MEM_MAP_ZERO_AFTER) != 0u) {
        cookie |= WT_SPM_MEM_COOKIE_ZERO_PENDING;
    }
    borrower_released(handle, e, cookie);
}

/* A bound partition that faults is terminated, never restarted, so what it
 * owned goes to the SPM, not back to it (1.3.1 rule 9): a transaction no
 * borrower holds ends now, one a borrower still maps when the last lets go. */
static void owner_teardown(uint16_t owner, uint64_t handle)
{
    const wt_ffa_mem_handle_entry_t* e;

    if ((wt_ffa_mem_handle_lookup(&g_reg, handle, &e) != 0) ||
        (e->owner != owner)) {
        return;
    }
    if (e->retrieved != 0u) {
        wt_ffa_mem_handle_set_meta(&g_reg, handle, e->tag,
                                   e->owner_cookie |
                                       WT_SPM_MEM_COOKIE_OWNER_GONE);
        return;
    }
    (void)wt_ffa_mem_handle_reclaim(&g_reg, handle, owner);
}

void wt_spm_mem_endpoint_teardown(const struct wt_co* co)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(co);
    uint64_t handle;
    unsigned int i;

    if (b == NULL) {
        return;
    }
    for (i = 0u; i < WT_SPM_MEM_FRAG_SLOTS; i++) {
        if ((g_frag[i].active != 0u) && (g_frag[i].sender == b->id)) {
            wt_ffa_mem_frag_reset(&g_frag[i]);
        }
    }
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        if (g_reg.entries[i].state != (uint8_t)WT_FFA_MEM_STATE_FREE) {
            handle = g_reg.entries[i].handle;
            borrower_teardown(b, handle);
            owner_teardown(b->id, handle);
        }
    }
}

void wt_spm_mem_unbind(const struct wt_co* co)
{
    unsigned int i;

    wt_spm_mem_endpoint_teardown(co);
    for (i = 0u; i < WT_SPM_MEM_MAX_BIND; i++) {
        if ((g_bind[i].live != 0u) && (g_bind[i].co == co)) {
            g_bind[i].co = NULL;
            g_bind[i].dom = NULL;
            g_bind[i].id = 0u;
            g_bind[i].live = 0u;
        }
    }
}
