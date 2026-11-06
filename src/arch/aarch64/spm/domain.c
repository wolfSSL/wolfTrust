/* domain.c
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

/* The wt_arch_* domain operations over prebuilt per-partition tables:
 * program = switch TTBR0 to that partition's table (own ASID, no TLBI),
 * restore = back to the SPM-only table. */

#include "wolftrust/arch.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/tables.h"

typedef struct wt_domain_entry {
    const wt_memory_region_t* regions;
    size_t count;
    wt_tables_t table;
    wt_memory_region_t fill[WT_DOMAIN_MAX_FILL];
    size_t fill_count;
} wt_domain_entry_t;

static wt_tables_pool_t g_pool;
static wt_tables_t g_spm_table;
static const wt_memory_region_t* g_fill;
static size_t g_fill_count;
static wt_domain_entry_t g_entries[WT_DOMAIN_MAX_TABLES];
static size_t g_built;
static uint64_t g_current_ttbr0;
static unsigned int g_ready;

static int covers(const wt_memory_region_t* outer,
                  const wt_memory_region_t* inner)
{
    uintptr_t outer_end = outer->base + outer->size;
    uintptr_t inner_end = inner->base + inner->size;

    return (outer->base <= inner->base) && (outer_end >= inner_end) &&
           (outer_end >= outer->base) && (inner_end >= inner->base);
}

static int takes_over(const wt_memory_region_t* region,
                      const wt_memory_region_t* fill)
{
    if ((fill->attributes & WT_DOMAIN_FILL_SHARED) == 0u) {
        return 0;
    }
    if ((fill->attributes & WT_DOMAIN_FILL_OWNED) != 0u) {
        return (region->base == fill->base) && (region->size == fill->size);
    }
    return covers(region, fill);
}

static size_t partition_fill(wt_domain_entry_t* e,
                             const wt_memory_region_t* regions, size_t count)
{
    size_t n = 0u;
    size_t i;
    size_t j;
    int replaced;

    for (i = 0u; (i < g_fill_count) && (n < WT_DOMAIN_MAX_FILL); i++) {
        replaced = 0;
        for (j = 0u; j < count; j++) {
            if (takes_over(&regions[j], &g_fill[i])) {
                replaced = 1;
                break;
            }
        }
        if (!replaced) {
            e->fill[n] = g_fill[i];
            n++;
        }
    }
    return n;
}

int wt_domain_stack_band(const wt_domain_descriptor_t* d,
                         wt_memory_region_t* band)
{
    const wt_memory_resource_t* r;
    const wt_memory_resource_t* found = NULL;
    size_t i;

    if ((d == NULL) || (band == NULL) ||
        ((d->memory_resource_count != 0u) && (d->memory_resources == NULL))) {
        return -1;
    }
    for (i = 0u; i < d->memory_resource_count; i++) {
        r = &d->memory_resources[i];
        if (((r->attributes & WT_MEM_ATTR_WRITE) == 0u) ||
            ((r->attributes & (WT_MEM_ATTR_DEVICE | WT_MEMORY_ATTR_SHARED)) !=
             0u)) {
            continue;
        }
        if ((d->stack_size != 0u) &&
            ((d->stack_base < r->base) ||
             ((d->stack_base + d->stack_size) > (r->base + r->size)))) {
            continue;
        }
        found = r;
    }
    if (found == NULL) {
        return -1;
    }
    band->base = found->base;
    band->size = found->size;
    band->attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    return 0;
}

int wt_domain_spm_band(const wt_domain_descriptor_t* d, size_t i,
                       wt_memory_region_t* band)
{
    wt_memory_region_t stack;
    const wt_memory_resource_t* r;
    uint32_t scrubbed = WT_MEM_ATTR_WRITE | WT_MEMORY_ATTR_RESTART_CLEAR;
    int ret = -1;

    if ((d == NULL) || (band == NULL) || (d->memory_resources == NULL) ||
        (i >= d->memory_resource_count)) {
        return -1;
    }
    r = &d->memory_resources[i];
    if ((wt_domain_stack_band(d, &stack) == 0) && (stack.base == r->base) &&
        (stack.size == r->size)) {
        ret = 0;
    }
    else if (((r->attributes & scrubbed) == scrubbed) &&
             ((r->attributes & (WT_MEM_ATTR_DEVICE | WT_MEMORY_ATTR_SHARED)) ==
              0u)) {
        ret = 0;
    }
    if (ret == 0) {
        band->base = r->base;
        band->size = r->size;
        band->attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    }
    return ret;
}

int wt_domain_fill_foreign(const wt_memory_region_t* fill,
                           const uint32_t* owners, size_t fill_count,
                           uint32_t owner, uintptr_t base, size_t size)
{
    uint64_t end = (uint64_t)base + (uint64_t)size;
    uint64_t fill_end;
    size_t i;

    if ((fill == NULL) || (owners == NULL) || (end < (uint64_t)base)) {
        return 1;
    }
    for (i = 0u; i < fill_count; i++) {
        fill_end = (uint64_t)fill[i].base + (uint64_t)fill[i].size;
        if (((fill[i].attributes & WT_DOMAIN_FILL_OWNED) != 0u) &&
            (owners[i] != owner) && ((uint64_t)base < fill_end) &&
            ((uint64_t)fill[i].base < end)) {
            return 1;
        }
    }
    return 0;
}

uint64_t wt_domain_init(const wt_memory_region_t* fill, size_t fill_count,
                        uint8_t* pool, uint64_t pool_pa, size_t pool_size)
{
    int ret;

    g_ready = 0u;
    g_built = 0u;
    g_fill = fill;
    g_fill_count = fill_count;
    wt_tables_pool_init(&g_pool, pool, pool_pa, pool_size);
    /* The SPM-only table keeps every fill entry EL1-only; the builder reads
     * only the access bits, so the shareable flag passes through unused. */
    ret = wt_tables_build(&g_spm_table, 0u, NULL, 0u, fill, fill_count, &g_pool);
    if (ret != WT_TABLES_OK) {
        wt_domain_fail(WT_DOMAIN_FAIL_INIT);
        return 0u;
    }
    g_current_ttbr0 = wt_tables_ttbr0(&g_spm_table);
    g_ready = 1u;
    return g_current_ttbr0;
}

uint64_t wt_domain_current_ttbr0(void)
{
    return g_current_ttbr0;
}

size_t wt_domain_tables_built(void)
{
    return g_built;
}

size_t wt_domain_pool_pages_used(void)
{
    return wt_tables_pool_pages_used(&g_pool);
}

static wt_domain_entry_t* find_or_build(const wt_memory_region_t* regions,
                                        size_t count)
{
    wt_domain_entry_t* e;
    size_t i;
    int ret;

    for (i = 0u; i < g_built; i++) {
        if ((g_entries[i].regions == regions) && (g_entries[i].count == count)) {
            return &g_entries[i];
        }
    }
    if (g_built >= WT_DOMAIN_MAX_TABLES) {
        wt_domain_fail(WT_DOMAIN_FAIL_SLOTS);
        return NULL;
    }
    e = &g_entries[g_built];
    if (g_fill_count > WT_DOMAIN_MAX_FILL) {
        wt_domain_fail(WT_DOMAIN_FAIL_BUILD);
        return NULL;
    }
    e->fill_count = partition_fill(e, regions, count);
    ret = wt_tables_build(&e->table, (uint16_t)(g_built + 1u), regions, count,
                          e->fill, e->fill_count, &g_pool);
    if (ret != WT_TABLES_OK) {
        wt_domain_fail(WT_DOMAIN_FAIL_BUILD);
        return NULL;
    }
    e->regions = regions;
    e->count = count;
    g_built++;
    return e;
}

static wt_domain_entry_t* find_built(const wt_memory_region_t* regions,
                                     size_t count)
{
    size_t i;

    for (i = 0u; i < g_built; i++) {
        if ((g_entries[i].regions == regions) && (g_entries[i].count == count)) {
            return &g_entries[i];
        }
    }
    return NULL;
}

/* A page EL0 may now execute can hold instructions the partition wrote as
 * data, which EL0 cannot make fetchable itself (SCTLR_EL1.UCI is 0). */
static void sync_el0_exec(const wt_domain_entry_t* e, uintptr_t va,
                          size_t pages)
{
    wt_tables_walk_t w;
    uint64_t ttbr0 = wt_tables_ttbr0(&e->table);
    uint64_t at;
    size_t i;
    int exec = 0;

    for (i = 0u; (i < pages) && (exec == 0); i++) {
        at = (uint64_t)va + ((uint64_t)i * WT_TABLES_PAGE_SIZE);
        if ((wt_tables_walk(&e->table, &g_pool, at, &w) == WT_TABLES_OK) &&
            (w.uxn == 0u)) {
            exec = 1;
        }
    }
    if (exec != 0) {
        if (ttbr0 != g_current_ttbr0) {
            wt_mmu_switch_ttbr0(ttbr0);
        }
        wt_mmu_sync_icache((uint64_t)va, (uint64_t)pages * WT_TABLES_PAGE_SIZE);
        if (ttbr0 != g_current_ttbr0) {
            wt_mmu_switch_ttbr0(g_current_ttbr0);
        }
    }
}

int wt_domain_set_permissions(const wt_memory_region_t* regions, size_t count,
                              uintptr_t va, size_t pages, uint32_t attributes)
{
    wt_domain_entry_t* e = find_built(regions, count);
    int ret;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    ret = wt_tables_set_el0_attributes(&e->table, &g_pool, (uint64_t)va, pages,
                                       attributes);
    if (ret == WT_TABLES_OK) {
        wt_mmu_tlbi_asid((uint64_t)e->table.asid);
        sync_el0_exec(e, va, pages);
    }
    return ret;
}

/* What EL0 access this partition's stage-1 table gives va, whatever its region
 * list says: memory a partition owns or was given (a donate) is reachable at
 * EL0, so ownership that a transaction moved is still seen. Only Normal
 * write-back memory counts, the one type the relayer maps a borrower with. */
int wt_domain_page_access(const wt_memory_region_t* regions, size_t count,
                          uintptr_t va)
{
    const wt_domain_entry_t* e = find_built(regions, count);
    wt_tables_walk_t w;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL) ||
        ((va % WT_TABLES_PAGE_SIZE) != 0u)) {
        return WT_DOMAIN_ACCESS_NONE;
    }
    if ((wt_tables_walk(&e->table, &g_pool, (uint64_t)va, &w) != WT_TABLES_OK) ||
        (w.attr_index != WT_TABLES_ATTR_NORMAL_WBWA)) {
        return WT_DOMAIN_ACCESS_NONE;
    }
    if (w.ap == WT_TABLES_AP_ALL_RW) {
        return WT_DOMAIN_ACCESS_RW;
    }
    return (w.ap == WT_TABLES_AP_ALL_RO) ? WT_DOMAIN_ACCESS_RO
                                         : WT_DOMAIN_ACCESS_NONE;
}

int wt_domain_page_claimed(const wt_memory_region_t* regions, size_t count,
                           uintptr_t va)
{
    const wt_domain_entry_t* e = find_built(regions, count);
    wt_tables_walk_t w;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL) ||
        ((va % WT_TABLES_PAGE_SIZE) != 0u) ||
        (wt_tables_walk(&e->table, &g_pool, (uint64_t)va, &w) != WT_TABLES_OK)) {
        return 0;
    }
    return ((w.ap == WT_TABLES_AP_ALL_RW) || (w.ap == WT_TABLES_AP_ALL_RO) ||
            (w.hidden != 0u) || (w.held != 0u)) ? 1 : 0;
}

int wt_domain_page_owned(const wt_memory_region_t* regions, size_t count,
                         uintptr_t va)
{
    const wt_domain_entry_t* e = find_built(regions, count);
    wt_tables_walk_t w;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL) ||
        ((va % WT_TABLES_PAGE_SIZE) != 0u) ||
        (wt_tables_walk(&e->table, &g_pool, (uint64_t)va, &w) != WT_TABLES_OK) ||
        (w.held != 0u)) {
        return 0;
    }
    return ((w.ap == WT_TABLES_AP_ALL_RW) || (w.ap == WT_TABLES_AP_ALL_RO) ||
            (w.hidden != 0u)) ? 1 : 0;
}

int wt_domain_page_ns(const wt_memory_region_t* regions, size_t count,
                      uintptr_t va)
{
    const wt_domain_entry_t* e = find_built(regions, count);
    wt_tables_walk_t w;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL) ||
        (wt_tables_walk(&e->table, &g_pool, (uint64_t)va, &w) != WT_TABLES_OK)) {
        return 0;
    }
    return (w.ns != 0u) ? 1 : 0;
}

int wt_domain_grant(const wt_memory_region_t* regions, size_t count,
                    uintptr_t va, size_t pages, uint32_t attributes,
                    int* was_mapped)
{
    wt_domain_entry_t* e = find_built(regions, count);
    int ret;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    ret = wt_tables_grant_el0(&e->table, &g_pool, (uint64_t)va, pages,
                              attributes, was_mapped);
    wt_mmu_tlbi_asid((uint64_t)e->table.asid);
    return ret;
}

int wt_domain_revoke(const wt_memory_region_t* regions, size_t count,
                     uintptr_t va, size_t pages, int was_mapped)
{
    wt_domain_entry_t* e = find_built(regions, count);
    int ret;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    ret = wt_tables_revoke_el0(&e->table, &g_pool, (uint64_t)va, pages,
                               was_mapped);
    wt_mmu_tlbi_asid((uint64_t)e->table.asid);
    return ret;
}

int wt_domain_owner_hold(const wt_memory_region_t* regions, size_t count,
                         uintptr_t va, size_t pages, int keep_read)
{
    wt_domain_entry_t* e = find_built(regions, count);
    int ret;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    ret = wt_tables_hold_el0(&e->table, &g_pool, (uint64_t)va, pages,
                             keep_read);
    wt_mmu_tlbi_asid((uint64_t)e->table.asid);
    return ret;
}

int wt_domain_owner_withdraw(const wt_memory_region_t* regions, size_t count,
                             uintptr_t va, size_t pages)
{
    wt_domain_entry_t* e = find_built(regions, count);
    int ret;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    ret = wt_tables_withdraw_el0(&e->table, &g_pool, (uint64_t)va, pages);
    wt_mmu_tlbi_asid((uint64_t)e->table.asid);
    return ret;
}

int wt_domain_owner_release(const wt_memory_region_t* regions, size_t count,
                            uintptr_t va, size_t pages)
{
    wt_domain_entry_t* e = find_built(regions, count);
    int ret;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    ret = wt_tables_release_el0(&e->table, &g_pool, (uint64_t)va, pages);
    wt_mmu_tlbi_asid((uint64_t)e->table.asid);
    if (ret == WT_TABLES_OK) {
        sync_el0_exec(e, va, pages);
    }
    return ret;
}

int wt_domain_get_permissions(const wt_memory_region_t* regions, size_t count,
                              uintptr_t va, uint32_t* attributes)
{
    const wt_domain_entry_t* e = find_built(regions, count);
    wt_tables_walk_t w;
    int ret;

    if ((g_ready == 0u) || (e == NULL) || (regions == NULL) ||
        (attributes == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    if ((va % WT_TABLES_PAGE_SIZE) != 0u) {
        return WT_TABLES_ERROR_ALIGN;
    }
    ret = wt_tables_walk(&e->table, &g_pool, (uint64_t)va, &w);
    if (ret == WT_TABLES_OK) {
        *attributes = 0u;
        if ((w.ap == WT_TABLES_AP_ALL_RW) || (w.ap == WT_TABLES_AP_ALL_RO)) {
            *attributes |= WT_MEM_ATTR_READ;
        }
        if (w.ap == WT_TABLES_AP_ALL_RW) {
            *attributes |= WT_MEM_ATTR_WRITE;
        }
        if (w.uxn == 0u) {
            *attributes |= WT_MEM_ATTR_EXEC;
        }
    }
    return ret;
}

static void switch_to(uint64_t ttbr0)
{
    g_current_ttbr0 = ttbr0;
    wt_mmu_switch_ttbr0(ttbr0);
}

void wt_arch_program_sp_thread_domain(const wt_memory_region_t* regions,
                                      size_t count)
{
    wt_domain_entry_t* e;

    if (g_ready == 0u) {
        wt_domain_fail(WT_DOMAIN_FAIL_INIT);
        return;
    }
    e = find_or_build(regions, count);
    if (e != NULL) {
        switch_to(wt_tables_ttbr0(&e->table));
    }
}

/* No privileged-default variant exists at S-EL1 (the H5 PRIVDEFENA-off
 * form): the partition table is the domain. */
void wt_arch_program_secure_partition_domain(const wt_memory_region_t* regions,
                                             size_t count)
{
    wt_arch_program_sp_thread_domain(regions, count);
}

void wt_arch_restore_spm_domain(void)
{
    if (g_ready != 0u) {
        switch_to(wt_tables_ttbr0(&g_spm_table));
    }
}
