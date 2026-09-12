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
} wt_domain_entry_t;

static wt_tables_pool_t g_pool;
static wt_tables_t g_spm_table;
static const wt_memory_region_t* g_fill;
static size_t g_fill_count;
static wt_domain_entry_t g_entries[WT_DOMAIN_MAX_TABLES];
static size_t g_built;
static uint64_t g_current_ttbr0;
static unsigned int g_ready;

uint64_t wt_domain_init(const wt_memory_region_t* fill, size_t fill_count,
                        uint8_t* pool, uint64_t pool_pa, size_t pool_size)
{
    int ret;

    g_ready = 0u;
    g_built = 0u;
    g_fill = fill;
    g_fill_count = fill_count;
    wt_tables_pool_init(&g_pool, pool, pool_pa, pool_size);
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
    ret = wt_tables_build(&e->table, (uint16_t)(g_built + 1u), regions, count,
                          g_fill, g_fill_count, &g_pool);
    if (ret != WT_TABLES_OK) {
        wt_domain_fail(WT_DOMAIN_FAIL_BUILD);
        return NULL;
    }
    e->regions = regions;
    e->count = count;
    g_built++;
    return e;
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
