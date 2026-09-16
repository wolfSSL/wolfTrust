/* tables.c
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

/* Stage-1 table builder for the S-EL0 partition domains (VMSAv8-64, 4 KB
 * granule, pages only). Identity-mapped: VA == PA for every region. */

#include "wolftrust/arch/aarch64/tables.h"

#define DESC_VALID      (1ull << 0)
#define DESC_TABLE      (1ull << 1)
#define DESC_PAGE       (1ull << 1)
#define PTE_ATTR_SHIFT  2u
#define PTE_NS          (1ull << 5)
#define PTE_AP_SHIFT    6u
#define PTE_SH_INNER    (3ull << 8)
#define PTE_AF          (1ull << 10)
#define PTE_NG          (1ull << 11)
#define PTE_PXN         (1ull << 53)
#define PTE_UXN         (1ull << 54)
#define PTE_ADDR_MASK   0x0000FFFFFFFFF000ull

#define L1_SHIFT 30u
#define L2_SHIFT 21u
#define L3_SHIFT 12u
#define INDEX_MASK (WT_TABLES_ENTRIES - 1u)

void wt_tables_pool_init(wt_tables_pool_t* pool, uint8_t* base, uint64_t base_pa,
                         size_t size)
{
    if (pool != NULL) {
        pool->base = base;
        pool->size = size;
        pool->used = 0u;
        pool->base_pa = base_pa;
    }
}

uint64_t wt_tables_pool_pa(const wt_tables_pool_t* pool, const void* page)
{
    return pool->base_pa + (uint64_t)((const uint8_t*)page - pool->base);
}

size_t wt_tables_pool_pages_used(const wt_tables_pool_t* pool)
{
    return (pool != NULL) ? (pool->used / WT_TABLES_PAGE_SIZE) : 0u;
}

static uint64_t* pool_page(wt_tables_pool_t* pool)
{
    uint64_t* page;
    size_t i;

    if ((pool->used + WT_TABLES_PAGE_SIZE) > pool->size) {
        return NULL;
    }
    page = (uint64_t*)(pool->base + pool->used);
    pool->used += WT_TABLES_PAGE_SIZE;
    for (i = 0u; i < WT_TABLES_ENTRIES; i++) {
        page[i] = 0u;
    }
    return page;
}

static uint64_t* table_at(const wt_tables_pool_t* pool, uint64_t desc)
{
    return (uint64_t*)(pool->base + (size_t)((desc & PTE_ADDR_MASK) - pool->base_pa));
}

/* Attribute word -> page descriptor bits, or a negative error. */
static int64_t encode(uint32_t attributes, int el1_only)
{
    uint64_t pte = DESC_VALID | DESC_PAGE | PTE_SH_INNER | PTE_AF;
    int readable = (attributes & WT_MEM_ATTR_READ) != 0u;
    int writable = (attributes & WT_MEM_ATTR_WRITE) != 0u;
    int exec = (attributes & WT_MEM_ATTR_EXEC) != 0u;
    int device = (attributes & WT_MEM_ATTR_DEVICE) != 0u;

    if (!readable) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    if (writable && exec) {
        return WT_TABLES_ERROR_WX;
    }
    if (device && exec) {
        return WT_TABLES_ERROR_WX;
    }
    if (device) {
        pte |= (uint64_t)WT_TABLES_ATTR_DEVICE_NGNRE << PTE_ATTR_SHIFT;
        pte |= PTE_UXN | PTE_PXN;
    }
    else {
        pte |= (uint64_t)WT_TABLES_ATTR_NORMAL_WBWA << PTE_ATTR_SHIFT;
        if (!exec) {
            pte |= PTE_UXN | PTE_PXN;
        }
        else if (el1_only) {
            pte |= PTE_UXN;
        }
    }
    if (el1_only) {
        pte |= (uint64_t)(writable ? WT_TABLES_AP_EL1_RW : WT_TABLES_AP_EL1_RO)
               << PTE_AP_SHIFT;
    }
    else {
        pte |= (uint64_t)(writable ? WT_TABLES_AP_ALL_RW : WT_TABLES_AP_ALL_RO)
               << PTE_AP_SHIFT;
    }
    /* A range any table maps at EL0 must never be a global entry: global
     * TLB entries match under every ASID and would serve a partition's
     * EL0 fetch with the EL1-only permissions cached by the SPM. */
    if (!el1_only || (attributes & WT_TABLES_ATTR_NG) != 0u) {
        pte |= PTE_NG;
    }
    if ((attributes & WT_TABLES_ATTR_NS) != 0u) {
        pte |= PTE_NS;
    }
    return (int64_t)pte;
}

static int map_page(wt_tables_t* t, wt_tables_pool_t* pool, uint64_t va,
                    uint64_t pte)
{
    uint64_t* l2;
    uint64_t* l3;
    uint64_t desc;
    uint32_t i1 = (uint32_t)((va >> L1_SHIFT) & INDEX_MASK);
    uint32_t i2 = (uint32_t)((va >> L2_SHIFT) & INDEX_MASK);
    uint32_t i3 = (uint32_t)((va >> L3_SHIFT) & INDEX_MASK);

    desc = t->l1[i1];
    if ((desc & DESC_VALID) == 0u) {
        l2 = pool_page(pool);
        if (l2 == NULL) {
            return WT_TABLES_ERROR_POOL;
        }
        t->l1[i1] = wt_tables_pool_pa(pool, l2) | DESC_VALID | DESC_TABLE;
    }
    else {
        l2 = table_at(pool, desc);
    }
    desc = l2[i2];
    if ((desc & DESC_VALID) == 0u) {
        l3 = pool_page(pool);
        if (l3 == NULL) {
            return WT_TABLES_ERROR_POOL;
        }
        l2[i2] = wt_tables_pool_pa(pool, l3) | DESC_VALID | DESC_TABLE;
    }
    else {
        l3 = table_at(pool, desc);
    }
    if ((l3[i3] & DESC_VALID) != 0u) {
        return WT_TABLES_ERROR_OVERLAP;
    }
    l3[i3] = pte | (va & PTE_ADDR_MASK);
    return WT_TABLES_OK;
}

static int map_regions(wt_tables_t* t, wt_tables_pool_t* pool,
                       const wt_memory_region_t* regions, size_t count,
                       int el1_only)
{
    int ret = WT_TABLES_OK;
    int64_t pte;
    uint64_t va;
    uint64_t end;
    size_t i;

    for (i = 0u; (i < count) && (ret == WT_TABLES_OK); i++) {
        if (regions[i].size == 0u) {
            continue;
        }
        if (((regions[i].base % WT_TABLES_PAGE_SIZE) != 0u) ||
            ((regions[i].size % WT_TABLES_PAGE_SIZE) != 0u)) {
            ret = WT_TABLES_ERROR_ALIGN;
            break;
        }
        end = (uint64_t)regions[i].base + (uint64_t)regions[i].size;
        if ((end > WT_TABLES_VA_LIMIT) || (end < (uint64_t)regions[i].base)) {
            ret = WT_TABLES_ERROR_RANGE;
            break;
        }
        pte = encode(regions[i].attributes, el1_only);
        if (pte < 0) {
            ret = (int)pte;
            break;
        }
        for (va = regions[i].base; (va < end) && (ret == WT_TABLES_OK);
             va += WT_TABLES_PAGE_SIZE) {
            ret = map_page(t, pool, va, (uint64_t)pte);
        }
    }
    return ret;
}

int wt_tables_build(wt_tables_t* t, uint16_t asid,
                    const wt_memory_region_t* el0_regions, size_t el0_count,
                    const wt_memory_region_t* el1_regions, size_t el1_count,
                    wt_tables_pool_t* pool)
{
    int ret;

    if ((t == NULL) || (pool == NULL) || (pool->base == NULL) ||
        ((el0_count != 0u) && (el0_regions == NULL)) ||
        ((el1_count != 0u) && (el1_regions == NULL)) || (asid > 0xFFu) ||
        (((uintptr_t)pool->base % WT_TABLES_PAGE_SIZE) != 0u) ||
        ((pool->base_pa % WT_TABLES_PAGE_SIZE) != 0u)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    t->l1 = pool_page(pool);
    if (t->l1 == NULL) {
        return WT_TABLES_ERROR_POOL;
    }
    t->l1_pa = wt_tables_pool_pa(pool, t->l1);
    t->asid = asid;
    ret = map_regions(t, pool, el1_regions, el1_count, 1);
    if (ret == WT_TABLES_OK) {
        ret = map_regions(t, pool, el0_regions, el0_count, 0);
    }
    return ret;
}

int wt_tables_walk(const wt_tables_t* t, const wt_tables_pool_t* pool,
                   uint64_t va, wt_tables_walk_t* out)
{
    const uint64_t* l2;
    const uint64_t* l3;
    uint64_t desc;

    if ((t == NULL) || (pool == NULL) || (out == NULL) || (t->l1 == NULL)) {
        return WT_TABLES_ERROR_ARGUMENT;
    }
    if (va >= WT_TABLES_VA_LIMIT) {
        return WT_TABLES_ERROR_RANGE;
    }
    desc = t->l1[(va >> L1_SHIFT) & INDEX_MASK];
    if ((desc & DESC_VALID) == 0u) {
        return WT_TABLES_ERROR_UNMAPPED;
    }
    l2 = table_at(pool, desc);
    desc = l2[(va >> L2_SHIFT) & INDEX_MASK];
    if ((desc & DESC_VALID) == 0u) {
        return WT_TABLES_ERROR_UNMAPPED;
    }
    l3 = table_at(pool, desc);
    desc = l3[(va >> L3_SHIFT) & INDEX_MASK];
    if ((desc & DESC_VALID) == 0u) {
        return WT_TABLES_ERROR_UNMAPPED;
    }
    out->pa = (desc & PTE_ADDR_MASK) | (va & (WT_TABLES_PAGE_SIZE - 1u));
    out->attr_index = (uint32_t)((desc >> PTE_ATTR_SHIFT) & 0x7u);
    out->ap = (uint32_t)((desc >> PTE_AP_SHIFT) & 0x3u);
    out->uxn = ((desc & PTE_UXN) != 0u) ? 1u : 0u;
    out->pxn = ((desc & PTE_PXN) != 0u) ? 1u : 0u;
    out->ng = ((desc & PTE_NG) != 0u) ? 1u : 0u;
    out->ns = ((desc & PTE_NS) != 0u) ? 1u : 0u;
    return WT_TABLES_OK;
}

uint64_t wt_tables_ttbr0(const wt_tables_t* t)
{
    return (t->l1_pa & PTE_ADDR_MASK) | ((uint64_t)t->asid << 48);
}
