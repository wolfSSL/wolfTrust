/* tables.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_TABLES_H
#define WOLFTRUST_ARCH_AARCH64_TABLES_H

#include "wolftrust/types.h"

#include <stddef.h>
#include <stdint.h>

/* Stage-1 translation tables for one Secure Partition domain at S-EL0/S-EL1:
 * 4 KB granule, 39-bit VA (T0SZ = 25, three levels, pages only), one table
 * set per partition, built from the manifest regions over a byte pool. Pure
 * C with no system-register access so the host suite can walk every page. */

#define WT_TABLES_PAGE_SIZE      4096u
#define WT_TABLES_ENTRIES        512u
#define WT_TABLES_VA_BITS        39u
#define WT_TABLES_VA_LIMIT       (1ull << WT_TABLES_VA_BITS)

#define WT_TABLES_OK               0
#define WT_TABLES_ERROR_ARGUMENT (-1)
#define WT_TABLES_ERROR_WX       (-2)
#define WT_TABLES_ERROR_POOL     (-3)
#define WT_TABLES_ERROR_ALIGN    (-4)
#define WT_TABLES_ERROR_RANGE    (-5)
#define WT_TABLES_ERROR_OVERLAP  (-6)
#define WT_TABLES_ERROR_UNMAPPED (-7)

/* MAIR_EL1: idx0 Device-nGnRnE, idx1 Device-nGnRE, idx2 Normal WBWA,
 * idx3 Normal non-cacheable. */
#define WT_TABLES_ATTR_DEVICE_NGNRNE 0u
#define WT_TABLES_ATTR_DEVICE_NGNRE  1u
#define WT_TABLES_ATTR_NORMAL_WBWA   2u
#define WT_TABLES_ATTR_NORMAL_NC     3u
#define WT_TABLES_MAIR_EL1 \
    (0x00ull | (0x04ull << 8) | (0xFFull << 16) | (0x44ull << 24))

/* TCR_EL1: T0SZ 25, IRGN0/ORGN0 WBWA, SH0 inner, TG0 4K, EPD1 (no TTBR1
 * walks until the NS window lands), IPS 40-bit, 8-bit ASIDs. */
#define WT_TABLES_TCR_EL1 \
    (25ull | (1ull << 8) | (1ull << 10) | (3ull << 12) | (0ull << 14) | \
     (1ull << 23) | (2ull << 32))

/* Access permission field values (AP[2:1]). */
#define WT_TABLES_AP_EL1_RW      0u
#define WT_TABLES_AP_ALL_RW      1u
#define WT_TABLES_AP_EL1_RO      2u
#define WT_TABLES_AP_ALL_RO      3u

/* base_pa is what the descriptors carry; on the target it equals base. */
typedef struct wt_tables_pool {
    uint8_t* base;
    uint64_t base_pa;
    size_t size;
    size_t used;
} wt_tables_pool_t;

typedef struct wt_tables {
    uint64_t* l1;
    uint64_t l1_pa;
    uint16_t asid;
} wt_tables_t;

typedef struct wt_tables_walk {
    uint64_t pa;
    uint32_t attr_index;
    uint32_t ap;
    uint32_t uxn;
    uint32_t pxn;
    uint32_t ng;
    uint32_t ns;
} wt_tables_walk_t;

void wt_tables_pool_init(wt_tables_pool_t* pool, uint8_t* base, uint64_t base_pa,
                         size_t size);
uint64_t wt_tables_pool_pa(const wt_tables_pool_t* pool, const void* page);
size_t wt_tables_pool_pages_used(const wt_tables_pool_t* pool);

/* el0_regions: the partition's manifest regions (EL0 + EL1 access, nG).
 * el1_regions: the SPM image, pool, and stacks (EL1 only, global). The two
 * sets must not overlap; a region that is writable and executable fails. */
int wt_tables_build(wt_tables_t* t, uint16_t asid,
                    const wt_memory_region_t* el0_regions, size_t el0_count,
                    const wt_memory_region_t* el1_regions, size_t el1_count,
                    wt_tables_pool_t* pool);

/* Software walk: WT_TABLES_OK with the page's fields, or ERROR_UNMAPPED. */
int wt_tables_walk(const wt_tables_t* t, const wt_tables_pool_t* pool,
                   uint64_t va, wt_tables_walk_t* out);

uint64_t wt_tables_ttbr0(const wt_tables_t* t);

#endif /* WOLFTRUST_ARCH_AARCH64_TABLES_H */
