/* main.c
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

/* WT-PORT-0014 (builder rows): the S-EL0 partition tables encode every
 * attribute per the matrix, refuse W^X and overlaps, leave the guard page
 * unmapped, keep partition pages non-global and Secure, and account for
 * the pool. The manifest-driven full-RAM scan lands with the real manifests. */

#include "wolftrust/arch/aarch64/tables.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define POOL_PAGES 64u
#define POOL_PA    0x0E100000ull

static int checks;
static int failures;
static uint8_t g_pool_mem[POOL_PAGES * WT_TABLES_PAGE_SIZE]
    __attribute__((aligned(4096)));

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

#define RW (WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE)
#define RX (WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC)

static const wt_memory_region_t g_el1[] = {
    { 0x0E041000u, 0x4000u, RX },
    { 0x0E045000u, 0x2000u, RW },
    { (uintptr_t)POOL_PA, POOL_PAGES * WT_TABLES_PAGE_SIZE, RW }
};

static const wt_memory_region_t g_sp[] = {
    { 0x0E200000u, 0x2000u, RX },
    { 0x0E202000u, 0x1000u, RW },
    { 0x0E203000u, 0x1000u, WT_MEM_ATTR_READ },
    { 0x0E205000u, 0x2000u, RW | WT_MEM_ATTR_RESTART_CLEAR },
    { 0x09040000u, 0x1000u, RW | WT_MEM_ATTR_DEVICE },
    { 0x0E300000u, 0u, RW }
};

static int build(wt_tables_t* t, uint16_t asid, const wt_memory_region_t* sp,
                 size_t n, wt_tables_pool_t* pool)
{
    return wt_tables_build(t, asid, sp, n, g_el1,
                           sizeof(g_el1) / sizeof(g_el1[0]), pool);
}

static int walk_is(const wt_tables_t* t, const wt_tables_pool_t* pool,
                   uint64_t va, uint32_t attr, uint32_t ap, uint32_t uxn,
                   uint32_t pxn, uint32_t ng)
{
    wt_tables_walk_t w;

    if (wt_tables_walk(t, pool, va, &w) != WT_TABLES_OK) {
        return 0;
    }
    return (w.pa == va) && (w.attr_index == attr) && (w.ap == ap) &&
           (w.uxn == uxn) && (w.pxn == pxn) && (w.ng == ng) && (w.ns == 0u);
}

int main(void)
{
    wt_tables_pool_t pool;
    wt_tables_t t;
    wt_tables_t t2;
    wt_tables_walk_t w;
    wt_memory_region_t bad[2];
    size_t used;
    int ret;

    printf("WT-PORT-0014 (AArch64 stage-1 table builder)\n");

    wt_tables_pool_init(&pool, g_pool_mem, POOL_PA, sizeof(g_pool_mem));
    ret = build(&t, 3u, g_sp, sizeof(g_sp) / sizeof(g_sp[0]), &pool);
    check(ret == WT_TABLES_OK, "a partition table builds from EL1 fill + EL0 regions");
    used = wt_tables_pool_pages_used(&pool);
    check(used == 5u, "one L1, one L2, three L3 pages for regions in three 2 MB blocks");
    check(wt_tables_ttbr0(&t) == (POOL_PA | (3ull << 48)),
          "TTBR0 = L1 page address with the ASID in bits 63:48");

    check(walk_is(&t, &pool, 0x0E200000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_ALL_RO, 0u, 0u, 1u) &&
          walk_is(&t, &pool, 0x0E201000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_ALL_RO, 0u, 0u, 1u),
          "SP code: Normal WBWA, RO for EL0+EL1, executable, non-global");
    check(walk_is(&t, &pool, 0x0E202000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_ALL_RW, 1u, 1u, 1u),
          "SP data: RW for EL0+EL1, UXN and PXN, non-global");
    check(walk_is(&t, &pool, 0x0E203000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_ALL_RO, 1u, 1u, 1u),
          "SP read-only data: RO, never executable");
    check(walk_is(&t, &pool, 0x0E205000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_ALL_RW, 1u, 1u, 1u) &&
          walk_is(&t, &pool, 0x0E206000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_ALL_RW, 1u, 1u, 1u),
          "SP stack: RW, restart-clear has no PTE effect");
    check(walk_is(&t, &pool, 0x09040000u, WT_TABLES_ATTR_DEVICE_NGNRE,
                  WT_TABLES_AP_ALL_RW, 1u, 1u, 1u),
          "device region: Device-nGnRE, RW, execute-never");
    check(walk_is(&t, &pool, 0x0E041000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_EL1_RO, 1u, 0u, 0u),
          "SPM code: EL1-only RO, PXN clear, UXN set, global");
    check(walk_is(&t, &pool, 0x0E045000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_EL1_RW, 1u, 1u, 0u) &&
          walk_is(&t, &pool, (uint64_t)POOL_PA, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_EL1_RW, 1u, 1u, 0u),
          "SPM data and the table pool: EL1-only RW, never EL0, global");
    check(wt_tables_walk(&t, &pool, 0x0E204000u, &w) == WT_TABLES_ERROR_UNMAPPED &&
          wt_tables_walk(&t, &pool, 0x0E207000u, &w) == WT_TABLES_ERROR_UNMAPPED &&
          wt_tables_walk(&t, &pool, 0x0E040000u, &w) == WT_TABLES_ERROR_UNMAPPED &&
          wt_tables_walk(&t, &pool, 0x40000000u, &w) == WT_TABLES_ERROR_UNMAPPED,
          "the stack guard page, the page past the stack, and untouched VAs are unmapped");
    check(wt_tables_walk(&t, &pool, 0x0E202ABCu, &w) == WT_TABLES_OK && w.pa == 0x0E202ABCu,
          "a walk keeps the page offset");
    check(wt_tables_walk(&t, &pool, WT_TABLES_VA_LIMIT, &w) == WT_TABLES_ERROR_RANGE,
          "a VA at or past 2^39 is out of range");

    ret = build(&t2, 4u, g_sp, 4u, &pool);
    check(ret == WT_TABLES_OK && wt_tables_pool_pages_used(&pool) == used + 4u &&
          wt_tables_ttbr0(&t2) != wt_tables_ttbr0(&t),
          "a second partition table shares the pool and gets its own L1");
    check(walk_is(&t2, &pool, 0x0E041000u, WT_TABLES_ATTR_NORMAL_WBWA,
                  WT_TABLES_AP_EL1_RO, 1u, 0u, 0u) &&
          wt_tables_walk(&t2, &pool, 0x09040000u, &w) == WT_TABLES_ERROR_UNMAPPED,
          "the EL1 fill is identical in every table, EL0 regions are per table");

    memcpy(bad, g_sp, sizeof(bad));
    bad[0].attributes = RW | WT_MEM_ATTR_EXEC;
    check(build(&t2, 5u, bad, 1u, &pool) == WT_TABLES_ERROR_WX,
          "a writable and executable region fails closed");
    bad[0].attributes = RX | WT_MEM_ATTR_DEVICE;
    check(build(&t2, 5u, bad, 1u, &pool) == WT_TABLES_ERROR_WX,
          "an executable device region fails closed");
    bad[0].attributes = WT_MEM_ATTR_WRITE;
    check(build(&t2, 5u, bad, 1u, &pool) == WT_TABLES_ERROR_ARGUMENT,
          "write without read has no encoding and is refused");
    bad[0].attributes = RX;
    bad[0].base = 0x0E200800u;
    check(build(&t2, 5u, bad, 1u, &pool) == WT_TABLES_ERROR_ALIGN,
          "a region base off the 4 KB granule is refused");
    bad[0].base = 0x0E200000u;
    bad[0].size = 0x1800u;
    check(build(&t2, 5u, bad, 1u, &pool) == WT_TABLES_ERROR_ALIGN,
          "a region size off the 4 KB granule is refused");
    bad[0].size = 0x2000u;
    bad[1].base = 0x0E201000u;
    bad[1].size = 0x1000u;
    bad[1].attributes = RW;
    check(build(&t2, 5u, bad, 2u, &pool) == WT_TABLES_ERROR_OVERLAP,
          "two EL0 regions sharing a page overlap");
    bad[1].base = 0x0E045000u;
    check(build(&t2, 5u, bad, 2u, &pool) == WT_TABLES_ERROR_OVERLAP,
          "an EL0 region over the SPM fill overlaps (no page differs across tables)");
    bad[1].base = (uintptr_t)(WT_TABLES_VA_LIMIT - 0x1000ull);
    bad[1].size = 0x2000u;
    check(build(&t2, 5u, bad, 2u, &pool) == WT_TABLES_ERROR_RANGE,
          "a region past the 39-bit VA space is refused");
    check(wt_tables_build(&t2, 256u, g_sp, 1u, g_el1, 1u, &pool) ==
              WT_TABLES_ERROR_ARGUMENT &&
          wt_tables_build(NULL, 1u, g_sp, 1u, g_el1, 1u, &pool) ==
              WT_TABLES_ERROR_ARGUMENT,
          "an ASID over 8 bits or a NULL table is refused");
    wt_tables_pool_init(&pool, g_pool_mem, POOL_PA, 2u * WT_TABLES_PAGE_SIZE);
    check(build(&t2, 6u, g_sp, 1u, &pool) == WT_TABLES_ERROR_POOL,
          "pool exhaustion fails the build");
    wt_tables_pool_init(&pool, g_pool_mem + 8u, POOL_PA, 4u * WT_TABLES_PAGE_SIZE);
    check(build(&t2, 6u, g_sp, 1u, &pool) == WT_TABLES_ERROR_ARGUMENT,
          "an unaligned pool is refused");
    check(WT_TABLES_MAIR_EL1 == 0x44FF0400ull &&
          (WT_TABLES_TCR_EL1 & 0x3Fu) == 25u && ((WT_TABLES_TCR_EL1 >> 32) & 7u) == 2u &&
          ((WT_TABLES_TCR_EL1 >> 23) & 1u) == 1u,
          "MAIR indexes and TCR (T0SZ 25, IPS 40-bit, EPD1) match the design");

    printf("aarch64_tables: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
