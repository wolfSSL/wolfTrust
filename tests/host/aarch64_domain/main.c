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

/* WT-PORT-0014 (domain rows): the AArch64 domain operations switch TTBR0
 * to one prebuilt table per partition region set, cache by the stable
 * regions pointer, restore the SPM-only table, and fail closed. */

#include "wolftrust/arch.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/tables.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define POOL_PAGES 32u
#define POOL_PA    0x0E041000ull

static int checks;
static int failures;
static uint8_t g_pool_mem[POOL_PAGES * WT_TABLES_PAGE_SIZE]
    __attribute__((aligned(4096)));
static uint64_t g_switched_to;
static unsigned int g_switches;
static int g_last_fail;
static unsigned int g_fails;

void wt_mmu_switch_ttbr0(uint64_t ttbr0)
{
    g_switched_to = ttbr0;
    g_switches++;
}

void wt_domain_fail(int code)
{
    g_last_fail = code;
    g_fails++;
}

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

static const wt_memory_region_t g_fill[] = {
    { 0x00000000u, 0x20000u, RX },
    { 0x0E000000u, 0x40000u, RW },
    { (uintptr_t)POOL_PA, POOL_PAGES * WT_TABLES_PAGE_SIZE, RW },
    { 0x09040000u, 0x1000u, RW | WT_MEM_ATTR_DEVICE }
};

static const wt_memory_region_t g_sp0[] = {
    { 0x0E200000u, 0x2000u, RX },
    { 0x0E202000u, 0x2000u, RW }
};

static const wt_memory_region_t g_sp1[] = {
    { 0x0E400000u, 0x2000u, RX },
    { 0x0E402000u, 0x1000u, RW }
};

static const wt_memory_region_t g_bad[] = {
    { 0x0E000000u, 0x1000u, RW }
};

int main(void)
{
    uint64_t spm;
    uint64_t sp0;
    uint64_t sp1;
    size_t used;
    unsigned int switches;

    printf("WT-PORT-0014 (AArch64 domain operations)\n");

    wt_arch_program_sp_thread_domain(g_sp0, 2u);
    check(g_fails == 1u && g_last_fail == WT_DOMAIN_FAIL_INIT && g_switches == 0u,
          "a domain switch before init fails closed and never touches TTBR0");
    wt_arch_restore_spm_domain();
    check(g_switches == 0u, "restore before init is a no-op");

    spm = wt_domain_init(g_fill, sizeof(g_fill) / sizeof(g_fill[0]), g_pool_mem,
                         POOL_PA, sizeof(g_pool_mem));
    check(spm == (POOL_PA | 0ull) && wt_domain_current_ttbr0() == spm &&
          wt_domain_tables_built() == 0u,
          "init builds the SPM-only table with ASID 0 and no partition tables");
    used = wt_domain_pool_pages_used();

    wt_arch_program_sp_thread_domain(g_sp0, 2u);
    sp0 = wt_domain_current_ttbr0();
    check(g_switches == 1u && g_switched_to == sp0 && (sp0 >> 48) == 1u &&
          wt_domain_tables_built() == 1u && wt_domain_pool_pages_used() > used,
          "the first partition gets ASID 1, its own L1, and TTBR0 switches to it");
    used = wt_domain_pool_pages_used();
    switches = g_switches;
    wt_arch_program_sp_thread_domain(g_sp0, 2u);
    check(g_switches == switches + 1u && g_switched_to == sp0 &&
          wt_domain_tables_built() == 1u && wt_domain_pool_pages_used() == used,
          "the same regions pointer reuses the table (no pool growth)");

    wt_arch_program_secure_partition_domain(g_sp1, 2u);
    sp1 = wt_domain_current_ttbr0();
    check((sp1 >> 48) == 2u && sp1 != sp0 && wt_domain_tables_built() == 2u,
          "a second partition gets ASID 2 through the privileged variant too");

    wt_arch_restore_spm_domain();
    check(g_switched_to == spm && wt_domain_current_ttbr0() == spm,
          "restore switches back to the SPM-only table");

    switches = g_switches;
    wt_arch_program_sp_thread_domain(g_bad, 1u);
    check(g_fails == 2u && g_last_fail == WT_DOMAIN_FAIL_BUILD &&
          g_switches == switches && wt_domain_tables_built() == 2u,
          "regions over the SPM fill fail the build and leave TTBR0 alone");

    check(wt_domain_pool_pages_used() <= POOL_PAGES, "pool accounting stays inside the pool");

    printf("aarch64_domain: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
