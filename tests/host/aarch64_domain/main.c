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
#include "wolftrust/sched/coroutine_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define POOL_PAGES 256u
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

static uint64_t g_tlbi_asid;
static unsigned int g_tlbis;

void wt_mmu_tlbi_asid(uint64_t asid)
{
    g_tlbi_asid = asid;
    g_tlbis++;
}

static uint64_t g_sync_va;
static uint64_t g_sync_size;
static uint64_t g_sync_ttbr0;
static unsigned int g_syncs;

void wt_mmu_sync_icache(uint64_t va, uint64_t size)
{
    g_sync_va = va;
    g_sync_size = size;
    g_sync_ttbr0 = g_switched_to;
    g_syncs++;
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
    { 0x00000000u, 0x20000u, RX | WT_DOMAIN_FILL_SHARED },
    { 0x0E000000u, 0x40000u, RW },
    { (uintptr_t)POOL_PA, POOL_PAGES * WT_TABLES_PAGE_SIZE, RW },
    { 0x09040000u, 0x1000u, RW | WT_MEM_ATTR_DEVICE },
    { 0x0E500000u, 0x2000u, RW | WT_DOMAIN_FILL_SHARED | WT_DOMAIN_FILL_OWNED }
};

/* Exactly the owned band: its owner's table takes it over. */
static const wt_memory_region_t g_sp_owned_exact[] = {
    { 0x0E500000u, 0x2000u, RW }
};

/* A wider region over the owned band is someone else claiming it. */
static const wt_memory_region_t g_sp_owned_cover[] = {
    { 0x0E4FF000u, 0x4000u, RW }
};

/* Public text, a band of domain 3, an SPMC band, and SPM RAM. */
static const wt_memory_region_t g_own_fill[] = {
    { 0x0E100000u, 0x10000u, RX | WT_DOMAIN_FILL_SHARED },
    { 0x0E240000u, 0x4000u, RW | WT_DOMAIN_FILL_SHARED | WT_DOMAIN_FILL_OWNED },
    { 0x0E2A0000u, 0x4000u, RW | WT_DOMAIN_FILL_SHARED | WT_DOMAIN_FILL_OWNED },
    { 0x0E200000u, 0x40000u, RW }
};
static const uint32_t g_own_owner[] = { 0u, 3u, WT_DOMAIN_ID_INVALID, 0u };

static void owner_rows(void)
{
    const size_t n = sizeof(g_own_fill) / sizeof(g_own_fill[0]);

    check(wt_domain_fill_foreign(g_own_fill, g_own_owner, n, 3u, 0x0E240000u,
                                 0x4000u) == 0 &&
          wt_domain_fill_foreign(g_own_fill, g_own_owner, n, 3u, 0x0E100000u,
                                 0x100000u) == 0,
          "a partition may name its own band and the public image");
    check(wt_domain_fill_foreign(g_own_fill, g_own_owner, n, 4u, 0x0E243000u,
                                 0x2000u) != 0 &&
          wt_domain_fill_foreign(g_own_fill, g_own_owner, n, 4u, 0x0E200000u,
                                 0x100000u) != 0,
          "one page of, or a range covering, another partition's band is refused");
    check(wt_domain_fill_foreign(g_own_fill, g_own_owner, n, 3u, 0x0E2A0000u,
                                 0x4000u) != 0,
          "no manifest partition may name an SPMC, echo, or native band, even exactly");
    check(wt_domain_fill_foreign(g_own_fill, g_own_owner, n, 3u,
                                 (uintptr_t)UINTPTR_MAX - 0xFFFu, 0x2000u) != 0,
          "a range that wraps is refused");
}


/* Covers the shared text fill entry exactly: allowed, replaces it. */
static const wt_memory_region_t g_sp_shared[] = {
    { 0x00000000u, 0x20000u, RX },
    { 0x0E600000u, 0x1000u, RW }
};

/* Covers only part of the shared text fill entry: still an overlap. */
static const wt_memory_region_t g_sp_partial[] = {
    { 0x00000000u, 0x10000u, RX },
    { 0x0E601000u, 0x1000u, RW }
};

/* One private page each, distinct region sets: as many tables as the cache
 * must hold for every partition plus the retained boot proofs and a borrower
 * rebuild, and one more to prove the cap. */
static wt_memory_region_t g_many[WT_DOMAIN_MAX_TABLES + 1u][1];

static void capacity_rows(void)
{
    size_t built = wt_domain_tables_built();
    size_t fails = g_fails;
    size_t i;
    int ok = 1;

    check(WT_DOMAIN_MAX_TABLES >= (WT_CO_MAX + WT_DOMAIN_PROOF_TABLES + 1u),
          "the table cache holds every partition, the five boot proof domains, "
          "and a borrower rebuild");
    for (i = 0u; (built + i) < WT_DOMAIN_MAX_TABLES; i++) {
        g_many[i][0].base = 0x0E700000u + (i * 0x1000u);
        g_many[i][0].size = 0x1000u;
        g_many[i][0].attributes = RW;
        wt_arch_program_sp_thread_domain(g_many[i], 1u);
        ok = ok && (g_fails == fails) &&
             (wt_domain_tables_built() == built + i + 1u);
    }
    check(ok && wt_domain_tables_built() == WT_DOMAIN_MAX_TABLES,
          "distinct region sets build up to the cache size without a failure");
    g_many[i][0].base = 0x0E700000u + (i * 0x1000u);
    g_many[i][0].size = 0x1000u;
    g_many[i][0].attributes = RW;
    wt_arch_program_sp_thread_domain(g_many[i], 1u);
    check(g_fails == fails + 1u && g_last_fail == WT_DOMAIN_FAIL_SLOTS &&
          wt_domain_tables_built() == WT_DOMAIN_MAX_TABLES,
          "one region set past the cache size fails closed on slots");
}

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

/* A partition whose declared stack is a strict subrange of its private
 * resource, next to a shared band, a plain data band, a scrubbed data band,
 * and a device. */
#define SCRUB (RW | WT_MEMORY_ATTR_RESTART_CLEAR)
static const wt_memory_resource_t g_res[] = {
    { 0x0E100000u, 0x100000u, RX | WT_MEMORY_ATTR_SHARED, 3u },
    { 0x0E240000u, 0x10000u, SCRUB, 0u },
    { 0x0E300000u, 0x40000u, RW | WT_MEMORY_ATTR_SHARED, 1u },
    { 0x0E260000u, 0x2000u, RW, 0u },
    { 0x0E270000u, 0x1000u, SCRUB, 0u },
    { 0x09000000u, 0x1000u, SCRUB | WT_MEM_ATTR_DEVICE, 0u }
};

static void stack_band_rows(void)
{
    wt_domain_descriptor_t d;
    wt_memory_region_t band;
    size_t i;
    unsigned int mask = 0u;

    (void)memset(&d, 0, sizeof(d));
    d.domain_class = WT_DOMAIN_CLASS_SECURE_PARTITION;
    d.memory_resources = g_res;
    d.memory_resource_count = sizeof(g_res) / sizeof(g_res[0]);
    d.stack_base = 0x0E244000u;
    d.stack_size = 0x4000u;
    check(wt_domain_stack_band(&d, &band) == 0 && band.base == 0x0E240000u &&
          band.size == 0x10000u && band.attributes == RW,
          "a declared stack inside a larger private resource maps the whole resource the scheduler seeds");
    for (i = 0u; i < d.memory_resource_count; i++) {
        if (wt_domain_spm_band(&d, i, &band) == 0) {
            mask |= 1u << i;
        }
    }
    check(mask == ((1u << 1) | (1u << 4)),
          "the SPMC maps the stack resource and a scrubbed private band, never a shared, plain, or device one");
    d.stack_base = 0x0E300000u;
    check(wt_domain_stack_band(&d, &band) == -1,
          "a declared stack only a shared band holds has no stack band");
    d.stack_size = 0u;
    check(wt_domain_stack_band(&d, &band) == 0 && band.base == 0x0E270000u,
          "with no declared stack the last private writable resource is the stack");
}

int main(void)
{
    uint64_t spm;
    uint64_t sp0;
    uint64_t sp1;
    size_t used;
    unsigned int switches;
    unsigned int fails;
    size_t built;
    unsigned int tlbis;
    uint32_t attrs;

    printf("WT-PORT-0014 (AArch64 domain operations)\n");
    stack_band_rows();

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

    switches = g_switches;
    wt_arch_program_sp_thread_domain(g_sp_shared, 2u);
    check(g_fails == 2u && g_switches == switches + 1u &&
          (wt_domain_current_ttbr0() >> 48) == 3u && wt_domain_tables_built() == 3u,
          "a partition region covering a shareable fill entry replaces it (ASID 3)");

    switches = g_switches;
    wt_arch_program_sp_thread_domain(g_sp_partial, 2u);
    check(g_fails == 3u && g_last_fail == WT_DOMAIN_FAIL_BUILD &&
          g_switches == switches && wt_domain_tables_built() == 3u,
          "partial cover of a shareable fill entry still fails the build");

    attrs = 0u;
    check(wt_domain_get_permissions(g_sp0, 2u, 0x0E201000u, &attrs) ==
              WT_TABLES_OK && attrs == RX,
          "a partition reads back its code page as read-execute");
    check(wt_domain_set_permissions(g_sp0, 2u, 0x0E201000u, 1u, RW) ==
              WT_TABLES_OK && g_tlbis == 1u && g_tlbi_asid == 1u &&
          wt_domain_get_permissions(g_sp0, 2u, 0x0E201000u, &attrs) ==
              WT_TABLES_OK && attrs == RW,
          "re-permissioning an owned page invalidates exactly that domain's ASID");
    check(wt_domain_set_permissions(g_sp0, 2u, 0x0E400000u, 1u, RW) ==
              WT_TABLES_ERROR_UNMAPPED &&
          wt_domain_set_permissions(g_sp0, 2u, 0x0E203000u, 2u, RW) ==
              WT_TABLES_ERROR_UNMAPPED &&
          wt_domain_set_permissions(g_sp0, 2u, 0x0E000000u, 1u, RW) ==
              WT_TABLES_ERROR_UNMAPPED && g_tlbis == 1u,
          "another partition's page, a range past the region end, and SPM memory are refused");
    check(wt_domain_get_permissions(g_sp0, 2u, 0x0E201001u, &attrs) ==
              WT_TABLES_ERROR_ALIGN,
          "a base address off its translation granule is refused (DEN0140 Table 2.37)");
    check(wt_domain_set_permissions(g_bad, 1u, 0x0E000000u, 1u, RW) ==
              WT_TABLES_ERROR_ARGUMENT &&
          wt_domain_get_permissions(g_sp0, 2u, 0x0E201000u, NULL) ==
              WT_TABLES_ERROR_ARGUMENT,
          "a domain that was never built and a NULL result are refused");
    check(wt_domain_owner_hold(g_sp0, 2u, 0x0E201000u, 1u, 0) == WT_TABLES_OK &&
          wt_domain_get_permissions(g_sp0, 2u, 0x0E201000u, &attrs) ==
              WT_TABLES_OK && attrs == 0u &&
          wt_domain_owner_release(g_sp0, 2u, 0x0E201000u, 1u) == WT_TABLES_OK &&
          wt_domain_get_permissions(g_sp0, 2u, 0x0E201000u, &attrs) ==
              WT_TABLES_OK && attrs == RW,
          "a page a transaction holds reads back as no access, and its own access once released");
    tlbis = g_tlbis;
    check(wt_domain_owner_hold(g_sp0, 2u, 0x0E201000u, 1u, 1) == WT_TABLES_OK &&
          wt_domain_owner_withdraw(g_sp0, 2u, 0x0E201000u, 1u) ==
              WT_TABLES_OK && g_tlbis == tlbis + 2u &&
          wt_domain_get_permissions(g_sp0, 2u, 0x0E201000u, &attrs) ==
              WT_TABLES_OK && attrs == 0u &&
          wt_domain_owner_release(g_sp0, 2u, 0x0E201000u, 1u) == WT_TABLES_OK &&
          wt_domain_get_permissions(g_sp0, 2u, 0x0E201000u, &attrs) ==
              WT_TABLES_OK && attrs == RW,
          "a page held for reading can be withdrawn to no access, invalidating the ASID, and is released as it was");
    switches = g_switches;
    check(g_syncs == 0u && wt_domain_current_ttbr0() != sp0 &&
          wt_domain_set_permissions(g_sp0, 2u, 0x0E201000u, 1u, RX) ==
              WT_TABLES_OK &&
          g_syncs == 1u && g_sync_va == 0x0E201000u &&
          g_sync_size == WT_TABLES_PAGE_SIZE && g_sync_ttbr0 == sp0 &&
          g_switches == switches + 2u &&
          g_switched_to == wt_domain_current_ttbr0(),
          "making a page executable syncs the instruction cache for it under its own table, then switches back");
    check(wt_domain_set_permissions(g_sp0, 2u, 0x0E201000u, 1u, RW) ==
              WT_TABLES_OK &&
          wt_domain_owner_hold(g_sp0, 2u, 0x0E202000u, 1u, 0) == WT_TABLES_OK &&
          wt_domain_owner_release(g_sp0, 2u, 0x0E202000u, 1u) ==
              WT_TABLES_OK && g_syncs == 1u,
          "a data page made or given back execute-never needs no instruction cache sync");

    fails = g_fails;
    switches = g_switches;
    built = wt_domain_tables_built();
    wt_arch_program_sp_thread_domain(g_sp_owned_cover, 1u);
    check(g_fails == fails + 1u && g_last_fail == WT_DOMAIN_FAIL_BUILD &&
          g_switches == switches && wt_domain_tables_built() == built,
          "a region wider than an owned band never takes it over: the build fails");
    wt_arch_program_sp_thread_domain(g_sp_owned_exact, 1u);
    check(g_fails == fails + 1u && g_switches == switches + 1u &&
          wt_domain_tables_built() == built + 1u &&
          wt_domain_page_owned(g_sp_owned_exact, 1u, 0x0E501000u) != 0,
          "the region that is exactly the owned band takes it over at EL0");
    owner_rows();
    capacity_rows();

    check(wt_domain_pool_pages_used() <= POOL_PAGES, "pool accounting stays inside the pool");

    printf("aarch64_domain: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
