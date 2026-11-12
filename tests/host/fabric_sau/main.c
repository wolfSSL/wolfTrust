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

/* The attribution contract of the shared SAU guest-window backend
 * (port/common/armv8m/fabric_sau.c, WT-PORT-0008) over a model of the SAU:
 * a static table that leaves no dynamic region, a misaligned, overflowing or
 * overlapping window, one past the SAU's capacity, and a programming that
 * does not read back are each refused by a panic, while the production
 * window algorithm (src/fabric_windows.c) opens exactly the arriving guest's
 * windows in the regions above the static table. */

#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fabric_sau.h"
#include "memory_map.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/fabric_windows.h"
#include "wolftrust/platform.h"

#define SAU_REGIONS 8u

typedef struct model_region {
    uint32_t base;
    uint32_t limit;
    bool nsc;
    bool enabled;
} model_region_t;

static int checks;
static int failures;
static model_region_t g_regions[SAU_REGIONS];
static uint32_t g_region_count = SAU_REGIONS;
static uint32_t g_programs;
static uint32_t g_syncs;
static int g_drop_next_program;
static jmp_buf g_panic;
static int g_panics;

extern volatile uint32_t g_wt_sau_refusals;

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

uint32_t wt_armv8m_sau_region_count(void)
{
    return g_region_count;
}

void wt_armv8m_sau_program_region(uint32_t rnr, uint32_t base,
                                  uint32_t limit_inclusive, bool nsc,
                                  bool enable)
{
    g_programs++;
    if (rnr >= SAU_REGIONS) {
        return;
    }
    if (g_drop_next_program) {
        /* The register did not take: the region keeps its old state. */
        g_drop_next_program = 0;
        return;
    }
    g_regions[rnr].base = base & 0xFFFFFFE0u;
    g_regions[rnr].limit = limit_inclusive & 0xFFFFFFE0u;
    g_regions[rnr].nsc = nsc;
    g_regions[rnr].enabled = enable;
}

int wt_armv8m_sau_region_is(uint32_t rnr, uint32_t base,
                            uint32_t limit_inclusive, bool nsc, bool enabled)
{
    if (rnr >= SAU_REGIONS) {
        return 0;
    }
    if (!enabled) {
        return !g_regions[rnr].enabled;
    }
    return g_regions[rnr].enabled && g_regions[rnr].nsc == nsc &&
           g_regions[rnr].base == (base & 0xFFFFFFE0u) &&
           g_regions[rnr].limit == (limit_inclusive & 0xFFFFFFE0u);
}

void wt_armv8m_sau_sync(void)
{
    g_syncs++;
}

void wt_platform_panic(void)
{
    g_panics++;
    longjmp(g_panic, 1);
}

/* Runs fn; nonzero when it panicked. */
static int panics(void (*fn)(void))
{
    int before = g_panics;

    if (setjmp(g_panic) == 0) {
        fn();
    }
    return g_panics != before;
}

static void model_reset(uint32_t regions)
{
    (void)memset(g_regions, 0, sizeof(g_regions));
    g_region_count = regions;
    g_programs = 0u;
    g_syncs = 0u;
    g_drop_next_program = 0;
}

static wt_memory_window_t window(uintptr_t base, size_t size)
{
    wt_memory_window_t w;

    (void)memset(&w, 0, sizeof(w));
    w.base = base;
    w.size = size;
    w.attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    return w;
}

static void apply(const wt_memory_window_t* windows, size_t count)
{
    wt_fabric_apply_windows(&wt_fabric_sau_backend, windows, count);
}

static void try_misaligned(void)
{
    wt_memory_window_t w = window(WT_RAM_NS_BASE + 16u, 0x1000u);

    apply(&w, 1u);
}

static void try_odd_size(void)
{
    wt_memory_window_t w = window(WT_RAM_NS_BASE, 0x1010u);

    apply(&w, 1u);
}

static void try_overflow(void)
{
    /* Inside no extent, so it reaches the backend directly: a window whose
     * end runs past the top of memory. */
    wt_fabric_sau_backend.open_window(0xFFFFFFE0u, 0x40u);
}

static void try_overlap(void)
{
    wt_memory_window_t w[2];

    w[0] = window(WT_RAM_NS_BASE, 0x2000u);
    w[1] = window(WT_RAM_NS_BASE + 0x1000u, 0x2000u);
    apply(w, 2u);
}

static void try_too_many(void)
{
    wt_memory_window_t w[SAU_REGIONS];
    size_t i;

    for (i = 0u; i < SAU_REGIONS; i++) {
        w[i] = window(WT_RAM_NS_BASE + i * 0x1000u, 0x800u);
    }
    apply(w, SAU_REGIONS);
}

static void try_dropped(void)
{
    wt_memory_window_t w = window(WT_RAM_NS_BASE, 0x1000u);

    g_drop_next_program = 1;
    apply(&w, 1u);
}

static void try_two(void)
{
    wt_memory_window_t w[2];

    w[0] = window(WT_GUEST0_RAM_BASE, WT_GUEST0_RAM_SIZE);
    w[1] = window(WT_GUEST0_RAM_BASE + WT_GUEST0_RAM_SIZE, 0x400u);
    apply(w, 2u);
}

static void try_close(void)
{
    apply(NULL, 0u);
}

int main(void)
{
    const size_t statics = 3u;
    uint32_t refusals;
    size_t i;

    printf("RUN: unit/fabric_sau\n");

    model_reset(statics);
    check(wt_fabric_sau_init(statics) != 0,
          "a static table using every region leaves no dynamic window: refused");
    model_reset(SAU_REGIONS);
    check(wt_fabric_sau_init(SAU_REGIONS) != 0,
          "a static table past the SAU's regions is refused");
    check(wt_fabric_sau_init(statics) == 0,
          "three static regions leave five dynamic ones");

    refusals = g_wt_sau_refusals;
    check(panics(try_misaligned) && g_wt_sau_refusals == refusals + 1u,
          "a window not on the 32-byte SAU granule is refused");
    check(g_regions[statics].enabled == false,
          "a refused window never reaches the SAU");
    refusals = g_wt_sau_refusals;
    check(panics(try_odd_size) && g_wt_sau_refusals == refusals + 1u,
          "a window whose size is not a granule multiple is refused");
    refusals = g_wt_sau_refusals;
    check(panics(try_overflow) && g_wt_sau_refusals == refusals + 1u,
          "a window running past the top of memory is refused");
    check(g_regions[statics].enabled == false,
          "the overflowing window never reached the SAU");
    refusals = g_wt_sau_refusals;
    check(panics(try_overlap) && g_wt_sau_refusals == refusals + 1u,
          "a window overlapping an open one is refused");
    check(g_regions[statics].enabled && !g_regions[statics + 1u].enabled,
          "the first window stayed open, the overlapping one never opened");
    refusals = g_wt_sau_refusals;
    check(panics(try_too_many) && g_wt_sau_refusals == refusals + 1u,
          "a sixth window exceeds the five dynamic regions: refused");
    for (i = statics; i < SAU_REGIONS; i++) {
        if (!g_regions[i].enabled) {
            break;
        }
    }
    check(i == SAU_REGIONS, "every dynamic region was used before the refusal");
    refusals = g_wt_sau_refusals;
    check(panics(try_dropped) && g_wt_sau_refusals == refusals + 1u,
          "a programming that does not read back is refused");

    model_reset(SAU_REGIONS);
    check(wt_fabric_sau_init(statics) == 0, "init again");
    check(!panics(try_two), "two disjoint windows inside the extent open");
    check(g_regions[statics].enabled &&
              g_regions[statics].base == WT_GUEST0_RAM_BASE &&
              g_regions[statics].limit ==
                  WT_GUEST0_RAM_BASE + WT_GUEST0_RAM_SIZE - 32u &&
              !g_regions[statics].nsc,
          "the first window is region 3 with the guest's bounds, not NSC");
    check(g_regions[statics + 1u].enabled &&
              g_regions[statics + 1u].base ==
                  WT_GUEST0_RAM_BASE + WT_GUEST0_RAM_SIZE,
          "the second window is region 4");
    check(!g_regions[statics + 2u].enabled && g_syncs >= 1u,
          "the remaining dynamic regions stay closed and the edit is committed");
    check(!panics(try_close), "a dispatch with no windows closes every region");
    for (i = statics; i < SAU_REGIONS; i++) {
        if (g_regions[i].enabled) {
            break;
        }
    }
    check(i == SAU_REGIONS, "every dynamic region is disabled after close_all");
    check(!g_regions[0].enabled && !g_regions[1].enabled &&
              !g_regions[2].enabled && g_programs > 0u,
          "the static regions were never touched by the backend");

    if (failures == 0) {
        printf("PASS: unit/fabric_sau (%d checks)\n", checks);
        return 0;
    }
    printf("FAIL: unit/fabric_sau (%d/%d failed)\n", failures, checks);
    return 1;
}
