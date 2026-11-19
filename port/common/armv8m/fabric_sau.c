/* fabric_sau.c
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fabric_sau.h"
#include "memory_map.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/platform.h"

#define WT_SAU_GRANULE   32u
#define WT_SAU_MAX_DYN   8u

typedef struct wt_sau_window {
    uint32_t base;
    uint32_t limit;
} wt_sau_window_t;

static uint32_t g_dyn_first;
static uint32_t g_dyn_last;
static uint32_t g_dyn_next;
static wt_sau_window_t g_open[WT_SAU_MAX_DYN];
/* Refused window programmings, read over the debug port. */
volatile uint32_t g_wt_sau_refusals __attribute__((used));

int wt_fabric_sau_init(size_t static_count)
{
    uint32_t regions = wt_armv8m_sau_region_count();

    if (static_count >= regions || regions > WT_SAU_MAX_DYN ||
            regions - static_count > WT_SAU_MAX_DYN) {
        return -1;
    }
    g_dyn_first = (uint32_t)static_count;
    g_dyn_last = regions - 1u;
    g_dyn_next = g_dyn_first;
    return 0;
}

static void wt_sau_refuse(void)
{
    g_wt_sau_refusals++;
    wt_platform_panic();
}

static void wt_sau_close_all(void)
{
    uint32_t rnr;

    for (rnr = g_dyn_first; rnr <= g_dyn_last; ++rnr) {
        wt_armv8m_sau_program_region(rnr, 0u, 0u, false, false);
        if (!wt_armv8m_sau_region_is(rnr, 0u, 0u, false, false)) {
            wt_sau_refuse();
        }
    }
    g_dyn_next = g_dyn_first;
}

static void wt_sau_open_window(uintptr_t base, size_t size)
{
    uint32_t limit;
    uint32_t i;

    if (size == 0u || (base % WT_SAU_GRANULE) != 0u ||
            (size % WT_SAU_GRANULE) != 0u || base > 0xFFFFFFFFu - (size - 1u)) {
        wt_sau_refuse();
    }
    limit = (uint32_t)(base + size - 1u);
    for (i = g_dyn_first; i < g_dyn_next; ++i) {
        if (base <= g_open[i - g_dyn_first].limit &&
                g_open[i - g_dyn_first].base <= limit) {
            wt_sau_refuse();
        }
    }
    if (g_dyn_next > g_dyn_last) {
        wt_sau_refuse();
    }
    wt_armv8m_sau_program_region(g_dyn_next, (uint32_t)base, limit, false,
                                 true);
    if (!wt_armv8m_sau_region_is(g_dyn_next, (uint32_t)base, limit, false,
                                 true)) {
        wt_sau_refuse();
    }
    g_open[g_dyn_next - g_dyn_first].base = (uint32_t)base;
    g_open[g_dyn_next - g_dyn_first].limit = limit;
    ++g_dyn_next;
}

static void wt_sau_commit(void)
{
    wt_armv8m_sau_sync();
}

const wt_fabric_windows_t wt_fabric_sau_backend = {
    WT_RAM_NS_BASE,
    WT_RAM_NS_BASE + WT_PLATFORM_GUEST_STACK_WINDOW_SIZE,
    wt_sau_close_all,
    wt_sau_open_window,
    wt_sau_commit
};
