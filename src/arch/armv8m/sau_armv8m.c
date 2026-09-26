/* sau_armv8m.c
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


/* Armv8-M Security Attribution Unit programming from a port-supplied region
 * table. */

#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/core_regs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static void wt_sau_set_region(uint32_t rnr,
                              uint32_t base,
                              uint32_t limit_inclusive,
                              bool nsc)
{
    WT_SAU_RNR = rnr;
    WT_SAU_RBAR = base & 0xFFFFFFE0u;
    WT_SAU_RLAR = (limit_inclusive & 0xFFFFFFE0u) | (nsc ? 2u : 0u) | 1u;
}

void wt_armv8m_sau_program_region(uint32_t rnr, uint32_t base,
                                  uint32_t limit_inclusive, bool nsc,
                                  bool enable)
{
    /* Reprogram one region while the SAU stays enabled. The Secure monitor
     * executes from the bit-28-set Secure alias, which no Non-secure region
     * covers, so a guest-RAM region edit cannot reclassify running code; a
     * disable clears ENABLE so the region stops matching. */
    WT_SAU_RNR = rnr;
    WT_SAU_RLAR = 0u;
    if (enable) {
        WT_SAU_RBAR = base & 0xFFFFFFE0u;
        WT_SAU_RLAR = (limit_inclusive & 0xFFFFFFE0u) | (nsc ? 2u : 0u) | 1u;
    }
    wt_dsb();
    wt_isb();
}

void wt_armv8m_sau_init(const wt_armv8m_sau_region_t* regions, size_t count)
{
    uint32_t region;
    uint32_t regionCount = WT_SAU_TYPE & 0xFFu;
    size_t i;

    /* Disable the SAU before changing any region pair. Updating RBAR while
     * the previous RLAR remains enabled creates a transient region spanning
     * the new base and old limit. That can reclassify the currently executing
     * Secure image as Non-secure before the matching RLAR write completes. */
    WT_SAU_CTRL = 0u;
    wt_dsb();
    wt_isb();

    /* A preceding Secure stage may leave enabled regions behind. Clear every
     * implemented slot before installing the port's complete attribution
     * map so no higher-priority stale region can override it. */
    for (region = 0u; region < regionCount; region++) {
        WT_SAU_RNR = region;
        WT_SAU_RLAR = 0u;
    }

    for (i = 0u; i < count; ++i) {
        wt_sau_set_region((uint32_t)i, regions[i].base, regions[i].limit,
                          regions[i].nsc);
    }
    WT_SAU_CTRL = 1u;
    wt_dsb();
    wt_isb();
}
