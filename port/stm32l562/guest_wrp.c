/* guest_wrp.c
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

#include <stddef.h>
#include <stdint.h>

#include "wolftrust/platform.h"
#include "wolftrust/guest_verify.h"

#include "memory_map.h"
#include "stm32l562_regs.h"

/* Write protection is two page-range areas per bank (WRPxAR/WRPxBR, inclusive
 * start and end pages); an area is active when its end is not below its
 * start. The window is protected only when every page it spans is covered. */
static int wt_wrp_area_covers(uint32_t area, uint32_t page)
{
    uint32_t start = area & WT_FLASH_WRP_PSTRT_MASK;
    uint32_t end = (area >> WT_FLASH_WRP_PEND_SHIFT) & WT_FLASH_WRP_PSTRT_MASK;

    return (start <= end && page >= start && page <= end) ? 1 : 0;
}

int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size)
{
    uintptr_t bank_base;
    uint32_t area_a;
    uint32_t area_b;
    uint32_t first;
    uint32_t last;
    uint32_t page;
    uint32_t optr;
    int upper;

    /* Single-bank mode has 4 KiB pages and other WRP areas than this map. */
    optr = WT_FLASH_OPTR;
    if ((optr & WT_FLASH_OPTR_DBANK) == 0u) {
        return WT_GUEST_VERIFY_ERROR_WRP;
    }
    /* Bounds by subtraction, so no end address can wrap past the check. */
    if (window_size == 0u || window_base < WT_FLASH_NS_BASE ||
            window_base - WT_FLASH_NS_BASE >= WT_FLASH_SIZE ||
            window_size > WT_FLASH_SIZE - (window_base - WT_FLASH_NS_BASE)) {
        return WT_GUEST_VERIFY_ERROR_WRP;
    }
    upper = (window_base >= WT_FLASH_NS_BASE + WT_FLASH_BANK_SIZE) ? 1 : 0;
    bank_base = (upper != 0) ? WT_FLASH_NS_BASE + WT_FLASH_BANK_SIZE :
                               WT_FLASH_NS_BASE;
    if (window_size > WT_FLASH_BANK_SIZE - (window_base - bank_base)) {
        return WT_GUEST_VERIFY_ERROR_WRP;
    }
    /* SWAP_BANK maps the upper address range onto bank 1's option bytes. */
    if ((optr & WT_FLASH_OPTR_SWAP_BANK) != 0u) {
        upper = (upper != 0) ? 0 : 1;
    }
    area_a = (upper != 0) ? WT_FLASH_WRP2AR : WT_FLASH_WRP1AR;
    area_b = (upper != 0) ? WT_FLASH_WRP2BR : WT_FLASH_WRP1BR;
    first = (uint32_t)((window_base - bank_base) / WT_FLASH_PAGE_SIZE);
    last = (uint32_t)((window_base + window_size - 1u - bank_base) /
                      WT_FLASH_PAGE_SIZE);
    for (page = first; page <= last; ++page) {
        if (wt_wrp_area_covers(area_a, page) == 0 &&
                wt_wrp_area_covers(area_b, page) == 0) {
            return WT_GUEST_VERIFY_ERROR_WRP;
        }
    }
    return WT_GUEST_VERIFY_OK;
}
