/* el3_board.c
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

/* Board bring-up the EL3 monitor asks of the Versal port. The PLM has
 * already configured the PS UARTs on silicon and on versal-virt. */

#include "memory_map.h"
#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/pl011.h"
#include "wolftrust/arch/aarch64/tables.h"

/* The SPMC owns the GIC: distributor and the redistributor frames of the
 * two APU cores beside the console. */
static const wt_memory_region_t g_device_regions[] = {
    { WT_UART_S_BASE, 0x1000u,
      WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE },
    { WT_GICD_BASE, 0x10000u,
      WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE },
    { WT_GICR_BASE, 0x80000u,
      WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE }
};

void wt_platform_board_init(void)
{
#if !defined(WT_UART_SKIP_INIT) || (WT_UART_SKIP_INIT == 0)
    wt_pl011_init(WT_UART_S_BASE, WT_UART_CLOCK_HZ, WT_UART_BAUD);
#endif
}

const wt_memory_region_t* wt_platform_board_device_regions(size_t* count)
{
    *count = sizeof(g_device_regions) / sizeof(g_device_regions[0]);
    return g_device_regions;
}
