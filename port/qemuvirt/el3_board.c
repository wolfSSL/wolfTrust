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

/* Board bring-up the EL3 monitor asks of the QEMU virt port. */

#include "memory_map.h"
#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/pl011.h"
#include "wolftrust/arch/aarch64/tables.h"

/* The machine's Secure PL061 (secure=on): its line 1 is wired to the board's
 * gpio-restart, a whole-machine reset. GPIODATA writes only the bits the
 * address selects (offset bits [9:2]). */
#define WT_SECURE_GPIO_BASE     0x090B0000u
#define WT_PL061_DIR            0x400u
#define WT_GPIO_RESET_LINE      (1u << 1)

/* The SPMC owns the GIC: distributor, the GICv2 CPU interface, and the
 * GICv3 redistributor frames (up to eight cores) beside the console. */
static const wt_memory_region_t g_device_regions[] = {
    { WT_UART_S_BASE, 0x1000u,
      WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE },
    { WT_GICD_BASE, 0x10000u,
      WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE },
    { WT_GICC_BASE, 0x10000u,
      WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE },
    { WT_GICR_BASE, 0x100000u,
      WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE }
};

void wt_platform_board_init(void)
{
#if !defined(WT_UART_SKIP_INIT) || (WT_UART_SKIP_INIT == 0)
    wt_pl011_init(WT_UART_S_BASE, WT_UART_CLOCK_HZ, WT_UART_BAUD);
#endif
}

void wt_platform_board_system_reset(void)
{
    volatile uint32_t* dir =
        (volatile uint32_t*)(uintptr_t)(WT_SECURE_GPIO_BASE + WT_PL061_DIR);
    volatile uint32_t* data = (volatile uint32_t*)(uintptr_t)
        (WT_SECURE_GPIO_BASE + (WT_GPIO_RESET_LINE << 2));

    *dir |= WT_GPIO_RESET_LINE;
    *data = WT_GPIO_RESET_LINE;
    for (;;) {
        __asm__ volatile("wfi" ::: "memory");
    }
}

const wt_memory_region_t* wt_platform_board_device_regions(size_t* count)
{
    *count = sizeof(g_device_regions) / sizeof(g_device_regions[0]);
    return g_device_regions;
}
