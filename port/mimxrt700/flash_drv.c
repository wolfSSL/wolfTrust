/* flash_drv.c
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

/* MIMXRT700 XSPI0 NOR primitives (flash_port.h): reads through the Secure
 * XIP alias, program and erase through xspi_nor.c on the Non-secure
 * aperture numbering it takes. A read of a faulting phrase through the
 * alias is not contained here; that behaviour is not established. */

#include <stdint.h>
#include <string.h>

#include "flash_port.h"
#include "memory_map.h"
#include "xspi_nor.h"
#include "wolftrust/static_assert.h"
#include "wolfhsm/wh_error.h"

WT_STATIC_ASSERT(WT_XSPI_NOR_UNIT == WT_FLASH_PROGRAM_UNIT &&
                 WT_XSPI_NOR_SECTOR == WT_FLASH_SECTOR_SIZE,
                 "the NOR driver's geometry must match memory_map.h");

/* Array reads go through this so the host model can stand behind it. */
#ifndef WT_FLASH_RD8
#define WT_FLASH_RD8(address) (*(const volatile uint8_t *)(address))
#endif

/* Last NOR driver failure, read over the debug port by the harness. */
volatile int32_t g_wt_nor_last_error __attribute__((used));

static uint32_t wt_flash_device_address(uintptr_t s_addr)
{
    return (uint32_t)(s_addr - WT_FLASH_S_ALIAS_BASE + WT_FLASH_NS_BASE);
}

static int wt_flash_nor_result(int rc)
{
    if (rc != WT_XSPI_NOR_OK) {
        g_wt_nor_last_error = (int32_t)rc;
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

int wt_port_flash_read(uintptr_t s_addr, uint8_t *dst, uint32_t size)
{
    uint32_t i;

    for (i = 0u; i < size; i++) {
        dst[i] = WT_FLASH_RD8(s_addr + i);
    }
    return WH_ERROR_OK;
}

int wt_port_flash_program(uintptr_t s_addr, const uint8_t *src, uint32_t size)
{
    return wt_flash_nor_result(
        wt_xspi_nor_program(wt_flash_device_address(s_addr), src, size));
}

int wt_port_flash_erase(uintptr_t s_addr, uint32_t size)
{
    return wt_flash_nor_result(
        wt_xspi_nor_erase(wt_flash_device_address(s_addr), size));
}

int wt_port_flash_blank_check(uintptr_t s_addr, uint32_t size)
{
    uint32_t i;

    for (i = 0u; i < size; i++) {
        if (WT_FLASH_RD8(s_addr + i) != 0xFFu) {
            return WH_ERROR_NOTBLANK;
        }
    }
    return WH_ERROR_OK;
}

/* Every NOR command completes before xspi_nor.c returns, with the read cache
 * flushed, so nothing is left in flight to wait for. */
void wt_port_flash_quiesce(void)
{
}

#if defined(WT_REMEASURE_PROBE)
int wt_port_flash_probe_tamper(uintptr_t ns_addr)
{
    return wt_flash_nor_result(wt_xspi_nor_probe_tamper((uint32_t)ns_addr));
}
#endif
