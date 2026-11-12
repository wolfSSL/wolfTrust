/* mimxrt700.c
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

/* The XSPI NOR driver's interface (xspi_nor.h) over the flash array, so the
 * production flash_drv.c links against the model; the driver itself has
 * its own suite (tests/host/rt700_xspi). Addresses are Non-secure. */

#include <string.h>

#include <stddef.h>
#include "flash_array.h"
#include "memory_map.h"
#include "xspi_nor.h"

static uintptr_t s_alias(uint32_t ns)
{
    return (uintptr_t)ns - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE;
}

static int nor_result(int rc)
{
    if (rc == FA_OK) {
        return WT_XSPI_NOR_OK;
    }
    return (rc == FA_UNMAPPED) ? WT_XSPI_NOR_ARGUMENT : WT_XSPI_NOR_DEVICE;
}

int wt_xspi_nor_erase(uint32_t address, uint32_t size)
{
    return nor_result(fa_erase(s_alias(address), size));
}

int wt_xspi_nor_program(uint32_t address, const uint8_t* data, uint32_t size)
{
    return nor_result(fa_program(s_alias(address), data, size));
}

int wt_xspi_nor_probe_tamper(uint32_t address)
{
    uint8_t zero[WT_XSPI_NOR_UNIT];
    int rc;

    if ((address & (WT_XSPI_NOR_SECTOR - 1u)) != 0u) {
        return WT_XSPI_NOR_ARGUMENT;
    }
    rc = fa_erase(s_alias(address), WT_XSPI_NOR_SECTOR);
    if (rc == FA_OK) {
        (void)memset(zero, 0, sizeof(zero));
        rc = fa_program(s_alias(address), zero, (uint32_t)sizeof(zero));
    }
    return nor_result(rc);
}

uint8_t wt_mock_flash_rd8(uintptr_t address)
{
    const uint8_t* p = fa_map(address, 1u);

    return (p == NULL) ? 0xFFu : *p;
}
