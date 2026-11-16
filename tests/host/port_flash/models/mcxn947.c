/* mcxn947.c
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

/* The ROM flash driver's interface (rom_flash.h) over the flash array, so
 * the production flash_drv.c links against the model; the driver itself has
 * its own suite (tests/host/mcxn947_flash). Offsets are flash offsets. */

#include <stddef.h>
#include "flash_array.h"
#include "memory_map.h"
#include "rom_flash.h"

static uintptr_t s_alias(uint32_t offset)
{
    return (uintptr_t)offset + WT_FLASH_S_ALIAS_BASE;
}

static int rom_result(int rc)
{
    switch (rc) {
        case FA_OK:
            return WT_ROM_FLASH_OK;
        case FA_UNMAPPED:
            return WT_ROM_FLASH_ERR_ARGS;
        case FA_TWICE:
            return WT_ROM_FLASH_ERR_NOTBLANK;
        default:
            return WT_ROM_FLASH_ERR_ROM;
    }
}

int wt_rom_flash_init(void)
{
    return WT_ROM_FLASH_OK;
}

int wt_rom_flash_program(uint32_t offset, const uint8_t *data, uint32_t size)
{
    if ((offset % WT_FLASH_PHRASE_SIZE) != 0u ||
            (size % WT_FLASH_PHRASE_SIZE) != 0u) {
        return WT_ROM_FLASH_ERR_ARGS;
    }
    return rom_result(fa_program(s_alias(offset), data, size));
}

int wt_rom_flash_erase(uint32_t offset, uint32_t size)
{
    if ((offset % WT_FLASH_SECTOR_SIZE) != 0u ||
            (size % WT_FLASH_SECTOR_SIZE) != 0u) {
        return WT_ROM_FLASH_ERR_ARGS;
    }
    return rom_result(fa_erase(s_alias(offset), size));
}

int wt_rom_flash_blank(uint32_t offset, uint32_t size)
{
    return rom_result(fa_blank(s_alias(offset), size));
}

uint32_t wt_rom_flash_last_status(void)
{
    return 0u;
}

uint8_t wt_mock_flash_rd8(uintptr_t address)
{
    const uint8_t* p = fa_map(address, 1u);

    return (p == NULL) ? 0xFFu : *p;
}
