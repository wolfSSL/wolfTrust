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

/* MCXN947 internal flash primitives (flash_port.h): reads through the
 * Secure alias, program, erase and blank checks through the boot ROM flash
 * API (rom_flash.c), which takes flash offsets. Only the update partition
 * and the Secure stores may be programmed or erased. A read of an erased
 * or faulting phrase through the alias is not contained here; that
 * behaviour is not established. */

#include <stdint.h>
#include <string.h>

#include "flash_port.h"
#include "memory_map.h"
#include "rom_flash.h"
#include "wolfhsm/wh_error.h"

/* Array reads go through this so the host model can stand behind it. */
#ifndef WT_FLASH_RD8
#define WT_FLASH_RD8(address) (*(const volatile uint8_t *)(address))
#endif

typedef struct wt_flash_window {
    uint32_t offset;
    uint32_t size;
} wt_flash_window_t;

static const wt_flash_window_t g_wt_flash_writable[] = {
    { WT_FWU_UPDATE_FLASH_BASE_S - WT_FLASH_S_ALIAS_BASE,
      WT_FWU_UPDATE_FLASH_SIZE },
    { WT_HSM_NVM_FLASH_BASE_S - WT_FLASH_S_ALIAS_BASE, WT_HSM_NVM_FLASH_SIZE },
    { WT_CONF_NVM_FLASH_BASE_S - WT_FLASH_S_ALIAS_BASE, WT_CONF_NVM_FLASH_SIZE },
};

static uint32_t wt_flash_offset(uintptr_t s_addr)
{
    return (uint32_t)(s_addr - WT_FLASH_S_ALIAS_BASE);
}

static int wt_flash_writable(uint32_t offset, uint32_t size)
{
    size_t i;

    for (i = 0u; i < sizeof(g_wt_flash_writable) /
                     sizeof(g_wt_flash_writable[0]); i++) {
        const wt_flash_window_t *w = &g_wt_flash_writable[i];

        if (offset >= w->offset && size <= w->size &&
                offset - w->offset <= w->size - size) {
            return 1;
        }
    }
    return 0;
}

static int wt_flash_rom_result(int rc)
{
    if (rc == WT_ROM_FLASH_OK) {
        return WH_ERROR_OK;
    }
    if (rc == WT_ROM_FLASH_ERR_NOTBLANK) {
        return WH_ERROR_NOTBLANK;
    }
    if (rc == WT_ROM_FLASH_ERR_ARGS) {
        return WH_ERROR_BADARGS;
    }
    return WH_ERROR_ABORTED;
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
    uint32_t offset = wt_flash_offset(s_addr);

    if (!wt_flash_writable(offset, size)) {
        return WH_ERROR_BADARGS;
    }
    return wt_flash_rom_result(wt_rom_flash_program(offset, src, size));
}

int wt_port_flash_erase(uintptr_t s_addr, uint32_t size)
{
    uint32_t offset = wt_flash_offset(s_addr);

    if (!wt_flash_writable(offset, size)) {
        return WH_ERROR_BADARGS;
    }
    return wt_flash_rom_result(wt_rom_flash_erase(offset, size));
}

/* The ROM verifies an erase; a mapped read of an erased phrase is not relied
 * on. */
int wt_port_flash_blank_check(uintptr_t s_addr, uint32_t size)
{
    return wt_flash_rom_result(wt_rom_flash_blank(wt_flash_offset(s_addr),
                                                  size));
}

/* Every ROM call completes before it returns, with the code cache cleared,
 * so nothing is left in flight to wait for. */
void wt_port_flash_quiesce(void)
{
}

#if defined(WT_REMEASURE_PROBE)
/* Probe-only: the one write outside the writable windows. */
int wt_port_flash_probe_tamper(uintptr_t ns_addr)
{
    uint8_t block[WT_FLASH_PROGRAM_UNIT];
    uint32_t offset = (uint32_t)(ns_addr - WT_FLASH_NS_BASE);
    int rc;

    if ((offset % WT_FLASH_SECTOR_SIZE) != 0u) {
        return WH_ERROR_BADARGS;
    }
    rc = wt_rom_flash_erase(offset, WT_FLASH_SECTOR_SIZE);
    if (rc == WT_ROM_FLASH_OK) {
        (void)memset(block, 0x00, sizeof(block));
        rc = wt_rom_flash_program(offset, block, (uint32_t)sizeof(block));
    }
    return wt_flash_rom_result(rc);
}
#endif
