/* flash_array.c
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

#include <string.h>

#include "flash_array.h"
#include "memory_map.h"

#define FA_UNIT   WT_FLASH_PROGRAM_UNIT
#define FA_SECTOR WT_FLASH_SECTOR_SIZE

typedef struct fa_region {
    uintptr_t base;
    uint32_t size;
    uint8_t* bytes;
    uint8_t* programmed;
    uint32_t* sector_erases;
} fa_region_t;

static uint8_t g_fwu_bytes[WT_FWU_UPDATE_FLASH_SIZE];
static uint8_t g_fwu_programmed[WT_FWU_UPDATE_FLASH_SIZE / FA_UNIT];
static uint32_t g_fwu_sector_erases[WT_FWU_UPDATE_FLASH_SIZE / FA_SECTOR];
static uint8_t g_hsm_bytes[WT_HSM_NVM_FLASH_SIZE];
static uint8_t g_hsm_programmed[WT_HSM_NVM_FLASH_SIZE / FA_UNIT];
static uint32_t g_hsm_sector_erases[WT_HSM_NVM_FLASH_SIZE / FA_SECTOR];
static uint8_t g_conf_bytes[WT_CONF_NVM_FLASH_SIZE];
static uint8_t g_conf_programmed[WT_CONF_NVM_FLASH_SIZE / FA_UNIT];
static uint32_t g_conf_sector_erases[WT_CONF_NVM_FLASH_SIZE / FA_SECTOR];
static uint8_t g_guest_bytes[FA_SECTOR];
static uint8_t g_guest_programmed[FA_SECTOR / FA_UNIT];
static uint32_t g_guest_sector_erases[1];

static fa_region_t g_regions[] = {
    { WT_FWU_UPDATE_FLASH_BASE_S, WT_FWU_UPDATE_FLASH_SIZE, g_fwu_bytes,
      g_fwu_programmed, g_fwu_sector_erases },
    { WT_HSM_NVM_FLASH_BASE_S, WT_HSM_NVM_FLASH_SIZE, g_hsm_bytes,
      g_hsm_programmed, g_hsm_sector_erases },
    { WT_CONF_NVM_FLASH_BASE_S, WT_CONF_NVM_FLASH_SIZE, g_conf_bytes,
      g_conf_programmed, g_conf_sector_erases },
    { WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE), FA_SECTOR, g_guest_bytes,
      g_guest_programmed, g_guest_sector_erases },
};

static int g_blank_filled;
static uint32_t g_programs;
static uint32_t g_erases;
static uint32_t g_fail_program_after = 0xFFFFFFFFu;
static uint32_t g_fail_erase_after = 0xFFFFFFFFu;

static void fa_fill_blank(void)
{
    size_t i;

    if (g_blank_filled == 0) {
        for (i = 0u; i < sizeof(g_regions) / sizeof(g_regions[0]); i++) {
            (void)memset(g_regions[i].bytes, 0xFF, g_regions[i].size);
        }
        g_blank_filled = 1;
    }
}

static fa_region_t* fa_region(uintptr_t s_addr, uint32_t size)
{
    size_t i;

    fa_fill_blank();
    for (i = 0u; i < sizeof(g_regions) / sizeof(g_regions[0]); i++) {
        fa_region_t* r = &g_regions[i];

        if (s_addr >= r->base && size <= r->size &&
                s_addr - r->base <= r->size - size) {
            return r;
        }
    }
    return NULL;
}

uint8_t* fa_map(uintptr_t s_addr, uint32_t size)
{
    fa_region_t* r = fa_region(s_addr, size);

    return (r == NULL) ? NULL : r->bytes + (s_addr - r->base);
}

int fa_program(uintptr_t s_addr, const uint8_t* src, uint32_t size)
{
    fa_region_t* r = fa_region(s_addr, size);
    uint32_t offset;
    uint32_t i;

    if (r == NULL) {
        return FA_UNMAPPED;
    }
    g_programs++;
    if (g_fail_program_after == 0u) {
        return FA_INJECTED;
    }
    if (g_fail_program_after != 0xFFFFFFFFu) {
        g_fail_program_after--;
    }
    offset = (uint32_t)(s_addr - r->base);
    for (i = 0u; i < size; i += FA_UNIT) {
        if (r->programmed[(offset + i) / FA_UNIT] != 0u) {
            return FA_TWICE;
        }
    }
    for (i = 0u; i < size; i++) {
        r->bytes[offset + i] &= src[i];
    }
    for (i = 0u; i < size; i += FA_UNIT) {
        r->programmed[(offset + i) / FA_UNIT] = 1u;
    }
    return FA_OK;
}

int fa_erase(uintptr_t s_addr, uint32_t size)
{
    fa_region_t* r = fa_region(s_addr, size);
    uint32_t offset;
    uint32_t i;

    if (r == NULL) {
        return FA_UNMAPPED;
    }
    g_erases++;
    if (g_fail_erase_after == 0u) {
        return FA_INJECTED;
    }
    if (g_fail_erase_after != 0xFFFFFFFFu) {
        g_fail_erase_after--;
    }
    offset = (uint32_t)(s_addr - r->base);
    (void)memset(r->bytes + offset, 0xFF, size);
    (void)memset(r->programmed + offset / FA_UNIT, 0, size / FA_UNIT);
    for (i = 0u; i < size; i += FA_SECTOR) {
        r->sector_erases[(offset + i) / FA_SECTOR]++;
    }
    return FA_OK;
}

int fa_blank(uintptr_t s_addr, uint32_t size)
{
    const uint8_t* p = fa_map(s_addr, size);
    uint32_t i;

    if (p == NULL) {
        return FA_UNMAPPED;
    }
    for (i = 0u; i < size; i++) {
        if (p[i] != 0xFFu) {
            return FA_TWICE;
        }
    }
    return FA_OK;
}

void fa_fail_programs_after(uint32_t count)
{
    g_fail_program_after = count;
}

void fa_fail_erases_after(uint32_t count)
{
    g_fail_erase_after = count;
}

uint32_t fa_programs(void)
{
    return g_programs;
}

uint32_t fa_erases(void)
{
    return g_erases;
}

uint32_t fa_sector_erases(uintptr_t s_addr)
{
    fa_region_t* r = fa_region(s_addr, 1u);

    if (r == NULL) {
        return 0u;
    }
    return r->sector_erases[(uint32_t)(s_addr - r->base) / FA_SECTOR];
}
