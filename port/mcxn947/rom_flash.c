/* rom_flash.c
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

/* MCXN947 internal flash program and erase through the boot ROM's flash API,
 * called directly from its API tree so the port needs no vendor SDK. */

#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "mcxn947_regs.h"
#include "rom_flash.h"

/* Layouts derived from MCUXpresso fsl_flash.c (bootloader_tree_t, the flash
 * driver interface prefix) and fsl_flash.h (flash_config_t, 72 bytes). */
typedef struct wt_rom_flash_api {
    uint32_t version;
    int32_t (*init)(void *config);
    int32_t (*erase)(void *config, uint32_t start, uint32_t length,
                     uint32_t key);
    int32_t (*program)(void *config, uint32_t start, uint8_t *src,
                       uint32_t length);
    int32_t (*verify_erase)(void *config, uint32_t start, uint32_t length);
    int32_t (*verify_program)(void *config, uint32_t start, uint32_t length,
                              const uint8_t *expected, uint32_t *failed_address,
                              uint32_t *failed_data);
    int32_t (*get_property)(void *config, uint32_t property, uint32_t *value);
} wt_rom_flash_api_t;

typedef struct wt_rom_api_tree {
    void (*run_bootloader)(void *arg);
    uint32_t version;
    const char *copyright;
    uint32_t reserved0;
    const wt_rom_flash_api_t *flash;
} wt_rom_api_tree_t;

#define WT_ROM_FLASH_CONFIG_WORDS  18u
#define WT_ROM_FLASH_STATUS_OK     0
#define WT_ROM_FLASH_ERASE_KEY     0x6B65666Cu
#define WT_ROM_FLASH_PROP_SECTOR   0x00u
#define WT_ROM_FLASH_PROP_TOTAL    0x01u

#ifndef WT_ROM_API_TREE_ADDR
#define WT_ROM_API_TREE_ADDR       WT_ROM_API_TREE
#endif
#ifndef WT_ROM_FLASH_VIEW_BASE
#define WT_ROM_FLASH_VIEW_BASE     WT_FLASH_S_ALIAS_BASE
#endif

/* SYSCON LPCAC_CTRL: the code-bus cache in front of the flash is cleared
 * after every change so a verify reads the array, not a stale line. */
#define WT_SYSCON_LPCAC_CTRL       WT_REG32(WT_SYSCON_BASE_S + 0x824u)
#define WT_SYSCON_LPCAC_CTRL_CLR   (1u << 1)

static uint32_t g_rom_flash_config[WT_ROM_FLASH_CONFIG_WORDS];
static int g_rom_flash_ready;
/* Last ROM status, read over the debug port by the harness. */
volatile uint32_t g_wt_rom_flash_last_status __attribute__((used));

static const wt_rom_flash_api_t *wt_rom_flash_api(void)
{
    const wt_rom_api_tree_t *tree =
        (const wt_rom_api_tree_t *)(uintptr_t)WT_ROM_API_TREE_ADDR;

    return tree->flash;
}

static const volatile uint8_t *wt_rom_flash_view(uint32_t offset)
{
    return (const volatile uint8_t *)((uintptr_t)WT_ROM_FLASH_VIEW_BASE +
                                      offset);
}

static uint32_t wt_rom_flash_irq_mask(void)
{
    uint32_t primask = 0u;

#if defined(__ARM_EABI__)
    __asm volatile("mrs %0, primask\n\tcpsid i" : "=r"(primask) :: "memory");
#endif
    return primask;
}

static void wt_rom_flash_irq_restore(uint32_t primask)
{
#if defined(__ARM_EABI__)
    __asm volatile("msr primask, %0" :: "r"(primask) : "memory");
#else
    (void)primask;
#endif
}

static void wt_rom_flash_cache_clear(void)
{
#if defined(__ARM_EABI__)
    WT_SYSCON_LPCAC_CTRL |= WT_SYSCON_LPCAC_CTRL_CLR;
    __asm volatile("dsb sy\n\tisb" ::: "memory");
#endif
}

static int wt_rom_flash_range_ok(uint32_t offset, uint32_t size,
                                 uint32_t unit)
{
    if (size == 0u || (offset % unit) != 0u || (size % unit) != 0u) {
        return 0;
    }
    if (offset > WT_FLASH_SIZE || size > WT_FLASH_SIZE - offset) {
        return 0;
    }
    return 1;
}

static int wt_rom_flash_status(int32_t status)
{
    g_wt_rom_flash_last_status = (uint32_t)status;
    return (status == WT_ROM_FLASH_STATUS_OK) ? WT_ROM_FLASH_OK :
                                                WT_ROM_FLASH_ERR_ROM;
}

int wt_rom_flash_init(void)
{
    const wt_rom_flash_api_t *api;
    uint32_t sector = 0u;
    uint32_t total = 0u;
    uint32_t primask;
    size_t i;
    int ret = WT_ROM_FLASH_OK;

    if (g_rom_flash_ready != 0) {
        return WT_ROM_FLASH_OK;
    }
    api = wt_rom_flash_api();
    if (api == NULL || api->init == NULL || api->erase == NULL ||
            api->program == NULL || api->verify_erase == NULL ||
            api->get_property == NULL) {
        return WT_ROM_FLASH_ERR_ROM;
    }
    for (i = 0u; i < WT_ROM_FLASH_CONFIG_WORDS; i++) {
        g_rom_flash_config[i] = 0u;
    }
    primask = wt_rom_flash_irq_mask();
    ret = wt_rom_flash_status(api->init(g_rom_flash_config));
    if (ret == WT_ROM_FLASH_OK) {
        ret = wt_rom_flash_status(api->get_property(g_rom_flash_config,
                                                    WT_ROM_FLASH_PROP_SECTOR,
                                                    &sector));
    }
    if (ret == WT_ROM_FLASH_OK) {
        ret = wt_rom_flash_status(api->get_property(g_rom_flash_config,
                                                    WT_ROM_FLASH_PROP_TOTAL,
                                                    &total));
    }
    wt_rom_flash_irq_restore(primask);
    /* The port's map is only valid on the geometry the ROM reports. */
    if (ret == WT_ROM_FLASH_OK &&
            (sector != WT_FLASH_SECTOR_SIZE || total != WT_FLASH_SIZE)) {
        ret = WT_ROM_FLASH_ERR_GEOMETRY;
    }
    if (ret == WT_ROM_FLASH_OK) {
        g_rom_flash_ready = 1;
    }
    return ret;
}

int wt_rom_flash_blank(uint32_t offset, uint32_t size)
{
    const volatile uint8_t *view;
    uint32_t i;

    if (offset > WT_FLASH_SIZE || size > WT_FLASH_SIZE - offset) {
        return WT_ROM_FLASH_ERR_ARGS;
    }
    view = wt_rom_flash_view(offset);
    for (i = 0u; i < size; i++) {
        if (view[i] != 0xFFu) {
            return WT_ROM_FLASH_ERR_NOTBLANK;
        }
    }
    return WT_ROM_FLASH_OK;
}

/* The ROM programs only from a page base (status 101 on silicon for any other
 * start) and an all-ones phrase changes nothing, so a phrase is programmed
 * from its page base behind all-ones padding, one page per ROM call. */
int wt_rom_flash_program(uint32_t offset, const uint8_t *data, uint32_t size)
{
    uint8_t page[WT_FLASH_PAGE_SIZE]
        __attribute__((aligned(WT_FLASH_PHRASE_SIZE)));
    volatile uint8_t *wipe = page;
    uint32_t primask;
    uint32_t done = 0u;
    uint32_t base;
    uint32_t head;
    uint32_t chunk;
    uint32_t i;
    int ret;

    if (data == NULL ||
            !wt_rom_flash_range_ok(offset, size, WT_FLASH_PHRASE_SIZE)) {
        return WT_ROM_FLASH_ERR_ARGS;
    }
    ret = wt_rom_flash_init();
    if (ret == WT_ROM_FLASH_OK) {
        ret = wt_rom_flash_blank(offset, size);
    }
    while (ret == WT_ROM_FLASH_OK && done < size) {
        base = (offset + done) & ~(WT_FLASH_PAGE_SIZE - 1u);
        head = (offset + done) - base;
        chunk = WT_FLASH_PAGE_SIZE - head;
        if (chunk > size - done) {
            chunk = size - done;
        }
        for (i = 0u; i < head; i++) {
            page[i] = 0xFFu;
        }
        for (i = 0u; i < chunk; i++) {
            page[head + i] = data[done + i];
        }
        primask = wt_rom_flash_irq_mask();
        ret = wt_rom_flash_status(wt_rom_flash_api()->program(
                g_rom_flash_config, base, page, head + chunk));
        wt_rom_flash_cache_clear();
        wt_rom_flash_irq_restore(primask);
        done += chunk;
    }
    for (i = 0u; i < WT_FLASH_PAGE_SIZE; i++) {
        wipe[i] = 0u;
    }
    return ret;
}

int wt_rom_flash_erase(uint32_t offset, uint32_t size)
{
    const wt_rom_flash_api_t *api;
    uint32_t primask;
    int ret;

    if (!wt_rom_flash_range_ok(offset, size, WT_FLASH_SECTOR_SIZE)) {
        return WT_ROM_FLASH_ERR_ARGS;
    }
    ret = wt_rom_flash_init();
    if (ret == WT_ROM_FLASH_OK) {
        api = wt_rom_flash_api();
        primask = wt_rom_flash_irq_mask();
        ret = wt_rom_flash_status(api->erase(g_rom_flash_config, offset, size,
                                             WT_ROM_FLASH_ERASE_KEY));
        if (ret == WT_ROM_FLASH_OK) {
            ret = wt_rom_flash_status(api->verify_erase(g_rom_flash_config,
                                                        offset, size));
        }
        wt_rom_flash_cache_clear();
        wt_rom_flash_irq_restore(primask);
    }
    return ret;
}

uint32_t wt_rom_flash_last_status(void)
{
    return g_wt_rom_flash_last_status;
}
