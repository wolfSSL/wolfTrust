/* main.c
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

/* Host suite for the MCXN947 ROM flash driver and the wolfHSM store over a
 * model of the part's ECC flash (a 16-byte phrase programmed twice between
 * erases is counted as a double program); built per wolfHSM unit size. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memory_map.h"
#include "rom_flash.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_unit.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"

/* Layouts mirrored from rom_flash.c (the driver's private view of the ROM). */
typedef struct mock_flash_api {
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
} mock_flash_api_t;

typedef struct mock_api_tree {
    void (*run_bootloader)(void *arg);
    uint32_t version;
    const char *copyright;
    uint32_t reserved0;
    const mock_flash_api_t *flash;
} mock_api_tree_t;

#define PHRASE          WT_FLASH_PHRASE_SIZE
#define SECTOR          WT_FLASH_SECTOR_SIZE
#define PHRASES         (WT_FLASH_SIZE / PHRASE)
#define ERASE_KEY       0x6B65666Cu
#define STATUS_OK       0
#define STATUS_ALIGN    101
#define STATUS_KEY      107
#define STATUS_COMPARE  117
#define NVM_OFF         (WT_HSM_NVM_FLASH_BASE_S - WT_FLASH_S_ALIAS_BASE)
#define NVM_SIZE        WT_HSM_NVM_FLASH_SIZE

static uint8_t g_flash[WT_FLASH_SIZE];
static uint8_t g_programmed[PHRASES];

/* Model counters and knobs. */
static uint32_t g_double_programs;
static uint32_t g_first_double_offset;
static uint32_t g_program_calls;
static uint32_t g_erase_calls;
static uint32_t g_verify_erase_calls;
static uint32_t g_init_calls;
static uint32_t g_prop_sector = SECTOR;
static uint32_t g_prop_total = WT_FLASH_SIZE;
static int32_t g_program_status = STATUS_OK;
static int32_t g_erase_status = STATUS_OK;

static int g_failures;
static int g_checks;

static void check(int cond, const char *name)
{
    g_checks++;
    if (cond) {
        printf("PASS: %s\n", name);
    }
    else {
        printf("FAIL: %s\n", name);
        g_failures++;
    }
}

/* Program as the array does: bits clear, and a phrase written twice since
 * its erase no longer carries a valid ECC. */
static void model_program(uint32_t start, const uint8_t *src, uint32_t len)
{
    uint32_t first = start / PHRASE;
    uint32_t last = (start + len - 1u) / PHRASE;
    uint32_t p;
    uint32_t i;

    for (p = first; p <= last; p++) {
        if (g_programmed[p] != 0u) {
            if (g_double_programs == 0u) {
                g_first_double_offset = p * PHRASE;
            }
            g_double_programs++;
        }
        g_programmed[p] = 1u;
    }
    for (i = 0u; i < len; i++) {
        g_flash[start + i] &= src[i];
    }
}

static void model_erase(uint32_t start, uint32_t len)
{
    uint32_t p;

    (void)memset(g_flash + start, 0xFF, len);
    for (p = start / PHRASE; p < (start + len) / PHRASE; p++) {
        g_programmed[p] = 0u;
    }
}

static void model_reset(void)
{
    (void)memset(g_flash, 0xFF, sizeof(g_flash));
    (void)memset(g_programmed, 0, sizeof(g_programmed));
    g_double_programs = 0u;
    g_first_double_offset = 0u;
}

static int32_t mock_init(void *config)
{
    uint32_t *words = (uint32_t *)config;

    g_init_calls++;
    words[0] = 0u;
    words[1] = g_prop_total;
    words[2] = 2u;
    words[3] = 128u;
    words[4] = g_prop_sector;
    return STATUS_OK;
}

static int32_t mock_erase(void *config, uint32_t start, uint32_t length,
                          uint32_t key)
{
    (void)config;
    g_erase_calls++;
    if (key != ERASE_KEY) {
        return STATUS_KEY;
    }
    if ((start % 4u) != 0u || (length % 4u) != 0u ||
            start + length > WT_FLASH_SIZE) {
        return STATUS_ALIGN;
    }
    if (g_erase_status != STATUS_OK) {
        return g_erase_status;
    }
    model_erase(start, length);
    return STATUS_OK;
}

static int32_t mock_program(void *config, uint32_t start, uint8_t *src,
                            uint32_t length)
{
    (void)config;
    g_program_calls++;
    if ((start % 4u) != 0u || (length % 4u) != 0u ||
            start + length > WT_FLASH_SIZE) {
        return STATUS_ALIGN;
    }
    if (g_program_status != STATUS_OK) {
        return g_program_status;
    }
    model_program(start, src, length);
    return STATUS_OK;
}

static int32_t mock_verify_erase(void *config, uint32_t start, uint32_t length)
{
    uint32_t i;

    (void)config;
    g_verify_erase_calls++;
    for (i = 0u; i < length; i++) {
        if (g_flash[start + i] != 0xFFu) {
            return STATUS_COMPARE;
        }
    }
    return STATUS_OK;
}

static int32_t mock_verify_program(void *config, uint32_t start,
                                   uint32_t length, const uint8_t *expected,
                                   uint32_t *failed_address,
                                   uint32_t *failed_data)
{
    (void)config;
    (void)failed_address;
    (void)failed_data;
    return (memcmp(g_flash + start, expected, length) == 0) ? STATUS_OK :
                                                              STATUS_COMPARE;
}

static int32_t mock_get_property(void *config, uint32_t property,
                                 uint32_t *value)
{
    (void)config;
    if (property == 0u) {
        *value = g_prop_sector;
    }
    else if (property == 1u) {
        *value = g_prop_total;
    }
    else {
        return 106;
    }
    return STATUS_OK;
}

static const mock_flash_api_t g_mock_api = {
    0x46010000u, mock_init, mock_erase, mock_program, mock_verify_erase,
    mock_verify_program, mock_get_property
};
static const mock_api_tree_t g_mock_tree = {
    NULL, 0x4B010000u, "mock", 0u, &g_mock_api
};

uintptr_t wt_mock_rom_tree(void)
{
    return (uintptr_t)&g_mock_tree;
}

uintptr_t wt_mock_flash_base(void)
{
    return (uintptr_t)g_flash;
}

static void test_driver(void)
{
    uint8_t phrase[PHRASE];
    uint8_t two[2u * PHRASE];
    uint32_t calls;
    int rc;

    model_reset();
    (void)memset(phrase, 0x5A, sizeof(phrase));
    (void)memset(two, 0xC3, sizeof(two));

    /* The ROM's geometry must be the one the map was written for. */
    g_prop_sector = 0x1000u;
    check(wt_rom_flash_init() == WT_ROM_FLASH_ERR_GEOMETRY,
          "init refuses a ROM reporting another sector size");
    g_prop_sector = SECTOR;
    check(wt_rom_flash_init() == WT_ROM_FLASH_OK && g_init_calls == 2u,
          "init accepts the 8 KiB sector, 2 MiB geometry");
    check(wt_rom_flash_init() == WT_ROM_FLASH_OK && g_init_calls == 2u,
          "init is idempotent");

    check(wt_rom_flash_program(NVM_OFF + 8u, phrase, PHRASE) ==
          WT_ROM_FLASH_ERR_ARGS, "program refuses a phrase-misaligned offset");
    check(wt_rom_flash_program(NVM_OFF, phrase, 8u) == WT_ROM_FLASH_ERR_ARGS,
          "program refuses a sub-phrase length");
    check(wt_rom_flash_program(NVM_OFF, NULL, PHRASE) == WT_ROM_FLASH_ERR_ARGS,
          "program refuses a null source");
    check(wt_rom_flash_program(WT_FLASH_SIZE - PHRASE, two, sizeof(two)) ==
          WT_ROM_FLASH_ERR_ARGS, "program refuses a range past the array");
    check(g_program_calls == 0u, "refused programs never reach the ROM");

    check(wt_rom_flash_program(NVM_OFF, two, sizeof(two)) == WT_ROM_FLASH_OK &&
          memcmp(g_flash + NVM_OFF, two, sizeof(two)) == 0,
          "two blank phrases program in one ROM call");
    calls = g_program_calls;
    rc = wt_rom_flash_program(NVM_OFF + PHRASE, phrase, PHRASE);
    check(rc == WT_ROM_FLASH_ERR_NOTBLANK && g_program_calls == calls,
          "a programmed phrase is refused before the ROM is called");
    check(g_double_programs == 0u, "no phrase was programmed twice");
    check(memcmp(g_flash + NVM_OFF + PHRASE, two, PHRASE) == 0,
          "the refused write left the phrase as it was");
    check(wt_rom_flash_blank(NVM_OFF, PHRASE) == WT_ROM_FLASH_ERR_NOTBLANK &&
          wt_rom_flash_blank(NVM_OFF + 2u * PHRASE, PHRASE) == WT_ROM_FLASH_OK,
          "blank check reads the array through the view");

    check(wt_rom_flash_erase(NVM_OFF + PHRASE, SECTOR) == WT_ROM_FLASH_ERR_ARGS,
          "erase refuses a sector-misaligned offset");
    check(wt_rom_flash_erase(NVM_OFF, PHRASE) == WT_ROM_FLASH_ERR_ARGS,
          "erase refuses a sub-sector length");
    check(g_erase_calls == 0u, "refused erases never reach the ROM");
    check(wt_rom_flash_erase(NVM_OFF, SECTOR) == WT_ROM_FLASH_OK &&
          g_verify_erase_calls == 1u &&
          wt_rom_flash_blank(NVM_OFF, SECTOR) == WT_ROM_FLASH_OK,
          "sector erase runs the ROM erase and its verify");
    check(wt_rom_flash_program(NVM_OFF + PHRASE, phrase, PHRASE) ==
          WT_ROM_FLASH_OK && g_double_programs == 0u,
          "an erased phrase programs again, once");

    g_program_status = 103;
    check(wt_rom_flash_program(NVM_OFF + 4u * PHRASE, phrase, PHRASE) ==
          WT_ROM_FLASH_ERR_ROM && wt_rom_flash_last_status() == 103u,
          "a ROM program failure is reported with its status");
    g_program_status = STATUS_OK;
    g_erase_status = 105;
    check(wt_rom_flash_erase(NVM_OFF, SECTOR) == WT_ROM_FLASH_ERR_ROM &&
          wt_rom_flash_last_status() == 105u,
          "a ROM erase failure is reported with its status");
    g_erase_status = STATUS_OK;
}

/* The port backend's rules (port/mcxn947/hsm_flash.c) over the real driver:
 * a 16-byte program unit, sector erases, reads through the alias. */
static int port_init(void *context, const void *config)
{
    (void)context;
    (void)config;
    return WH_ERROR_OK;
}

static int port_cleanup(void *context)
{
    (void)context;
    return WH_ERROR_OK;
}

static uint32_t port_partition_size(void *context)
{
    (void)context;
    return SECTOR;
}

static int port_lock(void *context, uint32_t offset, uint32_t size)
{
    (void)context;
    (void)offset;
    (void)size;
    return WH_ERROR_OK;
}

static int port_range_ok(uint32_t offset, uint32_t size)
{
    return (offset <= NVM_SIZE && size <= NVM_SIZE - offset) ? 1 : 0;
}

static int port_read(void *context, uint32_t offset, uint32_t size,
                     uint8_t *data)
{
    (void)context;
    if (!port_range_ok(offset, size)) {
        return WH_ERROR_BADARGS;
    }
    (void)memcpy(data, g_flash + NVM_OFF + offset, size);
    return WH_ERROR_OK;
}

static int port_result(int rc)
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

static int port_program(void *context, uint32_t offset, uint32_t size,
                        const uint8_t *data)
{
    (void)context;
    if (!port_range_ok(offset, size) || (offset % PHRASE) != 0u ||
            (size % PHRASE) != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    return port_result(wt_rom_flash_program(NVM_OFF + offset, data, size));
}

static int port_erase(void *context, uint32_t offset, uint32_t size)
{
    (void)context;
    if (!port_range_ok(offset, size) || (offset % SECTOR) != 0u ||
            (size % SECTOR) != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    return port_result(wt_rom_flash_erase(NVM_OFF + offset, size));
}

static int port_verify(void *context, uint32_t offset, uint32_t size,
                       const uint8_t *data)
{
    (void)context;
    if (!port_range_ok(offset, size)) {
        return WH_ERROR_BADARGS;
    }
    return (memcmp(g_flash + NVM_OFF + offset, data, size) == 0) ?
           WH_ERROR_OK : WH_ERROR_NOTVERIFIED;
}

static int port_blank_check(void *context, uint32_t offset, uint32_t size)
{
    int rc;

    (void)context;
    if (!port_range_ok(offset, size)) {
        return WH_ERROR_BADARGS;
    }
    rc = wt_rom_flash_blank(NVM_OFF + offset, size);
    if (rc == WT_ROM_FLASH_ERR_NOTBLANK) {
        return WH_ERROR_NOTBLANK;
    }
    return (rc == WT_ROM_FLASH_OK) ? WH_ERROR_OK : WH_ERROR_BADARGS;
}

static const whFlashCb g_port_cb = {
    .Init = port_init,
    .Cleanup = port_cleanup,
    .PartitionSize = port_partition_size,
    .WriteLock = port_lock,
    .WriteUnlock = port_lock,
    .Read = port_read,
    .Program = port_program,
    .Erase = port_erase,
    .Verify = port_verify,
    .BlankCheck = port_blank_check,
};

/* A backend that programs whatever unit it is handed, as a port that took
 * the wolfHSM unit for the flash's own would. */
static int raw_program(void *context, uint32_t offset, uint32_t size,
                       const uint8_t *data)
{
    (void)context;
    if (!port_range_ok(offset, size) || (offset % 4u) != 0u ||
            (size % 4u) != 0u) {
        return WH_ERROR_BADARGS;
    }
    model_program(NVM_OFF + offset, data, size);
    return WH_ERROR_OK;
}

static int raw_erase(void *context, uint32_t offset, uint32_t size)
{
    (void)context;
    if (!port_range_ok(offset, size) || (offset % SECTOR) != 0u ||
            (size % SECTOR) != 0u) {
        return WH_ERROR_BADARGS;
    }
    model_erase(NVM_OFF + offset, size);
    return WH_ERROR_OK;
}

static int raw_blank_check(void *context, uint32_t offset, uint32_t size)
{
    uint32_t i;

    (void)context;
    if (!port_range_ok(offset, size)) {
        return WH_ERROR_BADARGS;
    }
    for (i = 0u; i < size; i++) {
        if (g_flash[NVM_OFF + offset + i] != 0xFFu) {
            return WH_ERROR_NOTBLANK;
        }
    }
    return WH_ERROR_OK;
}

static const whFlashCb g_raw_cb = {
    .Init = port_init,
    .Cleanup = port_cleanup,
    .PartitionSize = port_partition_size,
    .WriteLock = port_lock,
    .WriteUnlock = port_lock,
    .Read = port_read,
    .Program = raw_program,
    .Erase = raw_erase,
    .Verify = port_verify,
    .BlankCheck = raw_blank_check,
};

#define OBJECTS      20u
#define OBJECT_MAX   300u
#define ROUNDS       3u

static whNvmFlashContext g_nf_ctx;
static whNvmFlashConfig g_nf_cfg;
static whNvmContext g_nvm;
static whNvmConfig g_nvm_cfg;
static whNvmCb g_nvm_cb = WH_NVM_FLASH_CB;
static uint8_t g_pattern[OBJECT_MAX];

static void fill_object(uint8_t *out, uint32_t id, uint32_t len)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        out[i] = (uint8_t)(id * 7u + i * 13u + 1u);
    }
}

static int nvm_open(const whFlashCb *cb)
{
    (void)memset(&g_nf_ctx, 0, sizeof(g_nf_ctx));
    (void)memset(&g_nvm, 0, sizeof(g_nvm));
    g_nf_cfg.cb = cb;
    g_nf_cfg.context = NULL;
    g_nf_cfg.config = NULL;
    g_nvm_cfg.cb = &g_nvm_cb;
    g_nvm_cfg.context = &g_nf_ctx;
    g_nvm_cfg.config = &g_nf_cfg;
    return wh_Nvm_Init(&g_nvm, &g_nvm_cfg);
}

/* Fill, read back, destroy, refill until the store compacts into its other
 * partition, then reopen the store as a reboot would and read everything
 * back. Every sector erase after the open is one such compaction. Returns 0
 * when every object read back as written. */
static int nvm_lifecycle(const whFlashCb *cb, uint32_t *compactions)
{
    whNvmMetadata meta;
    uint8_t readback[OBJECT_MAX];
    whNvmId victims[OBJECTS / 2u];
    uint32_t round;
    uint32_t i;
    uint32_t len;
    uint32_t erases_at_open;
    int ret;

    *compactions = 0u;
    ret = nvm_open(cb);
    erases_at_open = g_erase_calls;
    for (round = 0u; ret == WH_ERROR_OK && round < ROUNDS; round++) {
        for (i = 0u; ret == WH_ERROR_OK && i < OBJECTS; i++) {
            len = 1u + ((i * 37u + round * 11u) % OBJECT_MAX);
            (void)memset(&meta, 0, sizeof(meta));
            meta.id = (whNvmId)(0x100u + i);
            meta.access = WH_NVM_ACCESS_ANY;
            meta.flags = WH_NVM_FLAGS_NONE;
            meta.len = (whNvmSize)len;
            fill_object(g_pattern, meta.id + round, len);
            ret = wh_Nvm_AddObjectWithReclaim(&g_nvm, &meta, (whNvmSize)len,
                                              g_pattern);
        }
        for (i = 0u; ret == WH_ERROR_OK && i < OBJECTS; i++) {
            len = 1u + ((i * 37u + round * 11u) % OBJECT_MAX);
            fill_object(g_pattern, 0x100u + i + round, len);
            (void)memset(readback, 0, sizeof(readback));
            ret = wh_Nvm_Read(&g_nvm, (whNvmId)(0x100u + i), 0u,
                              (whNvmSize)len, readback);
            if (ret == WH_ERROR_OK && memcmp(readback, g_pattern, len) != 0) {
                ret = WH_ERROR_NOTVERIFIED;
            }
        }
        for (i = 0u; i < OBJECTS / 2u; i++) {
            victims[i] = (whNvmId)(0x100u + 2u * i);
        }
        if (ret == WH_ERROR_OK) {
            ret = wh_Nvm_DestroyObjects(&g_nvm, OBJECTS / 2u, victims);
        }
    }
    *compactions = g_erase_calls - erases_at_open;
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_Cleanup(&g_nvm);
    }
    if (ret == WH_ERROR_OK) {
        ret = nvm_open(cb);
    }
    for (i = 1u; ret == WH_ERROR_OK && i < OBJECTS; i += 2u) {
        len = 1u + ((i * 37u + (ROUNDS - 1u) * 11u) % OBJECT_MAX);
        fill_object(g_pattern, 0x100u + i + ROUNDS - 1u, len);
        (void)memset(readback, 0, sizeof(readback));
        ret = wh_Nvm_Read(&g_nvm, (whNvmId)(0x100u + i), 0u, (whNvmSize)len,
                          readback);
        if (ret == WH_ERROR_OK && memcmp(readback, g_pattern, len) != 0) {
            ret = WH_ERROR_NOTVERIFIED;
        }
    }
    return ret;
}

static void test_store(void)
{
    uint32_t compactions = 0u;
    int ret;

    model_reset();
    g_program_calls = 0u;
    g_erase_calls = 0u;
#if WOLFHSM_CFG_FLASH_UNIT_SIZE == 16
    ret = nvm_lifecycle(&g_port_cb, &compactions);
    check(ret == WH_ERROR_OK,
          "16-byte units: three fill/read/destroy rounds and a reopen");
    check(compactions >= 1u,
          "16-byte units: the store compacted into its other partition");
    check(g_program_calls > 100u,
          "16-byte units: the lifecycle programmed many phrases");
    printf("  programs=%u compactions=%u double=%u\n",
           (unsigned)g_program_calls, (unsigned)compactions,
           (unsigned)g_double_programs);
    check(g_double_programs == 0u,
          "16-byte units: no phrase was programmed twice between erases");
    /* The unit, not the port's guard, is what keeps every program whole:
     * a backend with no phrase rule stays clean at 16 bytes. */
    model_reset();
    ret = nvm_lifecycle(&g_raw_cb, &compactions);
    check(ret == WH_ERROR_OK && g_double_programs == 0u,
          "16-byte units: the raw backend never writes a phrase twice");
#else
    ret = nvm_open(&g_port_cb);
    check(ret != WH_ERROR_OK,
          "8-byte units: the port backend refuses the sub-phrase unit");
    check(g_program_calls == 0u && g_double_programs == 0u,
          "8-byte units: nothing reached the ROM through the port backend");
    model_reset();
    ret = nvm_lifecycle(&g_raw_cb, &compactions);
    check(ret == WH_ERROR_OK,
          "8-byte units: the raw backend completes the same lifecycle");
    printf("  compactions=%u double=%u first=0x%08X\n",
           (unsigned)compactions, (unsigned)g_double_programs,
           (unsigned)g_first_double_offset);
    check(g_double_programs > 0u,
          "8-byte units: two units sharing a phrase were written at "
          "different times, which this flash would corrupt");
#endif
}

int main(void)
{
    printf("MCXN947 flash: WOLFHSM_CFG_FLASH_UNIT_SIZE=%d\n",
           (int)WOLFHSM_CFG_FLASH_UNIT_SIZE);
    test_driver();
    test_store();
    printf("%s: %d checks, %d failures\n",
           (g_failures == 0) ? "PASS" : "FAIL", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
