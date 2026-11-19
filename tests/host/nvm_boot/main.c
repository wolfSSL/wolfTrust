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

/* Host proof of the boot anti-rollback floor store (WT-FFM-0050) over the
 * real wolfHSM NVM stack on the RAM flash simulator: the floor persists on a
 * store whose directory has no free entry but reclaimable ones. */

#include "wolftrust/monitor.h"
#include "wolftrust/rollback.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/services/hsm.h"
#include "psa/lifecycle.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RAMSIM_SECTOR 4096
#define RAMSIM_SIZE   (2 * RAMSIM_SECTOR)
#define RAMSIM_PAGE   8

#define TEST_GUESTS       2U
#define TEST_FILL_ID_BASE 0x0400U

whNvmContext g_wt_nvm_ctx;

static uint8_t g_flash_memory[RAMSIM_SIZE];
static whFlashRamsimCfg g_ramsim_cfg;
static whFlashRamsimCtx g_ramsim_ctx;
static const whFlashCb g_ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
static whNvmFlashConfig g_nvm_flash_cfg;
static whNvmFlashContext g_nvm_flash_ctx;
static const whNvmCb g_nvm_cb[1] = {WH_NVM_FLASH_CB};
static whNvmConfig g_nvm_cfg;

static wt_scheduler_state_t g_sched;
static unsigned int g_quarantined;
static int g_failures;

const whFlashCb g_wt_hsm_flash_cb = WH_FLASH_RAMSIM_CB;

void* wt_hsm_flash_context(void)
{
    return &g_ramsim_ctx;
}

const void* wt_hsm_flash_config(void)
{
    return &g_ramsim_cfg;
}

int wt_nvm_store_bind(void)
{
    return WH_ERROR_OK;
}

void wt_nvm_store_pin(void)
{
}

const wt_scheduler_state_t* wt_monitor_state(void)
{
    return &g_sched;
}

void wt_monitor_quarantine_guest(wt_guest_id_t guest_id)
{
    (void)guest_id;
    g_quarantined++;
}

const struct wt_guest_measurement* wt_platform_guest_measurements(
    size_t* count)
{
    if (count != NULL) {
        *count = 0U;
    }
    return NULL;
}

void wt_platform_panic(void)
{
    (void)printf("FAIL: unexpected platform panic\n");
    exit(1);
}

void wt_platform_system_reset(void)
{
    (void)printf("FAIL: unexpected platform reset\n");
    exit(1);
}

void wt_mutex_release_if_holder(wt_mutex_t* mutex, struct wt_co* co)
{
    (void)mutex;
    (void)co;
}

void wt_mutex_remove_waiter(wt_mutex_t* mutex, struct wt_co* co)
{
    (void)mutex;
    (void)co;
}

int wt_spm_transport_direct(wt_ffm_runtime_t* runtime, wt_spm_call_t* call)
{
    (void)runtime;
    (void)call;
    return WT_FFM_ERROR_STATE;
}

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    }
    else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static int test_nvm_up(void)
{
    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    (void)memset(&g_ramsim_cfg, 0, sizeof(g_ramsim_cfg));
    g_ramsim_cfg.memory = g_flash_memory;
    g_ramsim_cfg.size = RAMSIM_SIZE;
    g_ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    g_ramsim_cfg.pageSize = RAMSIM_PAGE;
    g_ramsim_cfg.erasedByte = 0xFF;
    (void)memset(&g_ramsim_ctx, 0, sizeof(g_ramsim_ctx));
    (void)memset(&g_nvm_flash_cfg, 0, sizeof(g_nvm_flash_cfg));
    g_nvm_flash_cfg.cb = g_ramsim_cb;
    g_nvm_flash_cfg.context = &g_ramsim_ctx;
    g_nvm_flash_cfg.config = &g_ramsim_cfg;
    (void)memset(&g_nvm_flash_ctx, 0, sizeof(g_nvm_flash_ctx));
    (void)memset(&g_nvm_cfg, 0, sizeof(g_nvm_cfg));
    g_nvm_cfg.cb = (whNvmCb*)g_nvm_cb;
    g_nvm_cfg.context = &g_nvm_flash_ctx;
    g_nvm_cfg.config = &g_nvm_flash_cfg;
    (void)memset(&g_wt_nvm_ctx, 0, sizeof(g_wt_nvm_ctx));
    return (wh_Nvm_Init(&g_wt_nvm_ctx, &g_nvm_cfg) == WH_ERROR_OK) ? 0 : -1;
}

static int test_add(whNvmId id, uint8_t fill)
{
    whNvmMetadata meta;
    uint8_t data[16];

    (void)memset(data, fill, sizeof(data));
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.len = (whNvmSize)sizeof(data);
    return wh_Nvm_AddObject(&g_wt_nvm_ctx, &meta, (whNvmSize)sizeof(data),
                            data);
}

/* Leave the directory with no free entry and one reclaimable entry, the
 * steady state a supersede write leaves behind. */
static int test_fill_directory(void)
{
    uint32_t avail_size = 0U;
    uint32_t reclaim_size = 0U;
    whNvmId avail_objects = 0U;
    whNvmId reclaim_objects = 0U;
    whNvmId id = TEST_FILL_ID_BASE;

    for (;;) {
        if (wh_Nvm_GetAvailable(&g_wt_nvm_ctx, &avail_size, &avail_objects,
                                &reclaim_size, &reclaim_objects) !=
                WH_ERROR_OK) {
            return -1;
        }
        if (avail_objects <= 1U) {
            break;
        }
        if (test_add(id, 0x11U) != WH_ERROR_OK) {
            return -1;
        }
        id++;
    }
    if (test_add(TEST_FILL_ID_BASE, 0x22U) != WH_ERROR_OK) {
        return -1;
    }
    if (wh_Nvm_GetAvailable(&g_wt_nvm_ctx, &avail_size, &avail_objects,
                            &reclaim_size, &reclaim_objects) != WH_ERROR_OK) {
        return -1;
    }
    return (avail_objects == 0U && reclaim_objects >= 1U) ? 0 : -1;
}

static int test_avail_size(uint32_t* out)
{
    uint32_t reclaim_size = 0U;
    whNvmId avail_objects = 0U;
    whNvmId reclaim_objects = 0U;

    return wh_Nvm_GetAvailable(&g_wt_nvm_ctx, out, &avail_objects,
                               &reclaim_size, &reclaim_objects) ==
           WH_ERROR_OK ? 0 : -1;
}

/* Leave free data for more than one floor table but less than two. */
static int test_fill_data(void)
{
    static uint8_t data[512];
    whNvmMetadata meta;
    uint32_t before = 0U;
    uint32_t after = 0U;
    uint32_t extent;
    uint32_t len;
    whNvmId id = TEST_FILL_ID_BASE;

    (void)memset(data, 0x33, sizeof(data));
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = id++;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.len = (whNvmSize)sizeof(wt_rollback_table_t);
    if (test_avail_size(&before) != 0 ||
            wh_Nvm_AddObject(&g_wt_nvm_ctx, &meta, meta.len, data) !=
                WH_ERROR_OK ||
            test_avail_size(&after) != 0 || after >= before) {
        return -1;
    }
    extent = before - after;
    while (after >= 2U * extent) {
        len = after - extent - (extent / 2U);
        if (len > sizeof(data)) {
            len = sizeof(data);
        }
        (void)memset(&meta, 0, sizeof(meta));
        meta.id = id++;
        meta.access = WH_NVM_ACCESS_ANY;
        meta.len = (whNvmSize)len;
        if (wh_Nvm_AddObject(&g_wt_nvm_ctx, &meta, (whNvmSize)len, data) !=
                WH_ERROR_OK || test_avail_size(&after) != 0) {
            return -1;
        }
    }
    return after >= extent ? 0 : -1;
}

static int test_floor_is(uint32_t floor)
{
    wt_rollback_table_t table;
    whNvmMetadata meta;

    (void)memset(&table, 0, sizeof(table));
    (void)memset(&meta, 0, sizeof(meta));
    return wh_Nvm_GetMetadata(&g_wt_nvm_ctx, WT_HSM_ROLLBACK_TABLE_ID,
                              &meta) == WH_ERROR_OK &&
           meta.len == sizeof(table) &&
           wh_Nvm_Read(&g_wt_nvm_ctx, WT_HSM_ROLLBACK_TABLE_ID, 0U,
                       (whNvmSize)sizeof(table), (uint8_t*)&table) ==
               WH_ERROR_OK &&
           wt_rollback_table_valid(&table) && table.image_floor == floor;
}

static void test_floor_store_on_full_directory(void)
{
    int ret;

    check(test_nvm_up() == 0, "boot store initialized");
    wt_hsm_set_boot_lifecycle(PSA_LIFECYCLE_SECURED);

    g_quarantined = 0U;
    ret = wt_hsm_rollback_enforce(3U);
    check(ret == WT_ROLLBACK_OK && g_quarantined == 0U && test_floor_is(3U),
          "first boot creates the floor table");

    check(test_fill_directory() == 0,
          "directory has no free entry but reclaimable ones");
    g_quarantined = 0U;
    ret = wt_hsm_rollback_enforce(4U);
    check(ret == WT_ROLLBACK_OK,
          "WT-FFM-0050 floor advance persists on a full directory");
    check(g_quarantined == 0U, "no guest quarantined by the floor store");
    check(test_floor_is(4U), "persisted image floor matches the update");

    g_quarantined = 0U;
    ret = wt_hsm_rollback_enforce(4U);
    check(ret == WT_ROLLBACK_OK && g_quarantined == 0U,
          "next boot at the same version accepts the persisted floor");

    g_quarantined = 0U;
    ret = wt_hsm_rollback_enforce(5U);
    check(ret == WT_ROLLBACK_OK && g_quarantined == 0U && test_floor_is(5U),
          "a later update still advances the floor on the same store");

    g_quarantined = 0U;
    ret = wt_hsm_rollback_enforce(4U);
    check(ret == WT_ROLLBACK_REFUSED && g_quarantined == TEST_GUESTS,
          "downgrade below the persisted floor is refused");
}

/* A floor table is created only with room left for its next supersede, so a
 * later floor advance never fails for space and quarantines every guest. */
static void test_floor_create_keeps_supersede_room(void)
{
    int created;
    int advanced;

    check(test_nvm_up() == 0 && test_fill_data() == 0,
          "boot store holds room for one floor table but not two");
    wt_hsm_set_boot_lifecycle(PSA_LIFECYCLE_SECURED);
    g_quarantined = 0U;
    created = wt_hsm_rollback_enforce(3U) == WT_ROLLBACK_OK &&
              test_floor_is(3U);
    g_quarantined = 0U;
    advanced = created && wt_hsm_rollback_enforce(4U) == WT_ROLLBACK_OK &&
               test_floor_is(4U);
    check(!created || advanced,
          "WT-FFM-0050 a created floor table can always be advanced");
}

/* A version-0 first boot already writes the table, so the first floor
 * advance on a vault that has since filled is a supersede, never a create. */
static void test_version_zero_boot_writes_table(void)
{
    int ret;

    check(test_nvm_up() == 0, "boot store initialized");
    wt_hsm_set_boot_lifecycle(PSA_LIFECYCLE_SECURED);
    g_quarantined = 0U;
    ret = wt_hsm_rollback_enforce(0U);
    check(ret == WT_ROLLBACK_OK && g_quarantined == 0U && test_floor_is(0U),
          "a version-0 first boot writes the floor table");
    check(test_fill_directory() == 0,
          "directory has no free entry but reclaimable ones");
    g_quarantined = 0U;
    ret = wt_hsm_rollback_enforce(1U);
    check(ret == WT_ROLLBACK_OK && g_quarantined == 0U && test_floor_is(1U),
          "WT-FFM-0050 the first floor advance lands on a full vault");
}

int main(void)
{
    (void)memset(&g_sched, 0, sizeof(g_sched));
    g_sched.guest_count = TEST_GUESTS;

    test_floor_store_on_full_directory();
    test_floor_create_keeps_supersede_room();
    test_version_zero_boot_writes_table();

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: boot rollback floor store\n");
    return 0;
}
