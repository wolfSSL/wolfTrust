/* nvm_store.c
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

/*
 * Engine-independent secure NVM store: the shared flash-backed object store,
 * its serialisation lock, the boot lifecycle latch, and the WT-FFM-0050
 * anti-rollback floors. Linked in both crypto engines — the wolfHSM server
 * (hsm engine) and the native dispatch both ride this store.
 */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_lock.h"

#include "wolftrust/types.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/platform.h"
#include "wolftrust/rollback.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/nvm_store.h"
#include "wolftrust/services/hsm.h"

#include "wolftrust/port_nvm.h"
#include "psa/lifecycle.h"

#include <string.h>
#include <stdint.h>

#ifndef WOLFHSM_CFG_THREADSAFE
#error "wolfTrust requires WOLFHSM_CFG_THREADSAFE for the shared NVM store"
#endif

/* -------------------------------------------------------------------------
 * Shared NVM state (one instance, serialised by g_wt_nvm_lock_mutex).
 * ---------------------------------------------------------------------- */
whNvmContext             g_wt_nvm_ctx;
static whNvmFlashContext g_nvm_flash_ctx;

static const whNvmCb   g_nvm_flash_cb[1] = {WH_NVM_FLASH_CB};

/* -------------------------------------------------------------------------
 * Shared NVM lock.
 *
 * g_wt_hsm_lock_cb is defined in the parallel Wave 3B file wt_hsm_lock.c.
 * Its callbacks dispatch acquire/release to g_wt_nvm_lock_mutex.
 * ---------------------------------------------------------------------- */
wt_mutex_t          g_wt_nvm_lock_mutex;
static whLockConfig g_nvm_lock_cfg;
extern const whLockCb g_wt_hsm_lock_cb; /* defined in wt_hsm_lock.c */

/* -------------------------------------------------------------------------
 * Store recovery policy. A pool written by an older firmware generation (or
 * a corrupt one) can block boot provisioning; recovery reformats it, but
 * only in an unlocked development lifecycle — a SECURED device must never
 * auto-wipe WRITE_ONCE storage or the sealed device key, so an unset or
 * unknown lifecycle stays locked.
 * ---------------------------------------------------------------------- */
static uint32_t g_boot_lifecycle;       /* PSA lifecycle from wolfBoot handoff */
static int      g_vault_reformatted;    /* observability: reformatted this boot */

void wt_hsm_set_boot_lifecycle(uint32_t lifecycle)
{
    g_boot_lifecycle = lifecycle;
}

int wt_hsm_vault_was_reformatted(void)
{
    return g_vault_reformatted;
}

void wt_nvm_mark_reformatted(void)
{
    g_vault_reformatted = 1;
}

int wt_nvm_reformat_allowed(void)
{
    return (g_boot_lifecycle == PSA_LIFECYCLE_ASSEMBLY_AND_TEST) ||
           (g_boot_lifecycle == PSA_LIFECYCLE_PSA_ROT_PROVISIONING);
}

int wt_nvm_store_bind(void)
{
    whNvmFlashConfig nvm_flash_cfg;
    whNvmConfig      nvm_cfg;

    (void)memset(&g_nvm_flash_ctx, 0, sizeof(g_nvm_flash_ctx));
    (void)memset(&nvm_flash_cfg, 0, sizeof(nvm_flash_cfg));
    nvm_flash_cfg.cb      = &g_wt_hsm_flash_cb;
    nvm_flash_cfg.context = wt_hsm_flash_context();
    nvm_flash_cfg.config  = wt_hsm_flash_config();

    g_nvm_lock_cfg.cb      = &g_wt_hsm_lock_cb;
    g_nvm_lock_cfg.context = &g_wt_nvm_lock_mutex;
    g_nvm_lock_cfg.config  = NULL;

    (void)memset(&g_wt_nvm_ctx, 0, sizeof(g_wt_nvm_ctx));
    (void)memset(&nvm_cfg, 0, sizeof(nvm_cfg));
    nvm_cfg.cb         = (whNvmCb *)g_nvm_flash_cb;
    nvm_cfg.context    = &g_nvm_flash_ctx;
    nvm_cfg.config     = &nvm_flash_cfg;
    nvm_cfg.lockConfig = &g_nvm_lock_cfg;

    return wh_Nvm_Init(&g_wt_nvm_ctx, &nvm_cfg);
}

void wt_hsm_release_locks(struct wt_co *co)
{
    /* Drop every secure-side store lock the faulted coroutine still held, and
     * unlink it if it died parked as a waiter, so no later acquirer deadlocks
     * behind a dead holder or a dead queued waiter. The NVM lock is the only
     * such mutex today; add any future ones here. Recovery runs this before
     * the partition is restarted, so the waiter is gone before it can
     * re-enqueue. */
    if (co != NULL) {
        wt_mutex_release_if_holder(&g_wt_nvm_lock_mutex, co);
        wt_mutex_remove_waiter(&g_wt_nvm_lock_mutex, co);
    }
}

wt_mutex_t *wt_hsm_nvm_lock_mutex(void)
{
    return &g_wt_nvm_lock_mutex;
}

/* -------------------------------------------------------------------------
 * WT-FFM-0050 firmware anti-rollback: monotonic version floors in a plain
 * NVM object (WT_HSM_ROLLBACK_TABLE_ID), same access idiom as the vault
 * counter table. Runs on the boot stack after the store binds and before
 * the first dispatch.
 * ---------------------------------------------------------------------- */
static int wt_nvm_rollback_load(wt_rollback_table_t* table)
{
    whNvmMetadata meta;
    int rc;

    rc = wh_Nvm_GetMetadata(&g_wt_nvm_ctx, WT_HSM_ROLLBACK_TABLE_ID, &meta);
    if (rc == WH_ERROR_NOTFOUND) {
        wt_rollback_table_init(table);
        return 0;
    }
    if (rc != WH_ERROR_OK || meta.len != sizeof(*table)) {
        return -1;
    }
    rc = wh_Nvm_Read(&g_wt_nvm_ctx, WT_HSM_ROLLBACK_TABLE_ID, 0U,
                     (whNvmSize)sizeof(*table), (uint8_t*)table);
    if (rc != WH_ERROR_OK || !wt_rollback_table_valid(table)) {
        return -1;
    }
    return 0;
}

static int wt_nvm_rollback_store(const wt_rollback_table_t* table)
{
    whNvmMetadata meta;
    int rc;

    (void)memset(&meta, 0, sizeof(meta));
    meta.id = WT_HSM_ROLLBACK_TABLE_ID;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = 0U;
    meta.len = (whNvmSize)sizeof(*table);
    rc = wh_Nvm_AddObject(&g_wt_nvm_ctx, &meta, (whNvmSize)sizeof(*table),
                          (const uint8_t*)table);
    return (rc == WH_ERROR_OK) ? 0 : -1;
}

static uint32_t g_active_image_version;

uint32_t wt_hsm_active_image_version(void)
{
    return g_active_image_version;
}

int wt_hsm_rollback_enforce(uint32_t image_version)
{
    wt_rollback_table_t table;
    const wt_guest_measurement_t* records;
    size_t record_count = 0U;
    size_t guest_count;
    size_t i;
    int refused_platform = 0;
    int changed = 0;

    g_active_image_version = image_version;
    guest_count = wt_monitor_state()->guest_count;

    if (wt_nvm_rollback_load(&table) != 0) {
        /* An unreadable floor cannot prove anything: fail closed. */
        refused_platform = 1;
    }

#if defined(WT_ROLLBACK_PROBE)
    /* Negative test: force the locked lifecycle (the emulator chain boots in
     * assembly-and-test, which rightly bypasses enforcement), then on the
     * first pass arm the image floor one above the running version and
     * reboot, so the second pass exercises the real downgrade refusal
     * against a floor that survived SYSRESETREQ. A failed arming store is a
     * broken test, not a refusal: trap loudly. */
    g_boot_lifecycle = PSA_LIFECYCLE_SECURED;
    if (!refused_platform && table.image_floor <= image_version) {
        table.image_floor = image_version + 1U;
        if (wt_nvm_rollback_store(&table) != 0) {
            wt_platform_panic();
        }
        wt_platform_system_reset();
    }
#endif

    if (!refused_platform &&
            wt_rollback_check(g_boot_lifecycle, image_version,
                              table.image_floor) != WT_ROLLBACK_OK) {
        refused_platform = 1;
    }

    records = wt_platform_guest_measurements(&record_count);

    if (refused_platform) {
        for (i = 0U; i < guest_count; i++) {
            wt_monitor_quarantine_guest((wt_guest_id_t)i);
        }
        return WT_ROLLBACK_REFUSED;
    }

    changed = wt_rollback_advance(image_version, &table.image_floor);
    for (i = 0U; records != NULL && i < record_count; i++) {
        uint32_t guest = records[i].guest_id;

        if (guest >= WT_GUEST_MEAS_MAX_RECORDS) {
            continue;
        }
        if (wt_rollback_check(g_boot_lifecycle, records[i].version,
                              table.guest_floor[guest]) != WT_ROLLBACK_OK) {
            wt_monitor_quarantine_guest((wt_guest_id_t)guest);
        }
        else if (wt_rollback_advance(records[i].version,
                                     &table.guest_floor[guest]) != 0) {
            changed = 1;
        }
    }

    if (changed && wt_nvm_rollback_store(&table) != 0) {
        /* An unpersisted floor must not launch guests: the next reset would
         * accept the previous floor again. Quarantine fail-closed; secure
         * services stay up so the wedge is observable and recoverable. */
        for (i = 0U; i < guest_count; i++) {
            wt_monitor_quarantine_guest((wt_guest_id_t)i);
        }
        return WT_ROLLBACK_REFUSED;
    }

    return WT_ROLLBACK_OK;
}

int wt_hsm_rollback_image_floor(uint32_t* floor)
{
    wt_rollback_table_t table;

    if (floor == NULL) {
        return -1;
    }
    if (wt_nvm_rollback_load(&table) != 0) {
        return -1;
    }
    /* The unlocked provisioning lifecycles bypass refusal at boot; the
     * staging floor mirrors that so development flows are never bricked. */
    *floor = wt_nvm_reformat_allowed() ? 0U : table.image_floor;
    return 0;
}
