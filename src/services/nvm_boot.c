/* nvm_boot.c
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
 * SPM-owned store state: the NVM serialisation lock, the boot lifecycle
 * latch, and the WT-FFM-0050 anti-rollback floors. Privileged code consumes
 * all of it, so none of it may live in a partition's data band.
 */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"

#include "wolftrust/types.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/platform.h"
#include "wolftrust/rollback.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/nvm_store.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/vault_service.h"

#include "wolftrust/port_nvm.h"
#include "psa/lifecycle.h"

#include <string.h>
#include <stdint.h>

wt_mutex_t g_wt_nvm_lock_mutex;

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

int wt_nvm_vault_bind(void)
{
    int rc;

    rc = g_wt_hsm_flash_cb.Init(wt_hsm_flash_context(),
                                wt_hsm_flash_config());
    if (rc == WH_ERROR_OK) {
        rc = wt_nvm_store_bind();
    }
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    if (wt_hsm_vault_init(&g_wt_nvm_ctx) == 0) {
        wt_vault_service_set_backend(&wt_hsm_vault_backend);
        wt_vault_service_set_nvm_backend(&wt_hsm_vault_nvm_backend);
        if (wt_hsm_seal_init(&g_wt_nvm_ctx) == 0) {
            wt_hsm_vault_set_sealer(&wt_hsm_sealer);
        }
        else {
            /* Reinit on the format/recovery path can fail after a prior
             * success; drop the sealer so sealed writes fail closed rather
             * than run with a stale or zero key. */
            wt_hsm_vault_set_sealer(NULL);
        }
        /* The vault serves no key ops (fail closed): keys live with the
         * crypto partition, reached through SERVICE_HSM (WT-FFM-0054). Only
         * the RANDOM face is served, from the vault's own DRBG. */
        wt_vault_service_set_rng(wt_hsm_vault_random);
        /* Nothing retries the seed later, so a failed restart must escalate. */
        if (wt_hsm_vault_rng_init() != 0) {
            return WH_ERROR_ABORTED;
        }
    }
    return WH_ERROR_OK;
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

    /* The privileged FWU-floor SVC and boot rollback reach this without a
     * server pump, so re-assert the NVM callback chain here too (WT-FFM-0011). */
    wt_nvm_store_pin();
    rc = wh_Nvm_GetMetadata(&g_wt_nvm_ctx, WT_HSM_ROLLBACK_TABLE_ID, &meta);
    if (rc == WH_ERROR_NOTFOUND) {
        wt_rollback_table_init(table);
        return 1;
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

    if (wt_hsm_vault_reserve_table_in(&g_wt_nvm_ctx, WT_HSM_ROLLBACK_TABLE_ID,
            (whNvmSize)sizeof(*table)) != PSA_SUCCESS) {
        return -1;
    }
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
/* The floor the boot enforcement settled on; the staging gate serves it from
 * here so no later request reads the vault's store with privilege. */
static uint32_t g_image_floor;
static int      g_image_floor_valid;

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
    int loaded;

    g_active_image_version = image_version;
    guest_count = wt_monitor_state()->guest_count;

    g_image_floor_valid = 0;
    loaded = wt_nvm_rollback_load(&table);
    if (loaded < 0) {
        /* An unreadable floor cannot prove anything: fail closed. */
        refused_platform = 1;
    }
    else {
        g_image_floor = table.image_floor;
        g_image_floor_valid = 1;
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
    g_image_floor = table.image_floor;
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

    /* The first boot that finds no table writes one while the store is still
     * empty, so later advances only supersede it; that create alone failing
     * persists nothing new, so it retries next boot instead of refusing. */
    if (!changed && loaded == 1) {
        (void)wt_nvm_rollback_store(&table);
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
    if (floor == NULL) {
        return -1;
    }
    if (g_image_floor_valid == 0) {
        return -1;
    }
    /* The unlocked provisioning lifecycles bypass refusal at boot; the
     * staging floor mirrors that so development flows are never bricked. */
    *floor = wt_nvm_reformat_allowed() ? 0U : g_image_floor;
    return 0;
}
