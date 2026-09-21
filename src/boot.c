/* boot.c
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


/* Architecture-neutral boot sequence, entered by the arch reset handler once
 * the image's data and bss are initialized: monitor, boot handoff, secure
 * engine, attestation, partition scheduler, then the guest monitor loop. */

#include "wolftrust/arch.h"
#include "wolftrust/boot.h"
#include "wolftrust/boot_handoff.h"
#include "wolftrust/ffm.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/monitor.h"
#include "wolftrust/partition.h"
#include "wolftrust/platform.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/initial_attestation.h"
#include "wolfhsm/wh_error.h"
#include "wolftrust/sched/tasklet.h"
#ifndef WT_ENGINE_HSM
#include "wolftrust/services/crypto_native.h"
#endif

#include <stddef.h>
#include <stdint.h>

/* Read over the debug port by the hardware harness. */
static volatile uint32_t g_wt_attest_degraded __attribute__((used));

void wt_boot_run(void)
{
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    wt_boot_handoff_t bootHandoff;
    int handoffRet;
#endif

    wt_monitor_init();
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    handoffRet = wt_boot_handoff_consume(&bootHandoff);
    wt_boot_handoff_clear();
#endif
    /* Coroutine runtime first: the SP scheduler and (in the hsm engine) the
     * per-guest server tasklets both ride it. */
    wt_tasklet_init();
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* Gate vault auto-reformat on the wolfBoot-reported lifecycle before the
     * store comes up: only unlocked development states permit a foreign-pool
     * wipe (see wt_hsm_set_boot_lifecycle). */
    if (handoffRet == 0) {
        wt_hsm_set_boot_lifecycle(bootHandoff.lifecycle);
    }
#endif
#ifdef WT_ENGINE_HSM
    if (wt_hsm_init() != 0) wt_platform_panic();
#else
    if (wt_native_init() != 0) wt_platform_panic();
#endif
    /* WT-FFM-0050: the vault NVM is live and no guest has dispatched, so the
     * monotonic version floors gate every domain now. A missing handoff
     * reports version zero, which fails closed once a floor is armed. */
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    (void)wt_hsm_rollback_enforce((handoffRet == 0) ?
                                  bootHandoff.image_version : 0u);
#else
    (void)wt_hsm_rollback_enforce(0u);
#endif
#ifdef WT_ENGINE_HSM
    /* WT-FFM-0054: every guest server binds the secure relay capture
     * transport — packets arrive only through SERVICE_HSM's mediated
     * psa_call path, never a shared NS-RAM window. */
    for (wt_guest_id_t gid = 0u; gid < WT_MAX_GUESTS; gid++) {
        const wt_guest_config_t *configs;
        size_t cfg_count;
        configs = wt_partitions_config_table(&cfg_count);
        if (configs == NULL || gid >= cfg_count) break;
        if (wt_hsm_guest_init_relay(gid) != 0) {
            wt_platform_panic();
        }
    }
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (wt_hsm_attest_bootstrap() != WH_ERROR_OK) {
        /* The vault could not be provisioned and auto-reformat was not
         * permitted (a foreign or corrupt pool on a SECURED device). Boot
         * degraded rather than dead-trap: attestation fails closed and the
         * condition is observable, never a mute HardFault. */
        g_wt_attest_degraded = 1u;
    }
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (handoffRet == 0) {
        if (wt_initial_attest_init(&bootHandoff) != WT_ATTEST_SUCCESS) {
            /* Attestation could not initialize (e.g. the IAK was unavailable on
             * a fail-closed vault). Degrade rather than dead-trap: the service
             * returns errors, the rest of the system boots. */
            g_wt_attest_degraded = 1u;
        }
    }
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (handoffRet == 0) {
        wt_ffm_set_lifecycle(wt_ffm_boot_runtime_mut(), bootHandoff.lifecycle);
    }
#endif
    /* P1t: the service partitions become scheduled unprivileged coroutines.
     * Fail closed — guests depend on them. */
    if (wt_ffm_boot_start_sched() != WT_FFM_SUCCESS) {
        wt_platform_panic();
    }
#if defined(WT_REMEASURE_PROBE)
    wt_platform_remeasure_probe();
#endif
#if defined(WT_BOOTUPDATE_PROBE)
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    wt_platform_bootupdate_probe((handoffRet == 0) ?
                                 bootHandoff.image_version : 0u);
#else
    wt_platform_bootupdate_probe(0u);
#endif
#endif
    wt_monitor_start();
    wt_platform_panic();
}
