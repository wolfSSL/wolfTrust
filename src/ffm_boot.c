/* ffm_boot.c
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

#include "wolftrust/ffm_boot.h"

#include "wolftrust/spm_sched.h"
#include "psa_manifest/pid.h"

/* The manifest carries the update partition exactly when WT_FWU builds it;
 * the conformance manifest never does. */
#if defined(PARTITION_FWU_ID) && !defined(WT_FWU)
#error "the manifest declares PARTITION_FWU but WT_FWU is off"
#endif
#if defined(WT_FWU) && !defined(PARTITION_FWU_ID) && \
    !(defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1))
#error "WT_FWU=1 but the manifest has no PARTITION_FWU"
#endif

void wt_ffm_boot_init(void)
{
    wt_spm_core_init();
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Arm PSA-FF conformance partitions (P3a): the unmodified upstream service
 * loops, scheduled like any other SP. */
extern void server_main(void);
extern void client_main(void);
extern void driver_main(void);

static void wt_conformance_server_entry(void* arg)
{
    (void)arg;
    server_main();
}

static void wt_conformance_client_entry(void* arg)
{
    (void)arg;
    client_main();
}

static void wt_conformance_driver_entry(void* arg)
{
    (void)arg;
    driver_main();
}
#endif

int wt_ffm_boot_start_sched(void)
{
    int ret;

    /* Launch by compile-time entry function, never by domain->entry_point: in
     * this single-image build entry_point holds the domain's flash base (a boot
     * integrity gate, not a linked address), so branching through it faults. */
    ret = wt_spm_hsm_start(&g_wt_spm, PARTITION_HSM_ID);
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_vault_start(&g_wt_spm, PARTITION_VAULT_ID);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_its_start(&g_wt_spm, PARTITION_ITS_ID);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_ps_start(&g_wt_spm, PARTITION_PS_ID);
    }
#ifdef PARTITION_FWU_ID
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_fwu_start(&g_wt_spm, PARTITION_FWU_ID);
    }
#endif
#ifdef PARTITION_VNET_ID
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_vnet_start(&g_wt_spm, PARTITION_VNET_ID);
    }
#endif
#if defined(WT_INTERFACE_PARTITION_ID)
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_interface_start(&g_wt_spm, WT_INTERFACE_PARTITION_ID);
    }
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* SERVICE_ATTEST now runs as a scheduled Secure Partition; the inline
     * dispatch registered in wt_ffm_boot_init is replaced by this coroutine. */
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_attest_start(&g_wt_spm, PARTITION_ATTEST_ID);
    }
#endif
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_add(&g_wt_spm, SERVER_PARTITION_ID,
                               wt_conformance_server_entry, NULL, NULL);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_add(&g_wt_spm, CLIENT_PARTITION_ID,
                               wt_conformance_client_entry, NULL, NULL);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_add(&g_wt_spm, DRIVER_PARTITION_ID,
                               wt_conformance_driver_entry, NULL, NULL);
    }
#endif
#if WT_MANIFEST_RUNTIME_CHECK || \
    (defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1))
    /* The generator proves the manifest tables; conformance adds grants. */
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_validate();
    }
#endif
#if defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)
    if (ret == WT_FFM_SUCCESS) {
#if (WT_BAND_NEG_PROBE <= 2)
        wt_spm_sched_prime(PARTITION_HSM_ID);
#elif (WT_BAND_NEG_PROBE <= 4)
        wt_spm_sched_prime(PARTITION_ATTEST_ID);
#else
        wt_spm_sched_prime(PARTITION_VAULT_ID);
#endif
    }
#endif
#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
    if (ret == WT_FFM_SUCCESS) {
#if (WT_RESTART_NEG_PROBE == 1)
        wt_spm_sched_prime(PARTITION_HSM_ID);
#elif (WT_RESTART_NEG_PROBE == 2)
        wt_spm_sched_prime(PARTITION_ATTEST_ID);
#else
        wt_spm_sched_prime(PARTITION_VAULT_ID);
#endif
    }
#endif
#if defined(WT_INTERFACE_NEG_PROBE) && (WT_INTERFACE_NEG_PROBE == 1)
    if (ret == WT_FFM_SUCCESS) {
        wt_spm_sched_prime(PARTITION_HSM_ID);
        wt_spm_sched_prime(WT_INTERFACE_PARTITION_ID);
    }
#endif
#if !defined(WT_SP_LAZY_FIRST_ENTRY)
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_start_all();
    }
#endif
    return ret;
}
