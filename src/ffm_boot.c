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

#include "wolftrust/platform.h"
#include "wolftrust/spm_sched.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/fwu_service.h"
#include "wolftrust/services/vnet_relay.h"
#include "wolftrust/services/storage_service.h"
#include "wolftrust/services/vault_service.h"
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
#include "wolftrust/services/attestation_service.h"
#endif
#include "psa_manifest/pid.h"

static wt_ffm_runtime_t g_ffm_runtime;

/* WT-FFM-0012: NS callers are validated by the installed NS-window checks.
 * Positive Secure-Partition callers are accepted here because wt_spm_gate
 * validates each dereferenced SP pointer against that caller's resolved
 * protection domain. Service nonsecure_clients policy is independent of
 * these pointer checks. */
static int wt_ffm_boot_caller_guest(psa_client_id_t caller,
                                    wt_guest_id_t* guest_id)
{
    if (caller >= 0) {
        return 0;
    }
    *guest_id = (wt_guest_id_t)(-caller - 1);
    return 1;
}

/* NS-window checks are installed by the architecture port (Armv8-M:
 * wt_ffm_gateway_install). NULL fails closed: every NS window is rejected until
 * a port provides its checker. */
static wt_ffm_ns_check_read_fn g_ns_check_read;
static wt_ffm_ns_check_write_fn g_ns_check_write;

void wt_ffm_boot_set_memcheck(wt_ffm_ns_check_read_fn check_read,
                              wt_ffm_ns_check_write_fn check_write)
{
    g_ns_check_read = check_read;
    g_ns_check_write = check_write;
}

static int wt_ffm_boot_check_read(void* context, psa_client_id_t caller,
                                  const void* address, size_t size)
{
    wt_guest_id_t guest_id;

    (void)context;
    /* Positive callers are Secure Partitions whose pointers the SPM gate
     * already bounded to their own protection domain (WT-FFM-0014); the
     * installed checks only describe Non-secure windows. */
    if (caller > 0) {
        return 1;
    }
    if (!wt_ffm_boot_caller_guest(caller, &guest_id)) {
        return 0;
    }
    if (g_ns_check_read == NULL) {
        return 0;
    }
    return g_ns_check_read(guest_id, address, size);
}

static int wt_ffm_boot_check_write(void* context, psa_client_id_t caller,
                                   void* address, size_t size)
{
    wt_guest_id_t guest_id;

    (void)context;
    if (caller > 0) {
        return 1;
    }
    if (!wt_ffm_boot_caller_guest(caller, &guest_id)) {
        return 0;
    }
    if (g_ns_check_write == NULL) {
        return 0;
    }
    return g_ns_check_write(guest_id, address, size);
}

/* Fail-closed fallback for a partition with no registered service loop.
 * Services bind their dispatch handler through wt_ffm_register_partition in
 * wt_ffm_boot_init, so the manifest-bound partition table routes each message
 * rather than a per-PID branch here. */
static int wt_ffm_boot_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                int32_t partition_id)
{
    (void)context;
    (void)runtime;
    (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

static void wt_ffm_boot_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
    wt_platform_panic();
}

static const wt_ffm_port_ops_t g_ffm_port_ops = {
    wt_ffm_boot_check_read,
    wt_ffm_boot_check_write,
    wt_ffm_boot_dispatch,
    wt_ffm_boot_panic
};

/* The direct src/ffm_api.c psa_* binding is host-only: on target every
 * psa_* call from a Secure Partition crosses the SVC gate instead
 * (src/arch/armv8m/spm_sp_api.c), so nothing binds the identity ops here. */
int wt_ffm_boot_init(const wt_system_manifest_t* manifest)
{
    int ret;
    int vault_ret;

    ret = wt_ffm_init(&g_ffm_runtime, manifest, &g_ffm_port_ops, NULL);
    if (ret == WT_FFM_SUCCESS) {
        /* SERVICE_HSM: the single mediated door to the wolfHSM server
         * (WT-FFM-0054). Fail-closed until the platform installs the relay
         * submit hook. */
        ret = wt_ffm_register_partition(&g_ffm_runtime, PARTITION_HSM_ID,
                                        wt_hsm_relay_dispatch, NULL);
    }
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_ffm_register_partition(&g_ffm_runtime, PARTITION_ATTEST_ID,
                                        wt_attestation_service_dispatch, NULL);
    }
#endif
    if (ret == WT_FFM_SUCCESS) {
        /* Manifest-optional vault + ITS: host fixtures without these
         * partitions run without them (the services fail closed); target
         * boot enforces scheduling in wt_ffm_boot_start_sched. */
        vault_ret = wt_ffm_register_partition(&g_ffm_runtime,
                                              PARTITION_VAULT_ID,
                                              wt_vault_service_dispatch, NULL);
        (void)vault_ret;
        vault_ret = wt_ffm_register_partition(&g_ffm_runtime,
                                              PARTITION_ITS_ID,
                                              wt_storage_service_dispatch,
                                              NULL);
        (void)vault_ret;
        vault_ret = wt_ffm_register_partition(&g_ffm_runtime,
                                              PARTITION_PS_ID,
                                              wt_storage_service_dispatch,
                                              NULL);
        (void)vault_ret;
#ifdef PARTITION_FWU_ID
        vault_ret = wt_ffm_register_partition(&g_ffm_runtime,
                                              PARTITION_FWU_ID,
                                              wt_fwu_service_dispatch, NULL);
        (void)vault_ret;
#endif
#ifdef PARTITION_VNET_ID
        vault_ret = wt_ffm_register_partition(&g_ffm_runtime,
                                              PARTITION_VNET_ID,
                                              wt_vnet_relay_dispatch, NULL);
        (void)vault_ret;
#endif
    }
    return ret;
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
    ret = wt_spm_hsm_start(&g_ffm_runtime, PARTITION_HSM_ID);
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_vault_start(&g_ffm_runtime, PARTITION_VAULT_ID);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_its_start(&g_ffm_runtime, PARTITION_ITS_ID);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_ps_start(&g_ffm_runtime, PARTITION_PS_ID);
    }
#ifdef PARTITION_FWU_ID
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_fwu_start(&g_ffm_runtime, PARTITION_FWU_ID);
    }
#endif
#ifdef PARTITION_VNET_ID
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_vnet_start(&g_ffm_runtime, PARTITION_VNET_ID);
    }
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* SERVICE_ATTEST now runs as a scheduled Secure Partition; the inline
     * dispatch registered in wt_ffm_boot_init is replaced by this coroutine. */
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_attest_start(&g_ffm_runtime, PARTITION_ATTEST_ID);
    }
#endif
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_add(&g_ffm_runtime, SERVER_PARTITION_ID,
                               wt_conformance_server_entry, NULL);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_add(&g_ffm_runtime, CLIENT_PARTITION_ID,
                               wt_conformance_client_entry, NULL);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_add(&g_ffm_runtime, DRIVER_PARTITION_ID,
                               wt_conformance_driver_entry, NULL);
    }
#endif
    return ret;
}

const wt_ffm_runtime_t* wt_ffm_boot_runtime(void)
{
    return &g_ffm_runtime;
}

wt_ffm_runtime_t* wt_ffm_boot_runtime_mut(void)
{
    return &g_ffm_runtime;
}
