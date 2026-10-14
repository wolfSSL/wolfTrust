/* spm_partitions.c
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

/* Secure Partition entry bodies and their scheduler registration: each
 * service loop runs as a confined SP coroutine over the neutral SP-side
 * transport. Deliberate test faults go through wt_arch_sp_fault_probe(). */

#include "wolftrust/spm_transport.h"

#include "wolftrust/ffm.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/monitor.h"
#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/sched/coroutine.h"
#include "wolftrust/sched/coroutine_internal.h"
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
#include "wolftrust/services/attestation_service.h"
#endif
#include "wolfhsm/wh_flash.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/services/fwu_service.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/nvm_client.h"
#include "wolftrust/nvm_store.h"
#include "wolftrust/boot.h"
#include "wolftrust/boot_handoff.h"
#include "wolftrust/partition.h"
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
#include "wolftrust/services/initial_attestation.h"
#endif
#ifndef WT_ENGINE_HSM
#include "wolftrust/services/crypto_native.h"
#endif
#include "wolftrust/sync/mutex.h"
#include "wolftrust/services/storage_service.h"
#include "wolftrust/services/vault_service.h"
#if defined(CONFIG_VNET)
#include "wolftrust/services/vnet_relay.h"
#include "wolftrust/services/vnet_service.h"
#endif
#if defined(CONFIG_TPM)
#include "wolftrust/services/tpm_relay.h"
#if defined(WT_INTERFACE_LOCAL_PROVIDER)
#include "wolftrust/services/tpm_local_provider.h"
#endif
#endif
#if defined(CONFIG_PKCS11)
#include "wolftrust/pkcs11_provider.h"
#include "wolftrust/pkcs11_secure_client.h"
#include "wolftrust/services/pkcs11_relay.h"
#endif
#include "wolftrust/sp_recovery.h"
#include "wolftrust/spm_gate.h"

#include <string.h>

/* Generated in every secure build; the ITS entry embeds SERVICE_VAULT_SID as
 * a code constant — the unprivileged loop cannot read SPM RAM at runtime. */
#include "psa_manifest/pid.h"
#include "psa_manifest/sid.h"

/* Port flash staging backend (WT-FWU-0002), driven by the FWU partition
 * through the gate's privileged backend ops. */
extern const wt_fwu_backend_t wt_fwu_flash_backend;

#if defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)
/* A keystore service the prober does not own must be refused at the gate;
 * reaching the privileged backend would be a privilege escape, so trap with
 * a fault the scenario does not expect. */
static void wt_spm_band_probe_refused(wt_spm_op_t op, int32_t sub_op)
{
    wt_spm_call_t pin;
    uint8_t scratch[4];

    (void)memset(&pin, 0, sizeof(pin));
    pin.op = op;
    pin.call_type = sub_op;
    if (op == WT_SPM_OP_KEYSTORE_ENTROPY) {
        pin.buffer = scratch;
        pin.num_bytes = sizeof(scratch);
    }
    if (wt_arch_sp_trap(&pin) != WT_FFM_ERROR_ARGUMENT) {
        wt_arch_sp_fault_probe(1u);
    }
}

/* Band isolation proof (WT-FFM-0011): the prober reads another partition's
 * data band, and after its restart writes it; both must MemManage-fault
 * inside the prober. Its third run serves normally. Never built into
 * production images. */
static void wt_spm_band_probe(void* arg, unsigned int target)
{
    volatile uint32_t* band =
        (volatile uint32_t*)wt_platform_probe_address(target);
    volatile uint32_t seen;

    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        seen = *band;
        (void)seen;
        wt_arch_sp_fault_probe(3u);
    }
    else if (((intptr_t)arg & WT_SP_FAULT_PROBE_SECOND) == 0) {
        *band = 0xA5A5A5A5u;
        wt_arch_sp_fault_probe(4u);
    }
}

#define WT_BAND_PROBE_ID(arg) \
    ((int32_t)((intptr_t)(arg) & ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED & \
               ~(intptr_t)WT_SP_FAULT_PROBE_SECOND))
#endif

#if defined(WT_TPM_NEG_PROBE) && (WT_TPM_NEG_PROBE == 1)
#define WT_TPM_PROBE_ID(arg) \
    ((int32_t)((intptr_t)(arg) & ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED & \
               ~(intptr_t)WT_SP_FAULT_PROBE_SECOND))

/* Prove that an unrelated partition cannot read or write TPMDATA. */
static void wt_spm_tpm_band_probe(void* arg)
{
    volatile uint32_t* band = (volatile uint32_t*)
        wt_platform_probe_address(WT_PROBE_TPM_DATA_BAND);
    volatile uint32_t seen;

    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        seen = *band;
        (void)seen;
        wt_arch_sp_fault_probe(3u);
    }
    else if (((intptr_t)arg & WT_SP_FAULT_PROBE_SECOND) == 0) {
        *band = 0xA5A5A5A5u;
        wt_arch_sp_fault_probe(4u);
    }
}

/* Prove that the relay cannot bypass IPC or execute from its data band. */
static void wt_spm_tpm_partition_probe(void* arg)
{
    volatile uint32_t seen;
    void (*xn_probe)(void);

    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        if (wt_tpm_relay_restart_probe(1) == 0) {
            wt_arch_sp_fault_probe(2u);
        }
        (void)wt_tpm_relay_restart_probe(0);
        seen = *(const volatile uint32_t*)
            wt_platform_probe_address(WT_PROBE_TPM_FTPM_RAM);
        (void)seen;
        wt_arch_sp_fault_probe(3u);
    }
    else if (((intptr_t)arg & WT_SP_FAULT_PROBE_SECOND) == 0) {
        if (wt_tpm_relay_restart_probe(1) == 0) {
            wt_arch_sp_fault_probe(2u);
        }
        xn_probe = (void (*)(void))
            (wt_platform_probe_address(WT_PROBE_TPM_DATA_BAND) | 1u);
        xn_probe();
        wt_arch_sp_fault_probe(4u);
    }
}
#endif

#if defined(WT_PKCS11_NEG_PROBE) && (WT_PKCS11_NEG_PROBE == 1)
#define WT_PKCS11_PROBE_ID(arg) \
    ((int32_t)((intptr_t)(arg) & ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED & \
               ~(intptr_t)WT_SP_FAULT_PROBE_SECOND))

/* Prove that an unrelated partition cannot read or write PKCS11DATA. */
static void wt_spm_pkcs11_band_probe(void* arg)
{
    volatile uint32_t* band = (volatile uint32_t*)
        wt_platform_probe_address(WT_PROBE_PKCS11_DATA_BAND);
    volatile uint32_t seen;

    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        seen = *band;
        (void)seen;
        wt_arch_sp_fault_probe(3u);
    }
    else if (((intptr_t)arg & WT_SP_FAULT_PROBE_SECOND) == 0) {
        *band = 0xA5A5A5A5u;
        wt_arch_sp_fault_probe(4u);
    }
}

/* Prove that the relay cannot bypass IPC or execute from its data band. */
static void wt_spm_pkcs11_partition_probe(void* arg)
{
    volatile uint32_t seen;
    void (*xn_probe)(void);

    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        if (wt_pkcs11_relay_restart_probe(1) == 0) {
            wt_arch_sp_fault_probe(2u);
        }
        (void)wt_pkcs11_relay_restart_probe(0);
        seen = *(const volatile uint32_t*)
            wt_platform_probe_address(WT_PROBE_PKCS11_PROVIDER_RAM);
        (void)seen;
        wt_arch_sp_fault_probe(3u);
    }
    else if (((intptr_t)arg & WT_SP_FAULT_PROBE_SECOND) == 0) {
        if (wt_pkcs11_relay_restart_probe(1) == 0) {
            wt_arch_sp_fault_probe(2u);
        }
        xn_probe = (void (*)(void))
            (wt_platform_probe_address(WT_PROBE_PKCS11_DATA_BAND) | 1u);
        xn_probe();
        wt_arch_sp_fault_probe(4u);
    }
}
#endif

#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
/* Restart proof (WT-FFM-0051): the partition plants state in its own band
 * and faults; its restarted instance must find the band's link-time image.
 * Never built into production images. */
static void wt_spm_restart_probe(void* arg, int (*probe)(int restarted))
{
    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        (void)probe(0);
        wt_arch_sp_fault_probe(0u);
    }
    else if (probe(1) == 0) {
        wt_arch_sp_fault_probe(2u);
    }
}

#define WT_RESTART_PROBE_ID(arg) \
    ((int32_t)((intptr_t)(arg) & ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED))
#endif

/* SERVICE_HSM's relay loop: a confined scheduled SP. The submit pump reaches
 * the crypto engine state in the partition's own data band; persistent key
 * objects go through SERVICE_VAULT, entropy traps to the SVC gate. */
static void wt_spm_hsm_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;
#if defined(WT_SP_FAULT_ALWAYS_PROBE) && (WT_SP_FAULT_ALWAYS_PROBE == 1)
    /* Budget-exhaustion probe (target/spbudgetneg): fault on every entry so
     * the limit-plus-one fault drives escalation into fail-closed platform
     * recovery (WT-FFM-0017/0051). Never built into production images. */
    wt_arch_sp_fault_probe(0u);
#endif
#if (defined(WT_SP_FAULT_PROBE) && (WT_SP_FAULT_PROBE == 1)) || \
    (defined(WT_BUSFAULT_NEG_PROBE) && (WT_BUSFAULT_NEG_PROBE == 1))
    /* One-shot graceful-recovery probes (target/spfaultneg, busfaultneg): an
     * undefined instruction, or a read of the port's bus-error window, raises
     * a recoverable Secure-Thread fault. The recovery re-arms this partition
     * with the restarted marker set, so the re-run skips the probe. */
    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
#if defined(WT_BUSFAULT_NEG_PROBE) && (WT_BUSFAULT_NEG_PROBE == 1)
        wt_memory_region_t probe;

        wt_platform_busfault_probe_region(&probe);
        (void)*(const volatile uint32_t*)(uintptr_t)probe.base;
#else
        wt_arch_sp_fault_probe(0u);
#endif
    }
    partition_id = (int32_t)((intptr_t)arg &
                             ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED);
#endif
#if defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)
    partition_id = WT_BAND_PROBE_ID(arg);
    wt_spm_band_probe_refused(WT_SPM_OP_KEYSTORE_FLASH,
                              WT_SPM_KS_FLASH_BLANKCHECK);
    wt_spm_band_probe_refused(WT_SPM_OP_KEYSTORE_LOCK,
                              WT_SPM_KS_LOCK_RELEASE);
#if (WT_BAND_NEG_PROBE == 1)
    wt_spm_band_probe(arg, WT_PROBE_VAULT_DATA_BAND);
#elif (WT_BAND_NEG_PROBE == 2)
    wt_spm_band_probe(arg, WT_PROBE_ATTEST_DATA_BAND);
#endif
#endif
#if defined(WT_TPM_NEG_PROBE) && (WT_TPM_NEG_PROBE == 1)
    partition_id = WT_TPM_PROBE_ID(arg);
    wt_spm_tpm_band_probe(arg);
#endif
#if defined(WT_PKCS11_NEG_PROBE) && (WT_PKCS11_NEG_PROBE == 1)
    partition_id = WT_PKCS11_PROBE_ID(arg);
    wt_spm_pkcs11_band_probe(arg);
#endif
#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
    partition_id = WT_RESTART_PROBE_ID(arg);
#if (WT_RESTART_NEG_PROBE == 1)
    wt_spm_restart_probe(arg, wt_hsm_relay_restart_probe);
#endif
#endif
#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
    /* The crypto partition forges its own server pointers for the relay to
     * re-pin on its next pump, and self-verifies the door view's pin. */
    if (wt_platform_hsm_pin_probe() == 0) {
        wt_arch_sp_fault_probe(0u);
    }
#endif

    for (;;) {
        (void)wt_hsm_relay_dispatch(NULL, NULL, partition_id);
    }
}

#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
/* What boot established about the attestation signer, kept in SPM RAM: a
 * restarted crypto partition is rebuilt from this, never from its own band. */
static uint8_t g_spm_iak_public[WT_HSM_ATTEST_PUBLIC_KEY_LEN];
static size_t g_spm_iak_public_len;
#endif

#if defined(WT_ENGINE_HSM) && defined(CONFIG_PKCS11) && \
    defined(WT_INTERFACE_LOCAL_PROVIDER)
static int wt_spm_hsm_init_pkcs11_namespace(void)
{
    if (!wt_hsm_guest_ready((wt_guest_id_t)WT_PKCS11_HSM_NAMESPACE) &&
            wt_hsm_guest_init_relay(
                (wt_guest_id_t)WT_PKCS11_HSM_NAMESPACE) != 0) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
#endif

/* Wire the crypto partition's band to the relay seams and to the vault's
 * door; boot and every restart run the same steps. */
static int wt_spm_hsm_bind(int32_t partition_id)
{
    wt_hsm_relay_set_transport(wt_spm_svc_transport);
    /* Boot provisioned on the direct store; the running partition only ever
     * sees the vault through its door (the client context lives in the
     * crypto partition's own data band, nvm_client.o). */
    if (wt_nvm_client_bind_partition(wt_spm_svc_transport, NULL, partition_id,
                                     SERVICE_VAULT_SID) != 0) {
        return WT_FFM_ERROR_STATE;
    }
#if defined(WT_ENGINE_HSM)
    if (wt_hsm_bind_nvm(wt_nvm_client_partition_nvm()) != 0) {
        return WT_FFM_ERROR_STATE;
    }
#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
    if (wt_hsm_relay_set_secure_client(PARTITION_PKCS11_ID,
            (wt_guest_id_t)WT_PKCS11_HSM_NAMESPACE) != 0) {
        return WT_FFM_ERROR_STATE;
    }
#endif
    wt_hsm_relay_set_submit(wt_hsm_relay_submit, NULL);
#else
    /* Native engine: SERVICE_HSM stays the single mediated door; its packets
     * carry the native wire and dispatch straight into wolfCrypt. */
    if (wt_native_bind_nvm(wt_nvm_client_partition_nvm()) != 0) {
        return WT_FFM_ERROR_STATE;
    }
    wt_hsm_relay_set_submit(wt_native_submit, (void*)(intptr_t)partition_id);
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    wt_hsm_relay_set_attest_ops(PARTITION_ATTEST_ID, wt_hsm_attest_sign,
                                wt_hsm_attest_public_key);
#endif
    return WT_FFM_SUCCESS;
}

static int wt_spm_hsm_restore(int32_t partition_id)
{
#if defined(WT_ENGINE_HSM)
    const wt_guest_config_t* configs;
    size_t cfg_count = 0u;
    wt_guest_id_t gid;

    configs = wt_partitions_config_table(&cfg_count);
    for (gid = 0u; configs != NULL && gid < WT_MAX_GUESTS &&
            gid < cfg_count; gid++) {
        if (wt_hsm_guest_init_relay(gid) != 0) {
            return WT_FFM_ERROR_STATE;
        }
    }
#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
    if (wt_spm_hsm_init_pkcs11_namespace() != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
#endif
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (wt_hsm_attest_restore((g_spm_iak_public_len != 0u) ?
                              g_spm_iak_public : NULL,
                              g_spm_iak_public_len) != 0) {
        return WT_FFM_ERROR_STATE;
    }
#endif
    return wt_spm_hsm_bind(partition_id);
}

int wt_spm_hsm_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    int ret;

#if defined(WT_ENGINE_HSM) && defined(CONFIG_PKCS11) && \
    defined(WT_INTERFACE_LOCAL_PROVIDER)
    ret = wt_spm_hsm_init_pkcs11_namespace();
    if (ret != WT_FFM_SUCCESS) {
        return ret;
    }
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* Taken before the store is rebound to the door view, which the boot
     * context cannot call through. */
    g_spm_iak_public_len = 0u;
    if (wt_hsm_attest_public_key(g_spm_iak_public, sizeof(g_spm_iak_public),
                                 &g_spm_iak_public_len) != 0) {
        g_spm_iak_public_len = 0u;
    }
#endif
    ret = wt_spm_hsm_bind(partition_id);
    if (ret != WT_FFM_SUCCESS) {
        return ret;
    }
    wt_spm_set_hsm_partition(partition_id);
    ret = wt_spm_sched_add(runtime, partition_id, wt_spm_hsm_entry,
                           (void*)(intptr_t)partition_id);
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_set_restore(partition_id, wt_spm_hsm_restore);
    }
    return ret;
}

#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
/* SERVICE_ATTEST's dispatch loop: a confined scheduled SP. The token state
 * lives in the partition's own data band; the IAK stays with the crypto
 * partition, reached through SERVICE_HSM's attestation door, and the boot
 * measurements come from the SVC gate's read-only snapshot. */
static void wt_spm_attest_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;

#if defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)
    partition_id = WT_BAND_PROBE_ID(arg);
    wt_spm_band_probe_refused(WT_SPM_OP_KEYSTORE_FLASH,
                              WT_SPM_KS_FLASH_BLANKCHECK);
    wt_spm_band_probe_refused(WT_SPM_OP_KEYSTORE_LOCK,
                              WT_SPM_KS_LOCK_RELEASE);
    wt_spm_band_probe_refused(WT_SPM_OP_KEYSTORE_ENTROPY, 0);
#if (WT_BAND_NEG_PROBE == 3)
    wt_spm_band_probe(arg, WT_PROBE_VAULT_DATA_BAND);
#elif (WT_BAND_NEG_PROBE == 4)
    wt_spm_band_probe(arg, WT_PROBE_HSM_DATA_BAND);
#endif
#endif
#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
    partition_id = WT_RESTART_PROBE_ID(arg);
#if (WT_RESTART_NEG_PROBE == 2)
    wt_spm_restart_probe(arg, wt_attestation_restart_probe);
#endif
#endif
    for (;;) {
        (void)wt_attestation_service_dispatch(NULL, NULL, partition_id);
    }
}

static int wt_spm_attest_bind(int32_t partition_id)
{
    wt_attestation_service_set_transport(wt_spm_svc_transport);
    if (wt_initial_attest_bind_hsm(wt_spm_svc_transport, NULL, partition_id,
                                   SERVICE_HSM_SID) != WT_ATTEST_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static int wt_spm_attest_restore(int32_t partition_id)
{
    const wt_boot_handoff_t* handoff = wt_boot_handoff_retained();

    /* As at boot, a handoff the partition cannot take leaves attestation
     * degraded (every request fails closed), not the restart refused. */
    if (handoff != NULL) {
        (void)wt_initial_attest_init(handoff);
    }
    return wt_spm_attest_bind(partition_id);
}

int wt_spm_attest_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    int ret;

    ret = wt_spm_attest_bind(partition_id);
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_add(runtime, partition_id, wt_spm_attest_entry,
                               (void*)(intptr_t)partition_id);
    }
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_set_restore(partition_id, wt_spm_attest_restore);
    }
    return ret;
}
#endif /* WT_ATTEST_COSE */

/* The vault partition's service loop: a confined scheduled SP. The NVM
 * store, its flash context, the sealer, and the service seams live in the
 * partition's own data band; flash, entropy, and the NVM lock trap to the
 * SVC gate. */
static void wt_spm_vault_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;

#if defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)
    partition_id = WT_BAND_PROBE_ID(arg);
#if (WT_BAND_NEG_PROBE == 5)
    wt_spm_band_probe(arg, WT_PROBE_ATTEST_DATA_BAND);
#elif (WT_BAND_NEG_PROBE == 6)
    wt_spm_band_probe(arg, WT_PROBE_HSM_DATA_BAND);
#endif
#endif
#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
    partition_id = WT_RESTART_PROBE_ID(arg);
#if (WT_RESTART_NEG_PROBE == 3)
    wt_spm_restart_probe(arg, wt_vault_restart_probe);
#endif
#endif
#if defined(WT_DEPUTY_NEG_PROBE) && (WT_DEPUTY_NEG_PROBE == 1)
    /* Privileged-deputy proof (WT-FFM-0011): the vault owns the writable flash
     * context, so it forges the base and size to aim the privileged NVM path at
     * SPM RAM across every primitive. A return of 0 means a byte could leak or
     * a primitive failed to refuse (the fix is absent); fault so the scenario
     * fails. Runs once before the dispatch loop; no SPM-private guard is
     * touched, which the unprivileged partition could not read. */
    if (wt_platform_deputy_flash_probe() == 0) {
        wt_arch_sp_fault_probe(2u);
    }
#endif
#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
    /* The vault owns the direct store and self-verifies its chain's pin. A
     * failed heal faults here so the scenario fails loudly instead of
     * proceeding on forged state (WT-FFM-0011). */
    if (wt_nvm_store_pin_probe() == 0) {
        wt_arch_sp_fault_probe(0u);
    }
#endif
    for (;;) {
        (void)wt_vault_service_dispatch(NULL, NULL, partition_id);
    }
}

static void wt_spm_vault_bind(void)
{
    wt_vault_service_set_transport(wt_spm_svc_transport);
    wt_vault_service_set_keystore_client(PARTITION_HSM_ID);
}

static int wt_spm_vault_restore(int32_t partition_id)
{
    (void)partition_id;
    if (wt_nvm_vault_bind() != 0) {
        return WT_FFM_ERROR_STATE;
    }
    wt_spm_vault_bind();
    return WT_FFM_SUCCESS;
}

int wt_spm_vault_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    int ret;

    /* The vault must run as a scheduled coroutine: every op takes the NVM
     * path, whose mutex cannot be held from the bootstrap context. */
    wt_spm_vault_bind();
    ret = wt_spm_sched_add(runtime, partition_id, wt_spm_vault_entry,
                           (void*)(intptr_t)partition_id);
    if (ret == WT_FFM_SUCCESS) {
        ret = wt_spm_sched_set_restore(partition_id, wt_spm_vault_restore);
    }
    return ret;
}

/* The ITS partition's service loop: a normal UNPRIVILEGED scheduled SP.
 * Context lives on its own stack — the narrowed MPU domain cannot read the
 * service's file-scope seams in SPM RAM. */
static void wt_spm_its_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;
    wt_storage_service_ctx_t ctx;
#if defined(WT_PERIPH_SP_NEG_PROBE) && (WT_PERIPH_SP_NEG_PROBE == 1)
    volatile uint32_t periph_probe;
#endif

#if (defined(WT_PANIC_NEG_PROBE) && (WT_PANIC_NEG_PROBE == 1)) || \
    (defined(WT_SVC_NEG_PROBE) && (WT_SVC_NEG_PROBE == 1))
    /* Secure-caller-misuse proofs (target/panicneg, svcneg): closing an
     * error-status handle, or issuing the scheduler's internal SVC, is an
     * FF-M PROGRAMMER ERROR the production SPM must panic this partition
     * for; the graceful recovery restarts it with the marker set and the
     * re-run serves storage normally. Reaching the udf below means the SPM
     * failed to panic the caller. Never built into production images. */
    partition_id = (int32_t)((intptr_t)arg &
                             ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED);
    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
#if defined(WT_SVC_NEG_PROBE) && (WT_SVC_NEG_PROBE == 1)
        wt_arch_sp_guest_return_probe();
#else
        wt_spm_call_t bad;

        (void)memset(&bad, 0, sizeof(bad));
        bad.op = WT_SPM_OP_CLOSE;
        bad.msg_handle = (psa_handle_t)-135;
        (void)wt_arch_sp_trap(&bad);
#endif
        wt_arch_sp_fault_probe(3u);
    }
#endif
    ctx.transport = wt_spm_svc_transport;
    ctx.vault_sid = SERVICE_VAULT_SID;
    ctx.vault_handle = 0;
    ctx.client_flags_mask = WT_VAULT_FLAG_WRITE_ONCE;
    ctx.vault_flags = 0U;
    ctx.caps = 0U;

    for (;;) {
#if defined(WT_KEYSTORE_NEG_PROBE) && (WT_KEYSTORE_NEG_PROBE == 1)
        /* Keystore-band isolation proof (WT-FFM-0062): the ITS partition is a
         * non-keystore SP whose domain grants none of the keystore data
         * bands, so this read must MemManage-fault. Placed in ITS (which runs
         * on every guest storage op) rather than FWU (which never runs without
         * a client). Its own build so it never races the crossdomain probe.
         * Never built into production images. */
        volatile uint32_t ks_probe;
        ks_probe = *(const volatile uint32_t*)
            wt_platform_probe_address(WT_PROBE_KEYSTORE_BAND);
        (void)ks_probe;
#endif
#if defined(WT_FFM_NEGATIVE_PROBE) && (WT_FFM_NEGATIVE_PROBE == 1)
        /* Negative isolation proof (WT-FFM-0011): an unprivileged read of
         * SPM-private RAM from inside the SP domain must MemManage-fault.
         * Never built into production images. */
        wt_spm_call_t pin;
        volatile uint32_t probe;

        /* Gate-pin proof (WT-FFM-0061/0062): a staging-backend or keystore
         * request from a non-owning partition must be refused at the SVC;
         * reaching either privileged backend from here would be a privilege
         * escape, so trap hard (unexpected extra fault fails the scenario)
         * instead of continuing to the expected MPU probe below. */
        (void)memset(&pin, 0, sizeof(pin));
        pin.op = WT_SPM_OP_FWU_BACKEND;
        pin.call_type = WT_SPM_FWU_BEGIN;
        if (wt_arch_sp_trap(&pin) != WT_FFM_ERROR_ARGUMENT) {
            wt_arch_sp_fault_probe(1u);
        }
        (void)memset(&pin, 0, sizeof(pin));
        pin.op = WT_SPM_OP_KEYSTORE_FLASH;
        pin.call_type = WT_SPM_KS_FLASH_ERASE;
        if (wt_arch_sp_trap(&pin) != WT_FFM_ERROR_ARGUMENT) {
            wt_arch_sp_fault_probe(2u);
        }
        probe = *(const volatile uint32_t*)
            wt_platform_probe_address(WT_PROBE_OUT_OF_DOMAIN);
        (void)probe;
#endif
#if defined(WT_PERIPH_SP_NEG_PROBE) && (WT_PERIPH_SP_NEG_PROBE == 1)
        /* WT-FFM-0068 negative: the SPM's own RNG is not in this partition's
         * domain, so an unprivileged read of it must MemManage-fault. */
        periph_probe = *(const volatile uint32_t*)
            wt_platform_probe_address(WT_PROBE_SPM_PERIPHERAL);
        (void)periph_probe;
#endif
        (void)wt_storage_service_dispatch(&ctx, NULL, partition_id);
    }
}

int wt_spm_its_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    return wt_spm_sched_add(runtime, partition_id, wt_spm_its_entry,
                            (void*)(intptr_t)partition_id);
}

/* The PS partition uses the same unprivileged storage loop, but every request
 * is forwarded SEALED. AES-GCM and rollback binding run in the confined vault
 * partition using the device-unique wolfHSM key (WT-FFM-0048). The NO_*
 * client hints are accepted and recorded, never
 * honoured downward: wolfTrust always stores at full strength. */
static void wt_spm_ps_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;
    wt_storage_service_ctx_t ctx;

    ctx.transport = wt_spm_svc_transport;
    ctx.vault_sid = SERVICE_VAULT_SID;
    ctx.vault_handle = 0;
    ctx.client_flags_mask = WT_VAULT_FLAG_WRITE_ONCE |
                            WT_VAULT_FLAG_NO_CONFIDENTIALITY |
                            WT_VAULT_FLAG_NO_REPLAY;
    ctx.vault_flags = WT_VAULT_FLAG_SEALED;
    ctx.caps = 0U;

    for (;;) {
        (void)wt_storage_service_dispatch(&ctx, NULL, partition_id);
    }
}

int wt_spm_ps_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    return wt_spm_sched_add(runtime, partition_id, wt_spm_ps_entry,
                            (void*)(intptr_t)partition_id);
}

/* Confined FWU staging backend: each op traps to the privileged SVC
 * dispatcher (WT_SPM_OP_FWU_BACKEND), which pins the caller to the FWU
 * partition and runs the port flash backend in handler mode. */
static int wt_spm_fwu_gate_op(int32_t sub_op, uint32_t offset,
                              const uint8_t* data, uint32_t size,
                              uint32_t version)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_FWU_BACKEND;
    call.call_type = sub_op;
    call.vec_idx = offset;
    call.buffer = (void*)(uintptr_t)data;
    call.num_bytes = size;
    call.version = version;
    if (wt_spm_svc_transport(NULL, &call) != WT_FFM_SUCCESS) {
        return -1;
    }
    return call.ret_int;
}

static int wt_spm_fwu_gate_begin(void* ctx)
{
    (void)ctx;
    return wt_spm_fwu_gate_op(WT_SPM_FWU_BEGIN, 0u, NULL, 0u, 0u);
}

static int wt_spm_fwu_gate_write(void* ctx, uint32_t offset,
                                 const uint8_t* data, uint32_t size)
{
    (void)ctx;
    return wt_spm_fwu_gate_op(WT_SPM_FWU_WRITE, offset, data, size, 0u);
}

static int wt_spm_fwu_gate_arm(void* ctx, uint32_t image_size,
                               uint32_t version)
{
    (void)ctx;
    return wt_spm_fwu_gate_op(WT_SPM_FWU_ARM, 0u, NULL, image_size, version);
}

static int wt_spm_fwu_gate_disarm(void* ctx)
{
    (void)ctx;
    return wt_spm_fwu_gate_op(WT_SPM_FWU_DISARM, 0u, NULL, 0u, 0u);
}

static int wt_spm_fwu_gate_floor(uint32_t* floor)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_FWU_BACKEND;
    call.call_type = WT_SPM_FWU_FLOOR;
    if (wt_spm_svc_transport(NULL, &call) != WT_FFM_SUCCESS ||
            call.ret_int != 0) {
        return -1;
    }
    *floor = call.ret_version;
    return 0;
}

static int wt_spm_fwu_gate_verify(void* ctx, uint32_t staged_size,
                                  uint32_t* header_version)
{
    wt_spm_call_t call;

    (void)ctx;
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_FWU_BACKEND;
    call.call_type = WT_SPM_FWU_VERIFY;
    call.num_bytes = staged_size;
    if (wt_spm_svc_transport(NULL, &call) != WT_FFM_SUCCESS ||
            call.ret_int != 0) {
        return -1;
    }
    *header_version = call.ret_version;
    return 0;
}

static uint32_t wt_spm_fwu_gate_active(void)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_FWU_BACKEND;
    call.call_type = WT_SPM_FWU_ACTIVE;
    if (wt_spm_svc_transport(NULL, &call) != WT_FFM_SUCCESS ||
            call.ret_int != 0) {
        return 0u;
    }
    return call.ret_version;
}

/* The Firmware Update partition (WT-FWU-0001/0002): a confined scheduled SP.
 * Context and the gate backend live on its own stack; capacity/align mirror
 * the port flash backend (rodata, readable from the confined domain). */
static void wt_spm_fwu_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;
    wt_fwu_service_ctx_t ctx;
    wt_fwu_backend_t backend;
    uint32_t version_floor = 0u;

    (void)memset(&backend, 0, sizeof(backend));
    backend.begin = wt_spm_fwu_gate_begin;
    backend.write = wt_spm_fwu_gate_write;
    backend.arm = wt_spm_fwu_gate_arm;
    backend.disarm = wt_spm_fwu_gate_disarm;
    backend.verify = wt_spm_fwu_gate_verify;
    backend.capacity = wt_fwu_flash_backend.capacity;
    backend.align = wt_fwu_flash_backend.align;

    /* WT-FWU-0003: staging enforces the persisted monotonic floor. An
     * unreadable floor proves nothing, so it fails closed by refusing
     * every candidate until a restart can read it. */
    if (wt_spm_fwu_gate_floor(&version_floor) != 0) {
        version_floor = 0xFFFFFFFFu;
    }

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.transport = wt_spm_svc_transport;
    ctx.backend = &backend;
    ctx.backend_ctx = NULL;
    ctx.version_floor = version_floor;
    ctx.active_version = wt_spm_fwu_gate_active();
    ctx.state = PSA_FWU_READY;

    for (;;) {
        (void)wt_fwu_service_dispatch(&ctx, NULL, partition_id);
    }
}

int wt_spm_fwu_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    return wt_spm_sched_add(runtime, partition_id, wt_spm_fwu_entry,
                            (void*)(intptr_t)partition_id);
}

#if defined(CONFIG_VNET)
/* The virtual network partition (WT-FFM-0056): an UNPRIVILEGED scheduled
 * coroutine confined to its manifest domain (code + stack + the vnet data
 * band). The switch state it drives lives in that band, and its time source
 * is the tick the SVC stamps on every gate return — the coroutine never
 * reaches monitor state or any other partition's memory. */
static void wt_spm_vnet_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;

#if defined(WT_VNET_NEG_PROBE) && (WT_VNET_NEG_PROBE == 1)
    /* Negative isolation proof (WT-FFM-0011/0056): the confined vnet
     * partition must fault reading SPM RAM, and again executing from its
     * own (XN) data band; each fault quarantines and restarts it with the
     * marker set, and the pass after both faults serves normally. Never
     * built into production images. */
    volatile uint32_t probe;
    void (*xn_probe)(void);

    partition_id = (int32_t)((intptr_t)arg &
                             ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED &
                             ~(intptr_t)WT_SP_FAULT_PROBE_SECOND);
    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        probe = *(const volatile uint32_t*)
            wt_platform_probe_address(WT_PROBE_OUT_OF_DOMAIN);
        (void)probe;
        wt_arch_sp_fault_probe(3u);
    }
    else if (((intptr_t)arg & WT_SP_FAULT_PROBE_SECOND) == 0) {
        xn_probe = (void (*)(void))
            (wt_platform_probe_address(WT_PROBE_VNET_DATA_BAND) | 1u);
        xn_probe();
        wt_arch_sp_fault_probe(4u);
    }
#endif
    /* The fault scrub zeroes the RESTART_CLEAR data band, which holds both the
     * switch state AND the relay's own wiring pointers (g_vnet_sw, transport).
     * So every entry (first schedule and each restart) rebuilds the switch and
     * re-establishes the wiring before serving — a restart that only rebuilt
     * the switch would dispatch through a zeroed transport/switch pointer. */
    wt_vnet_service_init_state();
    wt_vnet_relay_set_transport(wt_spm_svc_transport);
    wt_vnet_relay_set_switch(wt_vnet_service_switch());
    for (;;) {
        (void)wt_vnet_relay_dispatch(NULL, NULL, partition_id);
    }
}

int wt_spm_vnet_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    return wt_spm_sched_add(runtime, partition_id, wt_spm_vnet_entry,
                            (void*)(intptr_t)partition_id);
}
#endif /* CONFIG_VNET */

#if defined(CONFIG_TPM)
#ifndef WT_TPM_APP_GUEST
#define WT_TPM_APP_GUEST 0
#endif
#ifndef WT_TPM_FTPM_GUEST
#define WT_TPM_FTPM_GUEST 1
#endif
/* SERVICE_TPM: the single mediated door between the application guest and
 * the isolated fwTPM guest. An unprivileged scheduled coroutine confined to
 * its own domain; the one in-flight command/response slot lives in its own
 * data band. Roles bind to the SPM-stamped guest identities (-(N+1)), and a
 * restart re-binds them because the fault scrub zeroes the band. */
static void wt_spm_tpm_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;
#if defined(WT_INTERFACE_LOCAL_PROVIDER)
    void* provider_context = NULL;
#endif

#if defined(WT_TPM_NEG_PROBE) && (WT_TPM_NEG_PROBE == 1)
    partition_id = WT_TPM_PROBE_ID(arg);
    wt_spm_tpm_partition_probe(arg);
#endif
    wt_tpm_relay_set_transport(wt_spm_svc_transport);
#if defined(WT_INTERFACE_LOCAL_PROVIDER)
    if (wt_tpm_local_provider_init(&provider_context) != 0) {
        psa_panic();
    }
    wt_tpm_relay_set_local_provider(wt_tpm_local_provider_process,
                                    provider_context);
    wt_tpm_relay_set_roles(-1, 0);
#else
    wt_tpm_relay_set_roles(-(WT_TPM_APP_GUEST + 1),
                           -(WT_TPM_FTPM_GUEST + 1));
#endif
    for (;;) {
        (void)wt_tpm_relay_dispatch(NULL, NULL, partition_id);
    }
}

int wt_spm_tpm_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    return wt_spm_sched_add(runtime, partition_id, wt_spm_tpm_entry,
                            (void*)(intptr_t)partition_id);
}
#endif /* CONFIG_TPM */

#if defined(CONFIG_PKCS11)
#ifndef WT_PKCS11_APP_GUEST
#define WT_PKCS11_APP_GUEST 0
#endif
#ifndef WT_PKCS11_PROVIDER_GUEST
#define WT_PKCS11_PROVIDER_GUEST 1
#endif

#if defined(WT_INTERFACE_LOCAL_PROVIDER)
static int wt_spm_pkcs11_local_dispatch(uint8_t* request,
                                        size_t request_len,
                                        uint8_t* response,
                                        size_t response_cap,
                                        size_t* response_len,
                                        void* context)
{
    if (wt_pkcs11_secure_client_prepare() != 0) {
        *response_len = 0U;
        return -1;
    }
    return wt_pkcs11_provider_dispatch(request, request_len, response,
                                       response_cap, response_len, context);
}
#endif

static void wt_spm_pkcs11_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;

#if defined(WT_PKCS11_NEG_PROBE) && (WT_PKCS11_NEG_PROBE == 1)
    partition_id = WT_PKCS11_PROBE_ID(arg);
    wt_spm_pkcs11_partition_probe(arg);
#endif
    wt_pkcs11_relay_set_transport(wt_spm_svc_transport);
#if defined(WT_INTERFACE_LOCAL_PROVIDER)
    if (wt_pkcs11_secure_client_init() != 0) {
        psa_panic();
    }
    wt_pkcs11_relay_set_local_provider(wt_spm_pkcs11_local_dispatch, NULL);
    wt_pkcs11_relay_set_roles(-1, 0);
#else
    wt_pkcs11_relay_set_roles(-(WT_PKCS11_APP_GUEST + 1),
                              -(WT_PKCS11_PROVIDER_GUEST + 1));
#endif
    for (;;) {
        (void)wt_pkcs11_relay_dispatch(NULL, NULL, partition_id);
    }
}

int wt_spm_pkcs11_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    return wt_spm_sched_add(runtime, partition_id, wt_spm_pkcs11_entry,
                            (void*)(intptr_t)partition_id);
}
#endif /* CONFIG_PKCS11 */
