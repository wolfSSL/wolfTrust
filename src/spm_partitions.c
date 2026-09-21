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
#include "wolftrust/sp_recovery.h"
#include "wolftrust/spm_gate.h"

#include <string.h>

/* Generated in every secure build; the ITS entry embeds SERVICE_VAULT_SID as
 * a code constant — the unprivileged loop cannot read SPM RAM at runtime. */
#include "psa_manifest/sid.h"

/* Port flash staging backend (WT-FWU-0002), driven by the FWU partition
 * through the gate's privileged backend ops. */
extern const wt_fwu_backend_t wt_fwu_flash_backend;

/* SERVICE_HSM's relay loop: a confined scheduled SP. The submit pump reaches
 * the wolfHSM server state through the shared keystore band its manifest
 * domain grants; flash, entropy, and the NVM lock trap to the SVC gate. */
static void wt_spm_hsm_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;
#if defined(WT_SP_FAULT_ALWAYS_PROBE) && (WT_SP_FAULT_ALWAYS_PROBE == 1)
    /* Budget-exhaustion probe (target/spbudgetneg): fault on every entry so
     * the limit-plus-one fault drives escalation into fail-closed platform
     * recovery (WT-FFM-0017/0051). Never built into production images. */
    wt_arch_sp_fault_probe(0u);
#endif
#if defined(WT_SP_FAULT_PROBE) && (WT_SP_FAULT_PROBE == 1)
    /* One-shot graceful-recovery probe (target/spfaultneg): the relay runs
     * privileged, so an out-of-domain read cannot MemManage-fault; an
     * undefined instruction raises the same recoverable Secure-Thread
     * UsageFault instead. The recovery re-arms this partition with the
     * restarted marker set, so the re-run skips the probe and serves. */
    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        wt_arch_sp_fault_probe(0u);
    }
    partition_id = (int32_t)((intptr_t)arg &
                             ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED);
#endif

    for (;;) {
        (void)wt_hsm_relay_dispatch(NULL, NULL, partition_id);
    }
}

int wt_spm_hsm_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    wt_hsm_relay_set_transport(wt_spm_svc_transport);
#if defined(WT_ENGINE_HSM)
    wt_hsm_relay_set_submit(wt_hsm_relay_submit, NULL);
#else
    /* Native engine: SERVICE_HSM stays the single mediated door; its packets
     * carry the native wire and dispatch straight into wolfCrypt. */
    wt_hsm_relay_set_submit(wt_native_submit, (void*)(intptr_t)partition_id);
#endif
    wt_spm_set_hsm_partition(partition_id);
    return wt_spm_sched_add(runtime, partition_id, wt_spm_hsm_entry,
                            (void*)(intptr_t)partition_id);
}

#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
/* SERVICE_ATTEST's dispatch loop: a confined scheduled SP. The sign path
 * reaches the attestation wolfHSM server through the shared keystore band;
 * flash, entropy, and the NVM lock trap to the SVC gate. */
static void wt_spm_attest_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;

    for (;;) {
        (void)wt_attestation_service_dispatch(NULL, NULL, partition_id);
    }
}

int wt_spm_attest_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    wt_attestation_service_set_transport(wt_spm_svc_transport);
    return wt_spm_sched_add(runtime, partition_id, wt_spm_attest_entry,
                            (void*)(intptr_t)partition_id);
}
#endif /* WT_ATTEST_COSE */

/* The vault partition's service loop: a confined scheduled SP. Its file-scope
 * backend/transport seams live in the shared keystore band its manifest
 * domain grants; flash, entropy, and the NVM lock trap to the SVC gate. */
static void wt_spm_vault_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;

    for (;;) {
        (void)wt_vault_service_dispatch(NULL, NULL, partition_id);
    }
}

int wt_spm_vault_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    /* The vault must run as a scheduled coroutine: every op takes the shared
     * NVM path, whose mutex cannot be held from the bootstrap context. */
    wt_vault_service_set_transport(wt_spm_svc_transport);
    return wt_spm_sched_add(runtime, partition_id, wt_spm_vault_entry,
                            (void*)(intptr_t)partition_id);
}

/* The ITS partition's service loop: a normal UNPRIVILEGED scheduled SP.
 * Context lives on its own stack — the narrowed MPU domain cannot read the
 * service's file-scope seams in SPM RAM. */
static void wt_spm_its_entry(void* arg)
{
    int32_t partition_id = (int32_t)(intptr_t)arg;
    wt_storage_service_ctx_t ctx;

#if defined(WT_PANIC_NEG_PROBE) && (WT_PANIC_NEG_PROBE == 1)
    /* Secure-caller-misuse proof (target/panicneg): closing an error-status
     * handle is an FF-M PROGRAMMER ERROR the production SPM must panic this
     * partition for; the graceful recovery restarts it with the marker set
     * and the re-run serves storage normally. Reaching the udf below means
     * the SPM failed to panic the caller, which fails the scenario with a
     * distinct fault. Never built into production images. */
    partition_id = (int32_t)((intptr_t)arg &
                             ~(intptr_t)WT_SP_FAULT_PROBE_RESTARTED);
    if (((intptr_t)arg & WT_SP_FAULT_PROBE_RESTARTED) == 0) {
        wt_spm_call_t bad;

        (void)memset(&bad, 0, sizeof(bad));
        bad.op = WT_SPM_OP_CLOSE;
        bad.msg_handle = (psa_handle_t)-135;
        (void)wt_arch_sp_trap(&bad);
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
         * non-keystore SP whose domain does not grant the shared keystore
         * band, so this read must MemManage-fault. Placed in ITS (which runs
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
        (void)wt_storage_service_dispatch(&ctx, NULL, partition_id);
    }
}

int wt_spm_its_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    return wt_spm_sched_add(runtime, partition_id, wt_spm_its_entry,
                            (void*)(intptr_t)partition_id);
}

/* The PS partition: the same unprivileged storage loop, but every request is
 * forwarded SEALED — AES-GCM under the device-unique wolfHSM key plus
 * rollback binding, applied inside the privileged vault domain
 * (WT-FFM-0048). The NO_* client hints are accepted and recorded, never
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
