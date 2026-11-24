/* spm_gate_core.c
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

/* Architecture-neutral Secure Partition gate: the scheduled-SP table, the
 * privileged dispatch every arch trap decoder runs, graceful fault recovery,
 * and the partition scheduler. Trap decode, stack forensics, deliberate
 * faults, and privilege assertions come from wolftrust/arch.h; the shared
 * image windows and conformance grants from wolftrust/platform.h. */

#include "wolftrust/spm_transport.h"

#include "wolftrust/ffm.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/monitor.h"
#include "wolftrust/platform.h"
#include "wolftrust/periph.h"
#include "wolftrust/arch.h"
#include "wolftrust/sched/coroutine.h"
#include "wolftrust/sched/coroutine_internal.h"
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
#include "wolftrust/services/attestation_service.h"
#include "wolftrust/services/initial_attestation.h"
#endif
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#if (defined(CONFIG_PKCS11) || defined(CONFIG_TPM)) && \
    defined(WT_INTERFACE_LOCAL_PROVIDER)
#include "wolftrust/provider_crypto.h"
#endif
#include "wolftrust/services/crypto_native.h"
#include "wolftrust/services/nvm_client.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/services/storage_service.h"
#include "wolftrust/services/vault_service.h"
#if defined(CONFIG_VNET)
#include "wolftrust/services/vnet_relay.h"
#include "wolftrust/services/vnet_service.h"
#endif
#include "wolftrust/sp_recovery.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_ops.h"
#include "wolftrust/spm_sp_mem.h"

#include <string.h>

/* Generated in every secure build; the ITS entry embeds SERVICE_VAULT_SID as
 * a code constant — the unprivileged loop cannot read SPM RAM at runtime. */
#include "psa_manifest/pid.h"
#include "wolftrust_manifest_generated.h"
#include "psa_manifest/sid.h"

/* Table of scheduled Secure Partitions, each keyed by its coroutine. The SVC
 * dispatcher resolves the caller from wt_co_current() so every SP runs the same
 * transport with its own manifest MPU thread table. Only `table` is needed at
 * runtime; the resolved domain is a transient reused across setup calls. */
/* Why a partition is suspended: waiting for a signal (psa_wait) or for its
 * own SP-to-SP client message to complete. The scheduler loop uses this to
 * wake exactly the partitions whose condition now holds. */
#define WT_SPM_WAIT_NONE 0U
#define WT_SPM_WAIT_SIG  1U
#define WT_SPM_WAIT_MSG  2U
#define WT_SPM_WAIT_LOCK 3U

typedef struct wt_spm_sp {
    wt_co_t* co;
    wt_secure_domain_t table;
    int32_t partition_id;
    uint16_t partition_index;
    uint16_t wait_msg;
    int32_t wait_ipc;
    psa_signal_t wait_mask;
    uint8_t wait_kind;
    /* Graceful fault recovery (WT-SYS-0008 / WT-FFM-0017): re-arm the coroutine
     * in place from its original entry, scrub its private stack, and evaluate
     * the manifest restart budget on each fault. */
    wt_spm_sp_entry_fn entry;
    wt_spm_sp_restore_fn restore;
    void* arg;
    uint32_t restart_count;
    uint32_t first_restart_tick;
    volatile uint8_t fault_pending;
} wt_spm_sp_t;

/* One slot per generated partition; no manifest schedules more. */
#ifndef WT_SPM_SP_SLOTS
#define WT_SPM_SP_SLOTS (WT_GEN_SP_COUNT > 0U ? WT_GEN_SP_COUNT : 1U)
#endif
static wt_spm_sp_t g_spm_sp[WT_SPM_SP_SLOTS];
static size_t g_spm_sp_count;
static uint32_t g_spm_sp_faults;

#if (defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)) || \
    (defined(WT_CONF_DIAG_TRAP) && (WT_CONF_DIAG_TRAP != 0))
#define WT_SPM_SCHED_DIAG 1
static uint32_t wt_spm_sched_diag_word(int which);
#endif

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Privileged flash NVM sync, implemented in the port's hsm_flash.c. Declared
 * here to keep the wolfHSM flash headers out of the arch transport. */
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store);
/* Privileged PAL interrupt source control (P4.2c), in the port platform. */
void wt_conf_uart_irq_set(int on);
#endif


#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
/* Keystore-gate forensics, SWD-readable on target: the last pid-pin
 * rejection and the last flash or lock op result. */
volatile uint32_t g_wt_ks_reject_pid __attribute__((used));
volatile uint32_t g_wt_ks_reject_count __attribute__((used));
volatile uint32_t g_wt_ks_last_lock __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_count __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_call __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_psp __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_why __attribute__((used));
#endif

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Conformance-only hang tripwires: silent stalls on target are undebuggable,
 * so convert them into diag-trap register dumps. Activity is any SVC or
 * NS-driven dispatch; a non-blocking NOT_READY wait repeated without bound is
 * a partition spinning. */
static uint32_t g_spm_conf_activity;
static uint32_t g_spm_conf_wait_spins;

#endif

/* Resolve the scheduled SP whose coroutine is currently running, or NULL. */
static wt_spm_sp_t* wt_spm_slot_for_current(void)
{
    wt_co_t* cur;
    size_t i;

    cur = wt_co_current();
    for (i = 0u; i < g_spm_sp_count; i++) {
        if (g_spm_sp[i].co == cur) {
            return &g_spm_sp[i];
        }
    }
    return NULL;
}

/* One-shot fault-probe latch (target/spfaultneg): the recovery path re-arms the
 * partition with this bit set in its entry argument so the re-run skips the
 * deliberate out-of-domain read and serves normally. Chosen above any valid
 * partition id so the entry can still decode the id underneath it. */

/* --- Graceful Secure-Partition fault recovery (WT-SYS-0008 / WT-FFM-0017) ---
 * The neutral state machine (wt_sp_recovery_run) sequences these arch-specific
 * cleanup steps: drop the dead partition's locks, unblock its pinned clients,
 * scrub its stack, and restart it in place under the manifest budget — or, when
 * the budget is spent or the service is platform-fatal, escalate. */
typedef struct wt_spm_fault_ctx {
    wt_spm_sp_t* slot;
} wt_spm_fault_ctx_t;

static int32_t g_spm_hsm_partition_id = -1;

/* WT-FFM-0069: a partition's lines stay disabled, cleared, and Secure-routed
 * until its own psa_irq_enable, at first bring-up and on every restart. */
static int wt_spm_claim_irqs(uint16_t partition_index)
{
    size_t i;

    for (i = 0u; i < g_wt_spm_irq_count; i++) {
        if (g_wt_spm_irqs[i].sp == partition_index &&
                wt_arch_secure_irq_claim(g_wt_spm_irqs[i].irq) != 0) {
            return -1;
        }
    }
    return 0;
}

#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
static void wt_spm_fault_release(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;

    /* The NVM lock is engine-independent (nvm_boot.c): a faulted holder
     * must release it in both engines or later acquirers deadlock. */
    wt_hsm_release_locks(c->slot->co);
    if (c->slot->partition_id == PARTITION_VAULT_ID) {
        /* Every connection to the vault drops to the error state below; the
         * crypto partition's cached keystore door must close and reconnect. */
        wt_nvm_client_partition_vault_restarted();
    }
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (c->slot->partition_id == g_spm_hsm_partition_id) {
        wt_initial_attest_hsm_restarted();
    }
#endif
#if (defined(CONFIG_PKCS11) || defined(CONFIG_TPM)) && \
    defined(WT_INTERFACE_LOCAL_PROVIDER)
    if (c->slot->partition_id == g_spm_hsm_partition_id) {
        wt_provider_crypto_hsm_restarted();
    }
#endif
}

static void wt_spm_fault_messages(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;
    size_t i;

    (void)wt_spm_sp_restarted((uint8_t)c->slot->partition_index,
                              PSA_ERROR_COMMUNICATION_FAILURE);
    /* The dead instance's interrupt lines stay masked, with nothing pending,
     * until the new instance enables them itself. */
    for (i = 0u; i < g_wt_spm_irq_count; i++) {
        if (g_wt_spm_irqs[i].sp == c->slot->partition_index) {
            wt_arch_secure_irq_disable(g_wt_spm_irqs[i].irq);
        }
    }
}

static void wt_spm_fault_scrub(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;
    const wt_spm_sp_mem_t* mem = &g_wt_spm_sp_mems[c->slot->partition_index];

    wt_arch_zero_guest_memory(mem->stack_base, mem->stack_size);
    /* WT-FFM-0051: the declared RESTART_CLEAR band returns to its link-time
     * image, so the restart starts from a first start's C runtime state. */
    if (mem->band_size != 0u) {
        wt_arch_sp_band_reset(mem->band_base, mem->band_size);
    }
}


static int wt_spm_fault_restart(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;
    wt_spm_sp_t* slot = c->slot;
    void* arg = slot->arg;

#if (defined(WT_SP_FAULT_PROBE) && (WT_SP_FAULT_PROBE == 1)) || \
    (defined(WT_PANIC_NEG_PROBE) && (WT_PANIC_NEG_PROBE == 1)) || \
    (defined(WT_BUSFAULT_NEG_PROBE) && (WT_BUSFAULT_NEG_PROBE == 1)) || \
    (defined(WT_SVC_NEG_PROBE) && (WT_SVC_NEG_PROBE == 1)) || \
    (defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0))
    arg = (void*)((intptr_t)slot->arg | WT_SP_FAULT_PROBE_RESTARTED);
#endif
#if (defined(WT_VNET_NEG_PROBE) && (WT_VNET_NEG_PROBE == 1)) || \
    (defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)) || \
    (defined(WT_INTERFACE_NEG_PROBE) && (WT_INTERFACE_NEG_PROBE == 1))
    /* Two-stage probe progression persists in slot->arg: fault 1 arms
     * RESTARTED, fault 2 arms SECOND, the third run serves normally. */
    if (((intptr_t)slot->arg & WT_SP_FAULT_PROBE_RESTARTED) != 0) {
        slot->arg = (void*)((intptr_t)slot->arg | WT_SP_FAULT_PROBE_SECOND);
    }
    slot->arg = (void*)((intptr_t)slot->arg | WT_SP_FAULT_PROBE_RESTARTED);
    arg = slot->arg;
#endif
    if (wt_spm_claim_irqs(slot->partition_index) != 0) {
        return -1;
    }
    if (slot->restore != NULL && slot->restore(slot->partition_id) != 0) {
        return -1;
    }
    if (wt_co_reinit(slot->co, slot->entry, arg) != 0) {
        return -1;
    }
    slot->wait_kind = WT_SPM_WAIT_NONE;
    return 0;
}

static void wt_spm_fault_escalate(void* ctx, wt_restart_action_t action)
{
    (void)ctx;
    (void)action;
    /* Reaching escalation means the restart budget is exhausted, restart
     * itself failed, or the policy forbids restart; the registered behavior
     * is fail-closed platform recovery regardless of the domain's per-fault
     * action (WT-FFM-0017/0051). Does not return. */
    wt_platform_all_guests_faulted();
}

static const wt_sp_recovery_ops_t g_spm_fault_ops = {
    wt_spm_fault_release, wt_spm_fault_messages, wt_spm_fault_scrub,
    wt_spm_fault_restart, wt_spm_fault_escalate
};
#endif

/* Handler-mode half: identical footprint to the proven guest-tasklet fault
 * path — mark the coroutine dead, unlink it, drop the stale PendSV target —
 * plus one flag. The actual recovery (locks, clients, scrub, restart) runs
 * later on the bootstrap thread via wt_spm_recover_faulted, in exactly the
 * context that creates SPs at boot: recovery in handler mode leaked
 * CONTROL_S.nPRIV/MPU thread state into the NS window (M33MU HardFault
 * cascade at the next NS veneer entry). */
int wt_spm_sp_fault(struct wt_co* faulted_co)
{
    wt_spm_sp_t* slot = NULL;
    size_t i;

    for (i = 0u; i < g_spm_sp_count; i++) {
        if (g_spm_sp[i].co == faulted_co) {
            slot = &g_spm_sp[i];
            break;
        }
    }
    if (slot == NULL) {
        return WT_FFM_ERROR_STATE;  /* not a scheduled SP — caller falls back */
    }

    wt_co_mark_faulted(faulted_co);
    g_wt_co_pendsv_target = (struct wt_co *)0;
    slot->fault_pending = 1u;
    g_spm_sp_faults++;
    return WT_FFM_SUCCESS;
}

void wt_spm_recover_faulted(void)
{
#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
    const wt_spm_sp_mem_t* mem;
    wt_spm_fault_ctx_t ctx;
    uint32_t ticks = wt_monitor_state()->monotonic_ticks;
#endif
    wt_spm_sp_t* slot;
    size_t i;

    /* Defensive: the faulted partition ran with CONTROL.nPRIV=1 and the fault
     * tail clears it from handler mode; re-assert privileged Thread state here
     * so a delivery path that bypassed the tail can never leak nPRIV into the
     * next NS window. Normally the bit is already clear and this never fires. */
    wt_arch_assert_privileged_thread();

    for (i = 0u; i < g_spm_sp_count; i++) {
        slot = &g_spm_sp[i];
        if (slot->fault_pending == 0u) {
            continue;
        }
        slot->fault_pending = 0u;
#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
        mem = &g_wt_spm_sp_mems[slot->partition_index];
        ctx.slot = slot;
        (void)wt_sp_recovery_run(&g_spm_fault_ops, &ctx,
                                 (wt_restart_action_t)mem->restart_action,
                                 mem->restart_limit,
                                 mem->restart_window_ticks,
                                 ticks, &slot->restart_count,
                                 &slot->first_restart_tick);
#else
        /* Without partition recovery a fault fails the platform closed. */
        wt_platform_all_guests_faulted();
#endif
    }
}

void wt_spm_set_hsm_partition(int32_t partition_id)
{
    g_spm_hsm_partition_id = partition_id;
}

/* Privileged gate dispatcher, run by the architecture's trap decoder with the
 * partition's call block and its trap frame. Validates that the request comes
 * from a scheduled SP coroutine and that the call struct lies inside that
 * partition's writable domain, then runs the gate. A psa_wait with nothing
 * asserted suspends the coroutine; the SP-side transport re-issues the trap
 * on wake. Returns the gate-level status the decoder hands back to the SP. */
static int wt_spm_dispatch_held(wt_spm_sp_t* slot, wt_spm_call_t* call,
                                wt_trap_frame_t* frame);

int wt_spm_dispatch_call(wt_spm_call_t* call, wt_trap_frame_t* frame)
{
    wt_spm_call_t held;
    wt_spm_sp_t* slot;
    int status;

    slot = wt_spm_slot_for_current();
    if (slot == NULL ||
            wt_secure_domain_contains(&slot->table, (uintptr_t)call,
                                      sizeof(*call), 1) == 0) {
#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
        g_wt_svc_entry_rej_count++;
        if (g_wt_svc_entry_rej_call == 0u) {
            g_wt_svc_entry_rej_call = (uint32_t)(uintptr_t)call;
            g_wt_svc_entry_rej_psp = (uint32_t)wt_arch_sp_stack_pointer();
            g_wt_svc_entry_rej_why = (slot == NULL) ? 2u : 3u;
        }
#endif
        return WT_FFM_ERROR_ARGUMENT;
    }

    /* The block lives in the partition's memory: read it once, so every
     * privileged check and use below sees the same request. */
    (void)memcpy(&held, call, sizeof(held));
    status = wt_spm_dispatch_held(slot, &held, frame);
    (void)memcpy(call, &held, sizeof(held));
    return status;
}

static int wt_spm_dispatch_held(wt_spm_sp_t* slot, wt_spm_call_t* call,
                                wt_trap_frame_t* frame)
{
    const wt_scheduler_state_t* sched;
    int status;

    (void)frame;
    /* Every gate return carries the scheduler tick: a confined SP (the vnet
     * relay ages frames with it) must not dereference monitor state. */
    sched = wt_monitor_state();
    call->ret_tick = (sched != NULL) ? sched->monotonic_ticks : 0u;

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    /* Platform NVM service (P5 K2): the unprivileged DRIVER partition cannot
     * touch the flash controller, so it traps its shadow buffer here for the
     * privileged sync. Validate the buffer inside the caller's domain (written
     * on load, read on store), run the flash driver, and return without ever
     * entering the neutral FF-M gate. */
    if ((call->op == WT_SPM_OP_CONF_NVM_SYNC ||
            call->op == WT_SPM_OP_CONF_IRQ_SET) &&
            slot->partition_id != SERVER_PARTITION_ID &&
            slot->partition_id != CLIENT_PARTITION_ID &&
            slot->partition_id != DRIVER_PARTITION_ID) {
        /* The suite's platform services belong to its own partitions. */
        return WT_FFM_ERROR_ARGUMENT;
    }
    if (call->op == WT_SPM_OP_CONF_NVM_SYNC) {
        int nvm_ret = WT_FFM_ERROR_BUFFER;

#if defined(DRIVER_PARTITION_ID)
        if (slot->partition_id != DRIVER_PARTITION_ID) {
            return WT_FFM_ERROR_ARGUMENT;
        }
#endif
        if (call->call_type != 0 && call->call_type != 1) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        if (wt_secure_domain_contains(&slot->table, (uintptr_t)call->buffer,
                call->num_bytes, call->call_type == 0 ? 1 : 0) != 0) {
            nvm_ret = wt_conf_nvm_flash_sync((uint8_t*)call->buffer,
                          (uint32_t)call->num_bytes, call->call_type);
        }
        call->ret_int = nvm_ret;
        return WT_FFM_SUCCESS;
    }
    /* PAL interrupt source (P4.2c): the unprivileged DRIVER partition cannot
     * program the UART or NVIC, so pal_generate/disable_interrupt trap here
     * for the privileged device poke. The interrupt itself is delivered
     * through the real NVIC vector, not simulated. */
    if (call->op == WT_SPM_OP_CONF_IRQ_SET) {
#if defined(DRIVER_PARTITION_ID)
        if (slot->partition_id != DRIVER_PARTITION_ID) {
            return WT_FFM_ERROR_ARGUMENT;
        }
#endif
        if (call->call_type != 0 && call->call_type != 1) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        wt_conf_uart_irq_set(call->call_type);
        call->ret_int = WT_FFM_SUCCESS;
        return WT_FFM_SUCCESS;
    }
#endif

    /* SERVICE_FWU staging (WT-FWU-0002), pinned to the FWU partition. Without
     * one the op falls through to the gate's argument rejection. */
#if defined(PARTITION_FWU_ID)
    if (call->op == WT_SPM_OP_FWU_BACKEND) {
        if (slot->partition_id != PARTITION_FWU_ID) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        call->ret_int = wt_spm_fwu_op(&slot->table, call);
        return WT_FFM_SUCCESS;
    }
#endif /* PARTITION_FWU_ID */

    /* Keystore platform services (WT-FFM-0011): flash and the NVM lock are
     * pinned to the vault, entropy to the vault and the crypto partition. */
    if (call->op == WT_SPM_OP_KEYSTORE_FLASH ||
            call->op == WT_SPM_OP_KEYSTORE_ENTROPY ||
            call->op == WT_SPM_OP_KEYSTORE_LOCK) {
        wt_mutex_t* nvm_mutex;
        int ks_ret = -1;
        int pinned;

        pinned = wt_spm_keystore_op_pinned(call->op, slot->partition_id,
                                           PARTITION_VAULT_ID,
                                           PARTITION_HSM_ID);
#if defined(WT_INTERFACE_LOCAL_PROVIDER)
        if (!pinned && call->op == WT_SPM_OP_KEYSTORE_ENTROPY) {
#if defined(PARTITION_TPM_ID)
            pinned = slot->partition_id == PARTITION_TPM_ID;
#elif defined(PARTITION_PKCS11_ID)
            pinned = slot->partition_id == PARTITION_PKCS11_ID;
#endif
        }
#endif
        if (!pinned) {
#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
            g_wt_ks_reject_pid = (uint32_t)slot->partition_id;
            g_wt_ks_reject_count++;
#endif
            return WT_FFM_ERROR_ARGUMENT;
        }
        if (call->op != WT_SPM_OP_KEYSTORE_LOCK) {
            call->ret_int = wt_spm_keystore_op(&slot->table, call);
            return WT_FFM_SUCCESS;
        }
        nvm_mutex = (wt_mutex_t*)(void*)wt_hsm_nvm_lock_mutex();
        if (call->call_type == WT_SPM_KS_LOCK_ACQUIRE) {
            ks_ret = wt_mutex_acquire_queued(nvm_mutex, wt_co_current());
            if (ks_ret == 1) {
                /* Enqueued behind the holder: block on exception return
                 * and report retry; the release hands the mutex over
                 * before waking, so the re-issue observes ownership. */
                slot->wait_kind = WT_SPM_WAIT_LOCK;
                wt_co_block();
            }
            else if (ks_ret == 0) {
                slot->wait_kind = WT_SPM_WAIT_NONE;
            }
        }
        else if (call->call_type == WT_SPM_KS_LOCK_RELEASE) {
            ks_ret = wt_mutex_release(nvm_mutex);
        }
#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
        /* First-wins failure latch (1 means enqueued, not an error). */
        if (ks_ret != 0 && ks_ret != 1 && g_wt_ks_last_lock == 0u) {
            g_wt_ks_last_lock = ((uint32_t)call->call_type << 24) |
                                ((uint32_t)ks_ret & 0x00FFFFFFu);
        }
#endif
        call->ret_int = ks_ret;
        return WT_FFM_SUCCESS;
    }

    /* Read-only measurement snapshot (WT-FFM-0049/0062) for the attest SP. */
    if (call->op == WT_SPM_OP_MEASURE_READ) {
        if (slot->partition_id != PARTITION_ATTEST_ID) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        call->ret_int = wt_spm_measure_op(&slot->table, call);
        return WT_FFM_SUCCESS;
    }

    /* The caller's identity is the scheduled slot's, never the SP-supplied
     * field: a partition cannot impersonate another through the gate. */
    call->partition_id = slot->partition_id;
    slot->wait_kind = WT_SPM_WAIT_NONE;
    status = wt_spm_gate(&g_wt_spm, &slot->table, call);
    /* psa_irq_enable and psa_eoi: the gate validated the signal against the
     * manifest and resolved its interrupt number; the privileged controller
     * unmask happens here where NVIC access is legal. EOI must re-enable the
     * line (FF-M 4.5.3) — the dispatch handler masked it before asserting the
     * signal, so a level source cannot re-pend until the SP finishes. */
    if ((call->op == WT_SPM_OP_IRQ_ENABLE || call->op == WT_SPM_OP_EOI) &&
            call->ret_int == WT_FFM_SUCCESS)
        wt_arch_secure_irq_enable(call->ret_version);
    /* FF-M PROGRAMMER ERROR the SPM must panic the caller for. Conformance
     * resets (val resumes off its flash boot flag, P5 K3); production lands
     * the partition's resume PC on an undefined instruction so the UsageFault
     * takes the graceful quarantine path and pinned clients unblock with
     * PSA_ERROR_COMMUNICATION_FAILURE. */
    if (call->must_panic) {
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
        wt_platform_system_reset();
#else
        wt_arch_sp_redirect_to_panic_trap(frame);
#endif
    }
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    g_spm_conf_activity++;
    /* A service loop interleaves psa_wait with get/reply; an unbounded run of
     * consecutive waits — polling misses or successes nobody consumes — is a
     * spinning partition. Blocking suspensions reset via the non-WAIT ops that
     * follow a real wake. Trap payload: r4 = slot wait_kind/co-state nibbles,
     * r5 = spinner asserted<<16 | slot-1 wait_mask, r6 = msg bitmap. */
    if (call->op == WT_SPM_OP_WAIT) {
        if (++g_spm_conf_wait_spins > 5000u) {
            uint32_t word_a = 0u;
            uint32_t word_b;
            size_t i;

            for (i = 0u; i < g_spm_sp_count && i < 4u; i++) {
                word_a |= ((uint32_t)g_spm_sp[i].wait_kind & 0xFu) <<
                          (4u * i);
                word_a |= ((uint32_t)wt_co_state(g_spm_sp[i].co) & 0xFu) <<
                          (16u + 4u * i);
            }
            word_b = (g_wt_spm.asserted[slot->partition_index] & 0xFFFFu)
                     << 16;
            if (g_spm_sp_count > 1u)
                word_b |= g_spm_sp[1].wait_mask & 0xFFFFu;
            wt_arch_diag_trap(word_a, word_b,
                wt_spm_sched_diag_word(2));
        }
    }
    else {
        g_spm_conf_wait_spins = 0u;
    }
#endif
    if (status == WT_FFM_SUCCESS && wt_spm_call_would_block(call)) {
        /* Record the wake condition BEFORE pending the block: wt_co_block
         * only marks the suspension — this handler runs to completion and the
         * switch happens on exception return, so a post-block clear here
         * would erase the condition before the partition ever sleeps. */
        if (call->op == WT_SPM_OP_WAIT) {
            slot->wait_kind = WT_SPM_WAIT_SIG;
            slot->wait_mask = call->signal_mask;
        } else {
            slot->wait_kind = WT_SPM_WAIT_MSG;
            slot->wait_msg = call->pending_msg;
            slot->wait_ipc = call->op == WT_SPM_OP_CONNECT ? PSA_IPC_CONNECT :
                             call->op == WT_SPM_OP_CLOSE ? PSA_IPC_DISCONNECT :
                             PSA_IPC_CALL;
        }
        wt_co_block();
    }
    return status;
}

/* True when a suspended partition's wake condition holds: its awaited signal
 * set is now asserted, or its pending SP-to-SP message completed. */
static int wt_spm_slot_ready(const wt_spm_sp_t* slot)
{
    if (slot->wait_kind == WT_SPM_WAIT_SIG) {
        return (wt_spm_pending((uint8_t)slot->partition_index) &
                slot->wait_mask) != 0U;
    }
    if (slot->wait_kind == WT_SPM_WAIT_MSG) {
        /* A message no longer the partition's wakes it to be refused. */
        return wt_spm_done((uint8_t)slot->wait_msg,
                           (psa_client_id_t)slot->partition_id,
                           slot->wait_ipc) != 0;
    }
    if (slot->wait_kind == WT_SPM_WAIT_LOCK) {
        return 0;
    }
    /* No recorded wait (the partition has not run since boot): pending
     * signals mean queued work; a spurious wake lands in its psa_wait and
     * re-blocks harmlessly. */
    return wt_spm_pending((uint8_t)slot->partition_index) != 0U;
}

static int wt_spm_run_co(wt_co_t* co)
{
    if (wt_co_state(co) == WT_CO_BLOCKED) {
        wt_co_wake(co);
    }
    while (wt_co_state(co) == WT_CO_RUNNABLE) {
        if (wt_co_run(co) == 0u) {
            return WT_FFM_ERROR_STATE;
        }
    }
    return WT_FFM_SUCCESS;
}

#if defined(WT_SPM_SCHED_DIAG)
static uint32_t wt_spm_sched_diag_word(int which)
{
    uint32_t value = 0u;
    size_t i;

    if (which == 0) {
        /* nibbles: per-slot wait_kind (0..3) then coroutine state */
        for (i = 0u; i < g_spm_sp_count && i < 3u; i++) {
            value |= ((uint32_t)g_spm_sp[i].wait_kind & 0xFu) << (4u * i);
            value |= ((uint32_t)wt_co_state(g_spm_sp[i].co) & 0xFu) <<
                     (12u + 4u * i);
        }
    } else if (which == 1) {
        for (i = 0u; i < g_spm_sp_count && i < 2u; i++) {
            value |= ((uint32_t)g_spm_sp[i + 1u].wait_msg & 0xFFu) << (8u * i);
            value |= (g_wt_spm.asserted[g_spm_sp[i + 1u].partition_index] &
                      0xFFu) << (16u + 8u * i);
        }
    } else {
        /* Two bits per slot: its WT_SPM_MSG_* state. */
        for (i = 0u; i < WT_SPM_SLOTS; i++) {
            value |= ((uint32_t)g_wt_spm.slot[i].msg & 0x3u) << (2u * i);
        }
    }
    return value;
}
#endif

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
void wt_spm_sched_hang_probe(void)
{
    static uint32_t last_activity;
    static uint32_t idle_ticks;
    size_t i;
    int in_flight = 0;

    if (g_spm_conf_activity != last_activity) {
        last_activity = g_spm_conf_activity;
        idle_ticks = 0u;
        return;
    }
    for (i = 0u; i < WT_SPM_SLOTS; i++) {
        if (g_wt_spm.slot[i].msg == WT_SPM_MSG_QUEUED ||
                g_wt_spm.slot[i].msg == WT_SPM_MSG_ACTIVE) {
            in_flight = 1;
            break;
        }
    }
    if (in_flight == 0) {
        idle_ticks = 0u;
        return;
    }
    if (++idle_ticks > 500u) {
        wt_arch_diag_trap(
            wt_spm_sched_diag_word(0),
            wt_spm_sched_diag_word(1),
            wt_spm_sched_diag_word(2));
    }
}

void wt_spm_conf_irq(uint32_t irq)
{
    /* Mask first: a level source (UART TXE) would re-pend forever. The line
     * runs at the lowest priority, so this handler never nests inside the SVC
     * gate and the asserted_signals update cannot race it. */
    wt_arch_secure_irq_disable(irq);
    if (wt_spm_irq_assert(irq) >= 0) {
        g_spm_conf_activity++;
    }
}
#endif

/* Manifest-bound dispatch for a scheduled SP: wake the target coroutine, then
 * keep dispatching every partition whose wake condition holds until the
 * system is quiescent. SP-to-SP IPC depends on this: a client partition
 * blocks on its message while the serving partition's signal is asserted, so
 * cross-partition progress happens here on the bootstrap context, never
 * inside another partition's SVC. Runs until no partition is wakeable. */
/* SWD forensics: first failing wt_spm_sched_dispatch branch
 * ((branch<<28)|(co state<<24)|partition id low 16); 1 entry-faulted,
 * 2 first run, 3 wake-loop run, 4 pass cap, 5 final not blocked,
 * 6 table reaches SPM RAM, 7 tables overlap, 8 not idle after start. */
#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
volatile uint32_t g_wt_sched_fail;
#endif

static void wt_spm_sched_note(uint32_t branch, wt_co_t* co, int32_t pid)
{
#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
    if ((g_wt_sched_fail >> 28) == 0U) {
        g_wt_sched_fail = (branch << 28) |
            (((uint32_t)wt_co_state(co) & 0xFU) << 24) |
            ((uint32_t)pid & 0xFFFFU);
    }
#else
    (void)branch;
    (void)co;
    (void)pid;
#endif
}

/* Runs every partition whose wake condition holds until none does. */
static int wt_spm_sched_drain(void)
{
    uint32_t passes = 0u;
    int progressed;
    size_t i;

    do {
        progressed = 0;
        wt_spm_recover_faulted();
        for (i = 0u; i < g_spm_sp_count; i++) {
            wt_spm_sp_t* slot = &g_spm_sp[i];
            wt_co_state_t state = wt_co_state(slot->co);

            if (state != WT_CO_RUNNABLE &&
                    (state != WT_CO_BLOCKED ||
                     wt_spm_slot_ready(slot) == 0)) {
                continue;
            }
            if (wt_spm_run_co(slot->co) != WT_FFM_SUCCESS) {
                wt_spm_sched_note(3U, slot->co, slot->partition_id);
                return WT_FFM_ERROR_STATE;
            }
            progressed = 1;
        }
        if (++passes > 1000u) {
#if defined(WT_SPM_SCHED_DIAG)
            wt_arch_diag_trap(wt_spm_sched_diag_word(0),
                              wt_spm_sched_diag_word(1),
                              wt_spm_sched_diag_word(2));
#endif
            wt_spm_sched_note(4U, NULL, 0);
            return WT_FFM_ERROR_STATE;
        }
    } while (progressed != 0);
    return WT_FFM_SUCCESS;
}

void wt_spm_run(void)
{
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    g_spm_conf_activity++;
#endif
    (void)wt_spm_sched_drain();
}

/* Runs one partition from where it parked, then drains the rest; the
 * partition must be back in a wait afterwards. */
static int wt_spm_sched_drive(wt_co_t* co, int32_t partition_id)
{
    int ret;

    /* Settle any fault recovery pended by the Secure fault dispatcher first:
     * a partition that faulted earlier may be restartable and healthy now. */
    wt_spm_recover_faulted();
    if (co == NULL || wt_co_state(co) == WT_CO_FAULTED) {
        wt_spm_sched_note(1U, co, partition_id);
        return WT_FFM_ERROR_STATE;
    }
    if (wt_spm_run_co(co) != WT_FFM_SUCCESS) {
        wt_spm_sched_note(2U, co, partition_id);
        return WT_FFM_ERROR_STATE;
    }
    ret = wt_spm_sched_drain();
    if (ret == WT_FFM_SUCCESS && wt_co_state(co) != WT_CO_BLOCKED) {
        wt_spm_sched_note(5U, co, partition_id);
        ret = WT_FFM_ERROR_STATE;
    }
    return ret;
}

static int wt_spm_sched_add_common(wt_ffm_runtime_t* runtime,
                                   int32_t partition_id,
                                   wt_spm_sp_entry_fn entry, void* arg)
{
    const wt_spm_sp_mem_t* mem;
    wt_spm_sp_t* slot;
    const wt_periph_t* periph;
    size_t periph_count;
    size_t region_count;
    size_t i;
    int index;

    (void)runtime;
    if (entry == NULL) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    if (g_spm_sp_count >= WT_SPM_SP_SLOTS) {
        return WT_FFM_ERROR_RESOURCE;
    }
    index = wt_spm_sp_index(partition_id);
    if (index < 0) {
        return WT_FFM_ERROR_STATE;
    }
    mem = &g_wt_spm_sp_mems[index];

    /* WT-FFM-0068: MMIO maps only as a DEVICE peripheral the port lets a
     * partition own, so no manifest can hand a partition SPM hardware. */
    periph = wt_platform_sp_peripherals(&periph_count);
    if (wt_periph_sp_domain_ok(periph, periph_count, mem->regions,
                               mem->region_count,
                               wt_arch_range_is_mmio) != 1) {
        return WT_FFM_ERROR_RESOURCE;
    }

    slot = &g_spm_sp[g_spm_sp_count];
    slot->table.domain_id = (wt_domain_id_t)partition_id;
    /* Thread-domain table: the image windows every partition shares (the port
     * knows where executable code ends), then the domain's non-EXEC resources.
     * Every scheduled SP is confined this way; no wide privileged table exists
     * any more (WT-FFM-0011/0010). NOTE: in conformance builds the Arm client
     * SP uses exactly WT_MAX_MEMORY_REGIONS (2 flash + stack + 5 window
     * grants) — a new fixed region needs a budget re-count. */
    region_count = wt_platform_sp_shared_regions(slot->table.regions,
                                                 WT_MAX_MEMORY_REGIONS);
    for (i = 0u; i < mem->region_count &&
            region_count < WT_MAX_MEMORY_REGIONS; i++) {
        if ((mem->regions[i].attributes & WT_MEM_ATTR_EXEC) == 0u) {
            slot->table.regions[region_count] = mem->regions[i];
            region_count++;
        }
    }
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    region_count = wt_platform_conf_sp_grants(partition_id,
                                              slot->table.regions,
                                              region_count,
                                              WT_MAX_MEMORY_REGIONS);
#endif
#if defined(WT_BUSFAULT_NEG_PROBE) && (WT_BUSFAULT_NEG_PROBE == 1)
    /* busfaultneg: grant the port's bus-error window so the probe read
     * passes the MPU and faults on the bus. Never built into production. */
    if (region_count < WT_MAX_MEMORY_REGIONS) {
        wt_platform_busfault_probe_region(&slot->table.regions[region_count]);
        region_count++;
    }
#endif
#if defined(WT_MANIFEST_NEG_PROBE) && (WT_MANIFEST_NEG_PROBE == 3)
    /* Composition negative: hand the vault one granule of the crypto
     * partition's band behind the validated manifest's back; the boot must
     * refuse the composed tables. Never built into production images. */
    if (partition_id == PARTITION_VAULT_ID &&
            region_count < WT_MAX_MEMORY_REGIONS) {
        slot->table.regions[region_count].base =
            wt_platform_probe_address(WT_PROBE_HSM_DATA_BAND);
        slot->table.regions[region_count].size = 32u;
        slot->table.regions[region_count].attributes =
            WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
        region_count++;
    }
#endif
    slot->table.region_count = region_count;

    slot->co = wt_co_create_blocked_ex((uint8_t*)mem->stack_base,
                                       mem->stack_size, entry, arg);
    if (slot->co == NULL) {
        return WT_FFM_ERROR_RESOURCE;
    }
    wt_co_set_domain(slot->co, &slot->table, 1u);
    slot->partition_id = partition_id;
    slot->wait_kind = WT_SPM_WAIT_NONE;
    slot->entry = entry;
    slot->restore = NULL;
    slot->arg = arg;
    slot->restart_count = 0u;
    slot->first_restart_tick = 0u;
    slot->partition_index = (uint16_t)index;
    if (wt_spm_claim_irqs(slot->partition_index) != 0) {
        return WT_FFM_ERROR_RESOURCE;
    }

    /* Publish the slot last: the SVC dispatcher only scans up to
     * g_spm_sp_count, so an SP is never visible half-built. */
    g_spm_sp_count++;
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg)
{
    return wt_spm_sched_add_common(runtime, partition_id, entry, arg);
}

#if (defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)) || \
    (defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)) || \
    (defined(WT_INTERFACE_NEG_PROBE) && (WT_INTERFACE_NEG_PROBE == 1))
/* Run the probing partition at boot until its probes have faulted and its
 * next entry parks in the service loop, so no client request is lost to the
 * deliberate faults. Never built into production images. */
void wt_spm_sched_prime(int32_t partition_id)
{
    size_t i;
    unsigned int run;

    for (i = 0u; i < g_spm_sp_count; i++) {
        if (g_spm_sp[i].partition_id == partition_id) {
            for (run = 0u; run < 3u; run++) {
                (void)wt_spm_sched_drive(g_spm_sp[i].co, partition_id);
            }
        }
    }
}
#endif

int wt_spm_sched_start_all(void)
{
    wt_spm_sp_t* slot;
    int ret = WT_FFM_SUCCESS;
    uint32_t faults = g_spm_sp_faults;
    size_t i;

    for (i = 0u; ret == WT_FFM_SUCCESS && i < g_spm_sp_count; i++) {
        slot = &g_spm_sp[i];
        if (slot->wait_kind == WT_SPM_WAIT_NONE &&
                wt_co_state(slot->co) == WT_CO_BLOCKED) {
            ret = wt_spm_sched_drive(slot->co, slot->partition_id);
        }
    }
    /* Idle means every partition parked in psa_wait; one still blocked on a
     * reply or a lock left start-up IPC undrained. */
    for (i = 0u; ret == WT_FFM_SUCCESS && i < g_spm_sp_count; i++) {
        slot = &g_spm_sp[i];
        if (wt_co_state(slot->co) != WT_CO_BLOCKED ||
                slot->wait_kind != WT_SPM_WAIT_SIG) {
            wt_spm_sched_note(8U, slot->co, slot->partition_id);
            ret = WT_FFM_ERROR_STATE;
        }
    }
    /* A partition restarted after a startup fault may look idle; refuse. */
    if (ret == WT_FFM_SUCCESS && g_spm_sp_faults != faults) {
        wt_spm_sched_note(8U, NULL, 0);
        ret = WT_FFM_ERROR_STATE;
    }
    return ret;
}

int wt_spm_partition_memory_ok(int32_t partition_id, const void* address,
                               size_t size, int need_write)
{
    size_t i;

    for (i = 0u; i < g_spm_sp_count; i++) {
        if (g_spm_sp[i].partition_id == partition_id) {
            return wt_secure_domain_contains(&g_spm_sp[i].table,
                                             (uintptr_t)address, size,
                                             need_write);
        }
    }
    return 0;
}

int wt_spm_sched_validate(void)
{
    wt_memory_region_t spm_ram[2];
    wt_memory_region_t shared[1];
    size_t spm_ram_count;
    size_t shared_count = 0u;
    size_t i;
    size_t j;

    spm_ram_count = wt_platform_spm_private_regions(
        spm_ram, sizeof(spm_ram) / sizeof(spm_ram[0]));
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    shared_count = wt_platform_conf_shared_regions(
        shared, sizeof(shared) / sizeof(shared[0]));
#endif
    if (spm_ram_count == 0u) {
        return WT_FFM_ERROR_ISOLATION;
    }
    for (i = 0u; i < g_spm_sp_count; i++) {
        for (j = 0u; j < spm_ram_count; j++) {
            if (wt_secure_domain_excludes(&g_spm_sp[i].table,
                    spm_ram[j].base, spm_ram[j].size) == 0) {
                wt_spm_sched_note(6U, g_spm_sp[i].co,
                                  g_spm_sp[i].partition_id);
                return WT_FFM_ERROR_ISOLATION;
            }
        }
        for (j = i + 1u; j < g_spm_sp_count; j++) {
            if (wt_secure_domains_isolated(&g_spm_sp[i].table,
                    &g_spm_sp[j].table, shared, shared_count) == 0) {
                wt_spm_sched_note(7U, g_spm_sp[i].co,
                                  g_spm_sp[i].partition_id);
                return WT_FFM_ERROR_ISOLATION;
            }
        }
    }
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_set_restore(int32_t partition_id,
                             wt_spm_sp_restore_fn restore)
{
    size_t i;

    for (i = 0u; i < g_spm_sp_count; i++) {
        if (g_spm_sp[i].partition_id == partition_id) {
            g_spm_sp[i].restore = restore;
            return WT_FFM_SUCCESS;
        }
    }
    return WT_FFM_ERROR_STATE;
}
