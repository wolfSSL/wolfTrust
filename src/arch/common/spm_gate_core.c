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
#include "wolftrust/services/crypto_native.h"
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
#include "psa_manifest/pid.h"
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

typedef struct wt_spm_sp {
    wt_co_t* co;
    wt_secure_domain_t table;
    int32_t partition_id;
    uint16_t partition_index;
    uint16_t wait_msg;
    psa_signal_t wait_mask;
    uint8_t wait_kind;
    uint8_t in_use;
    /* Graceful fault recovery (WT-SYS-0008 / WT-FFM-0017): re-arm the coroutine
     * in place from its original entry, scrub its private stack, and evaluate
     * the manifest restart budget on each fault. */
    wt_spm_sp_entry_fn entry;
    void* arg;
    uintptr_t scrub_base;
    uint32_t scrub_size;
    uintptr_t scrub2_base;
    uint32_t scrub2_size;
    uint32_t restart_count;
    uint32_t first_restart_tick;
    volatile uint8_t fault_pending;
} wt_spm_sp_t;

static wt_ffm_runtime_t* g_spm_svc_runtime;
static wt_spm_sp_t g_spm_sp[WT_FFM_MAX_PARTITIONS];
static size_t g_spm_sp_count;
static wt_secure_domain_t g_spm_sp_domain;

static uint32_t wt_spm_sched_diag_word(const wt_ffm_runtime_t* runtime,
                                       int which);

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Privileged flash NVM sync, implemented in the port's hsm_flash.c. Declared
 * here to keep the wolfHSM flash headers out of the arch transport. */
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store);
/* Privileged PAL interrupt source control (P4.2c), in the port platform. */
void wt_conf_uart_irq_set(int on);
#endif

/* Port flash staging backend (WT-FWU-0002); the SVC dispatcher runs its ops
 * privileged on behalf of the confined FWU partition. */
extern const wt_fwu_backend_t wt_fwu_flash_backend;

/* Port seams the SVC dispatcher runs privileged on behalf of the confined
 * keystore partitions: the shared NVM flash callback set and its context
 * singleton (hsm_flash.c) and the TRNG entropy source (rng_entropy.c). */
extern const whFlashCb g_wt_hsm_flash_cb;
void *wt_hsm_flash_context(void);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

/* Keystore-gate forensics, SWD-readable on target: silent -146 storage
 * failures on silicon are undebuggable from the interleaved console, so latch
 * the last pid-pin rejection and the last flash/lock op result here. */
volatile uint32_t g_wt_ks_reject_pid __attribute__((used));
volatile uint32_t g_wt_ks_reject_count __attribute__((used));
volatile uint32_t g_wt_ks_last_flash __attribute__((used));
volatile uint32_t g_wt_ks_last_flash_off __attribute__((used));
volatile uint32_t g_wt_ks_flash_ops __attribute__((used));
volatile uint32_t g_wt_ks_last_lock __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_count __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_subop __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_buf __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_len __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_count __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_call __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_psp __attribute__((used));
volatile uint32_t g_wt_svc_entry_rej_why __attribute__((used));

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
        if (g_spm_sp[i].in_use != 0u && g_spm_sp[i].co == cur) {
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

static void wt_spm_fault_release(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;

    /* The shared NVM lock is engine-independent (nvm_store.c): a faulted
     * holder must release it in both engines or later acquirers deadlock. */
    wt_hsm_release_locks(c->slot->co);
#if defined(WT_ENGINE_HSM)
    if (c->slot->partition_id == g_spm_hsm_partition_id) {
        /* The fault may have torn a per-guest server mid-request; rebuild
         * them all. Fails closed — a guest whose re-init fails stays down. */
        (void)wt_hsm_relay_reinit_servers();
    }
#elif defined(WT_ENGINE_NATIVE)
    /* The native vault DRBG is process-global — the HSM relay, SERVICE_VAULT
     * (RANDOM and key ops), and attestation signing all draw from the one
     * g_kv_rng. Any recovered fault may have torn it mid-draw, so invalidate
     * it unconditionally; the next draw re-seeds and fails closed on error. */
    wt_native_reinit();
#endif
}

static void wt_spm_fault_messages(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;

    (void)wt_ffm_fail_partition_messages(g_spm_svc_runtime,
                                         c->slot->partition_id,
                                         PSA_ERROR_COMMUNICATION_FAILURE);
}

static void wt_spm_fault_scrub(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;

    wt_arch_zero_guest_memory(c->slot->scrub_base, c->slot->scrub_size);
    /* WT-FFM-0051: the domain's declared RESTART_CLEAR data band is private
     * state too; the restarted entry re-initializes it from scratch. */
    if (c->slot->scrub2_size != 0u) {
        wt_arch_zero_guest_memory(c->slot->scrub2_base,
                                      c->slot->scrub2_size);
    }
}

static int wt_spm_fault_restart(void* ctx)
{
    wt_spm_fault_ctx_t* c = (wt_spm_fault_ctx_t*)ctx;
    wt_spm_sp_t* slot = c->slot;
    void* arg = slot->arg;

#if (defined(WT_SP_FAULT_PROBE) && (WT_SP_FAULT_PROBE == 1)) || \
    (defined(WT_PANIC_NEG_PROBE) && (WT_PANIC_NEG_PROBE == 1))
    arg = (void*)((intptr_t)slot->arg | WT_SP_FAULT_PROBE_RESTARTED);
#endif
#if defined(WT_VNET_NEG_PROBE) && (WT_VNET_NEG_PROBE == 1)
    /* Two-stage probe progression persists in slot->arg: fault 1 arms
     * RESTARTED, fault 2 arms SECOND, the third run serves normally. */
    if (((intptr_t)slot->arg & WT_SP_FAULT_PROBE_RESTARTED) != 0) {
        slot->arg = (void*)((intptr_t)slot->arg | WT_SP_FAULT_PROBE_SECOND);
    }
    slot->arg = (void*)((intptr_t)slot->arg | WT_SP_FAULT_PROBE_RESTARTED);
    arg = slot->arg;
#endif
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

static const wt_domain_descriptor_t* wt_spm_domain_for(int32_t partition_id)
{
    const wt_system_manifest_t* manifest;
    size_t i;

    if (g_spm_svc_runtime == NULL || g_spm_svc_runtime->manifest == NULL) {
        return NULL;
    }
    manifest = g_spm_svc_runtime->manifest;
    for (i = 0u; i < manifest->domain_count; i++) {
        if (manifest->domains[i].id == (wt_domain_id_t)partition_id) {
            return &manifest->domains[i];
        }
    }
    return NULL;
}

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
        if (g_spm_sp[i].in_use != 0u && g_spm_sp[i].co == faulted_co) {
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
    return WT_FFM_SUCCESS;
}

void wt_spm_recover_faulted(void)
{
    const wt_domain_descriptor_t* domain;
    wt_spm_fault_ctx_t ctx;
    wt_spm_sp_t* slot;
    uint32_t ticks;
    size_t i;

    /* Defensive: the faulted partition ran with CONTROL.nPRIV=1 and the fault
     * tail clears it from handler mode; re-assert privileged Thread state here
     * so a delivery path that bypassed the tail can never leak nPRIV into the
     * next NS window. Normally the bit is already clear and this never fires. */
    wt_arch_assert_privileged_thread();

    ticks = wt_monitor_state()->monotonic_ticks;
    for (i = 0u; i < g_spm_sp_count; i++) {
        slot = &g_spm_sp[i];
        if (slot->in_use == 0u || slot->fault_pending == 0u) {
            continue;
        }
        slot->fault_pending = 0u;
        domain = wt_spm_domain_for(slot->partition_id);
        if (domain == NULL) {
            continue;  /* stays FAULTED — quarantined by the mark */
        }
        ctx.slot = slot;
        (void)wt_sp_recovery_run(&g_spm_fault_ops, &ctx,
                                 domain->restart_policy.action,
                                 domain->restart_policy.restart_limit,
                                 domain->restart_policy.restart_window_ticks,
                                 ticks, &slot->restart_count,
                                 &slot->first_restart_tick);
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
int wt_spm_dispatch_call(wt_spm_call_t* call, wt_trap_frame_t* frame)
{
    wt_spm_sp_t* slot;
    const wt_scheduler_state_t* sched;
    int status;

    (void)frame;
    slot = wt_spm_slot_for_current();
    if (g_spm_svc_runtime == NULL || slot == NULL ||
            wt_secure_domain_contains(&slot->table, (uintptr_t)call,
                                      sizeof(*call), 1) == 0) {
        g_wt_svc_entry_rej_count++;
        if (g_wt_svc_entry_rej_call == 0u) {
            uint32_t psp_now;
            psp_now = (uint32_t)wt_arch_sp_stack_pointer();
            g_wt_svc_entry_rej_call = (uint32_t)(uintptr_t)call;
            g_wt_svc_entry_rej_psp = psp_now;
            g_wt_svc_entry_rej_why = (g_spm_svc_runtime == NULL) ? 1u :
                                     (slot == NULL) ? 2u : 3u;
        }
        return WT_FFM_ERROR_ARGUMENT;
    }

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
    if (call->op == WT_SPM_OP_CONF_NVM_SYNC) {
        int nvm_ret = WT_FFM_ERROR_BUFFER;

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
        wt_conf_uart_irq_set(call->call_type);
        call->ret_int = WT_FFM_SUCCESS;
        return WT_FFM_SUCCESS;
    }
#endif

    /* SERVICE_FWU staging (WT-FWU-0002): the confined FWU partition cannot
     * touch the flash controller, so its backend ops trap here for the
     * privileged program/erase, pinned to the FWU partition identity. The
     * conformance manifest schedules no FWU partition, so the op falls
     * through to the gate's argument rejection there. */
#if defined(PARTITION_FWU_ID)
    if (call->op == WT_SPM_OP_FWU_BACKEND) {
        int fwu_ret = -1;

        if (slot->partition_id != PARTITION_FWU_ID) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        if (call->call_type == WT_SPM_FWU_BEGIN &&
                wt_fwu_flash_backend.begin != NULL) {
            fwu_ret = wt_fwu_flash_backend.begin(NULL);
        }
        else if (call->call_type == WT_SPM_FWU_WRITE &&
                wt_fwu_flash_backend.write != NULL &&
                wt_secure_domain_contains(&slot->table,
                    (uintptr_t)call->buffer, call->num_bytes, 0) != 0) {
            fwu_ret = wt_fwu_flash_backend.write(NULL, call->vec_idx,
                (const uint8_t*)call->buffer, (uint32_t)call->num_bytes);
        }
        else if (call->call_type == WT_SPM_FWU_ARM &&
                wt_fwu_flash_backend.arm != NULL) {
            fwu_ret = wt_fwu_flash_backend.arm(NULL,
                (uint32_t)call->num_bytes, call->version);
        }
        else if (call->call_type == WT_SPM_FWU_DISARM &&
                wt_fwu_flash_backend.disarm != NULL) {
            fwu_ret = wt_fwu_flash_backend.disarm(NULL);
        }
        else if (call->call_type == WT_SPM_FWU_REBOOT) {
            /* psa_fwu_request_reboot: the granted reset does not return. */
            wt_platform_system_reset();
        }
        else if (call->call_type == WT_SPM_FWU_FLOOR) {
            uint32_t fwu_floor = 0u;

            if (wt_hsm_rollback_image_floor(&fwu_floor) == 0) {
                call->ret_version = fwu_floor;
                fwu_ret = 0;
            }
        }
        else if (call->call_type == WT_SPM_FWU_VERIFY &&
                wt_fwu_flash_backend.verify != NULL) {
            uint32_t staged_version = 0u;

            fwu_ret = wt_fwu_flash_backend.verify(NULL,
                (uint32_t)call->num_bytes, &staged_version);
            if (fwu_ret == 0) {
                call->ret_version = staged_version;
            }
        }
        else if (call->call_type == WT_SPM_FWU_ACTIVE) {
            call->ret_version = wt_hsm_active_image_version();
            fwu_ret = 0;
        }
        call->ret_int = fwu_ret;
        return WT_FFM_SUCCESS;
    }
#endif /* PARTITION_FWU_ID */

    /* Keystore platform services (WT-FFM-0011): the confined keystore
     * partitions cannot touch the flash controller, the TRNG, or the
     * scheduler state the NVM lock needs, so those ops trap here, pinned to
     * the keystore partition identities. The flash context is always the
     * shared NVM singleton — never a caller-supplied pointer. */
    if (call->op == WT_SPM_OP_KEYSTORE_FLASH ||
            call->op == WT_SPM_OP_KEYSTORE_ENTROPY ||
            call->op == WT_SPM_OP_KEYSTORE_LOCK) {
        void* flash_ctx;
        wt_mutex_t* nvm_mutex;
        int ks_ret = -1;

        if (slot->partition_id != PARTITION_ATTEST_ID &&
                slot->partition_id != PARTITION_HSM_ID &&
                slot->partition_id != PARTITION_VAULT_ID) {
            g_wt_ks_reject_pid = (uint32_t)slot->partition_id;
            g_wt_ks_reject_count++;
            return WT_FFM_ERROR_ARGUMENT;
        }
        if (call->op == WT_SPM_OP_KEYSTORE_FLASH) {
            flash_ctx = wt_hsm_flash_context();
            if (call->call_type == WT_SPM_KS_FLASH_READ &&
                    wt_secure_domain_contains(&slot->table,
                        (uintptr_t)call->buffer, call->num_bytes, 1) != 0) {
                ks_ret = g_wt_hsm_flash_cb.Read(flash_ctx, call->vec_idx,
                    (uint32_t)call->num_bytes, (uint8_t*)call->buffer);
            }
            else if (call->call_type == WT_SPM_KS_FLASH_PROGRAM &&
                    wt_secure_domain_contains(&slot->table,
                        (uintptr_t)call->buffer, call->num_bytes, 0) != 0) {
                ks_ret = g_wt_hsm_flash_cb.Program(flash_ctx, call->vec_idx,
                    (uint32_t)call->num_bytes, (const uint8_t*)call->buffer);
            }
            else if (call->call_type == WT_SPM_KS_FLASH_ERASE) {
                ks_ret = g_wt_hsm_flash_cb.Erase(flash_ctx, call->vec_idx,
                    (uint32_t)call->num_bytes);
            }
            else if (call->call_type == WT_SPM_KS_FLASH_VERIFY &&
                    wt_secure_domain_contains(&slot->table,
                        (uintptr_t)call->buffer, call->num_bytes, 0) != 0) {
                ks_ret = g_wt_hsm_flash_cb.Verify(flash_ctx, call->vec_idx,
                    (uint32_t)call->num_bytes, (const uint8_t*)call->buffer);
            }
            else if (call->call_type == WT_SPM_KS_FLASH_BLANKCHECK) {
                ks_ret = g_wt_hsm_flash_cb.BlankCheck(flash_ctx,
                    call->vec_idx, (uint32_t)call->num_bytes);
            }
            else if (call->call_type == WT_SPM_KS_FLASH_CLEANUP) {
                ks_ret = g_wt_hsm_flash_cb.Cleanup(flash_ctx);
            }
        }
        else if (call->op == WT_SPM_OP_KEYSTORE_ENTROPY) {
            if (wt_secure_domain_contains(&slot->table,
                    (uintptr_t)call->buffer, call->num_bytes, 1) != 0) {
                ks_ret = wolftrust_rng_generate_block_direct(
                    (unsigned char*)call->buffer,
                    (unsigned int)call->num_bytes);
            }
        }
        else {
            nvm_mutex = (wt_mutex_t*)(void*)wt_hsm_nvm_lock_mutex();
            if (call->call_type == WT_SPM_KS_LOCK_ACQUIRE) {
                ks_ret = wt_mutex_acquire_queued(nvm_mutex, wt_co_current());
                if (ks_ret == 1) {
                    /* Enqueued behind the holder: block on exception return
                     * and report retry; the release hands the mutex over
                     * before waking, so the re-issue observes ownership. */
                    wt_co_block();
                }
            }
            else if (call->call_type == WT_SPM_KS_LOCK_RELEASE) {
                ks_ret = wt_mutex_release(nvm_mutex);
            }
        }
        if (call->op == WT_SPM_OP_KEYSTORE_FLASH) {
            g_wt_ks_flash_ops++;
            /* ks_ret untouched by the else-if chain = the buffer failed the
             * caller-domain bounds check (or an unknown sub-op). */
            if (ks_ret == -1) {
                g_wt_ks_dom_reject_count++;
                g_wt_ks_dom_reject_subop = (uint32_t)call->call_type;
                g_wt_ks_dom_reject_buf = (uint32_t)(uintptr_t)call->buffer;
                g_wt_ks_dom_reject_len = (uint32_t)call->num_bytes;
            }
        }
        /* First-wins failure latch (lock ret 1 = enqueued, not an error). */
        if (ks_ret != 0 && ks_ret != 1) {
            if (call->op == WT_SPM_OP_KEYSTORE_LOCK &&
                    g_wt_ks_last_lock == 0u) {
                g_wt_ks_last_lock = ((uint32_t)call->call_type << 24) |
                                    ((uint32_t)ks_ret & 0x00FFFFFFu);
            }
            else if (call->op != WT_SPM_OP_KEYSTORE_LOCK &&
                    g_wt_ks_last_flash == 0u) {
                g_wt_ks_last_flash = ((uint32_t)call->call_type << 24) |
                                     ((uint32_t)ks_ret & 0x00FFFFFFu);
                g_wt_ks_last_flash_off = call->vec_idx;
            }
        }
        call->ret_int = ks_ret;
        return WT_FFM_SUCCESS;
    }

    /* Read-only measurement snapshot (WT-FFM-0049/0062): the confined attest
     * partition embeds the launch-verified guest measurements in its token
     * but must not reach the monitor's table directly; copy on its behalf. */
    if (call->op == WT_SPM_OP_MEASURE_READ) {
        const wt_guest_measurement_t* rec;
        int m_ret = 0;

        if (slot->partition_id != PARTITION_ATTEST_ID) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        call->ret_size = wt_guest_measurement_count();
        if (call->buffer != NULL) {
            m_ret = -1;
            rec = wt_guest_measurement_get(call->vec_idx, NULL);
            if (rec != NULL && call->num_bytes == sizeof(*rec) &&
                    wt_secure_domain_contains(&slot->table,
                        (uintptr_t)call->buffer, call->num_bytes, 1) != 0) {
                (void)memcpy(call->buffer, rec, sizeof(*rec));
                m_ret = 0;
            }
        }
        call->ret_int = m_ret;
        return WT_FFM_SUCCESS;
    }

    /* The caller's identity is the scheduled slot's, never the SP-supplied
     * field: a partition cannot impersonate another through the gate. */
    call->partition_id = slot->partition_id;
    slot->wait_kind = WT_SPM_WAIT_NONE;
    status = wt_spm_gate(g_spm_svc_runtime, &slot->table, call);
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
            word_b = (g_spm_svc_runtime->partitions[slot->partition_index].
                          asserted_signals & 0xFFFFu) << 16;
            if (g_spm_sp_count > 1u)
                word_b |= g_spm_sp[1].wait_mask & 0xFFFFu;
            wt_arch_diag_trap(word_a, word_b,
                wt_spm_sched_diag_word(g_spm_svc_runtime, 2));
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
        }
        wt_co_block();
    }
    return status;
}

/* True when a suspended partition's wake condition holds: its awaited signal
 * set is now asserted, or its pending SP-to-SP message completed. */
static int wt_spm_slot_ready(const wt_ffm_runtime_t* runtime,
                             const wt_spm_sp_t* slot)
{
    if (slot->wait_kind == WT_SPM_WAIT_SIG) {
        return (runtime->partitions[slot->partition_index].asserted_signals &
                slot->wait_mask) != 0U;
    }
    if (slot->wait_kind == WT_SPM_WAIT_MSG) {
        return wt_ffm_msg_complete(runtime, slot->wait_msg);
    }
    /* No recorded wait (the partition has not run since boot): pending
     * signals mean queued work; a spurious wake lands in its psa_wait and
     * re-blocks harmlessly. */
    return runtime->partitions[slot->partition_index].asserted_signals != 0U;
}

static int wt_spm_run_co(wt_co_t* co)
{
    wt_co_wake(co);
    while (wt_co_state(co) == WT_CO_RUNNABLE) {
        if (wt_co_run(co) == 0u) {
            return WT_FFM_ERROR_STATE;
        }
    }
    return WT_FFM_SUCCESS;
}

static uint32_t wt_spm_sched_diag_word(const wt_ffm_runtime_t* runtime,
                                       int which)
{
    uint32_t value = 0u;
    size_t i;

    if (which == 0) {
        /* nibbles: per-slot wait_kind (0..2) then co state (3..5) */
        for (i = 0u; i < g_spm_sp_count && i < 3u; i++) {
            value |= ((uint32_t)g_spm_sp[i].wait_kind & 0xFu) << (4u * i);
            value |= ((uint32_t)wt_co_state(g_spm_sp[i].co) & 0xFu) <<
                     (12u + 4u * i);
        }
    } else if (which == 1) {
        for (i = 0u; i < g_spm_sp_count && i < 2u; i++) {
            value |= ((uint32_t)g_spm_sp[i + 1u].wait_msg & 0xFFu) << (8u * i);
            value |= (runtime->partitions[g_spm_sp[i + 1u].partition_index].
                          asserted_signals & 0xFFu) << (16u + 8u * i);
        }
    } else {
        for (i = 0u; i < WT_FFM_MAX_MESSAGES; i++) {
            if (runtime->messages[i].allocated != 0U)
                value |= 1uL << (16u + i);
            if (runtime->messages[i].complete != 0U)
                value |= 1uL << i;
        }
    }
    return value;
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
void wt_spm_sched_hang_probe(void)
{
    static uint32_t last_activity;
    static uint32_t idle_ticks;
    size_t i;
    int in_flight = 0;

    if (g_spm_svc_runtime == NULL)
        return;
    if (g_spm_conf_activity != last_activity) {
        last_activity = g_spm_conf_activity;
        idle_ticks = 0u;
        return;
    }
    for (i = 0u; i < WT_FFM_MAX_MESSAGES; i++) {
        if (g_spm_svc_runtime->messages[i].allocated != 0U &&
                g_spm_svc_runtime->messages[i].complete == 0U) {
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
            wt_spm_sched_diag_word(g_spm_svc_runtime, 0),
            wt_spm_sched_diag_word(g_spm_svc_runtime, 1),
            wt_spm_sched_diag_word(g_spm_svc_runtime, 2));
    }
}

void wt_spm_conf_irq(uint32_t irq)
{
    int32_t partition_id;
    psa_signal_t signal;

    /* Mask first: a level source (UART TXE) would re-pend forever. The line
     * runs at the lowest priority, so this handler never nests inside the SVC
     * gate and the asserted_signals update cannot race it. */
    wt_arch_secure_irq_disable(irq);
    if (g_spm_svc_runtime != NULL &&
            wt_ffm_irq_route(g_spm_svc_runtime, irq, &partition_id,
                             &signal) == WT_FFM_SUCCESS) {
        (void)wt_ffm_assert_signal(g_spm_svc_runtime, partition_id, signal);
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
 * 2 first run, 3 wake-loop run, 4 pass cap, 5 final not blocked. */
volatile uint32_t g_wt_sched_fail;

static void wt_spm_sched_note(uint32_t branch, wt_co_t* co, int32_t pid)
{
    if ((g_wt_sched_fail >> 28) == 0U) {
        g_wt_sched_fail = (branch << 28) |
            (((uint32_t)wt_co_state(co) & 0xFU) << 24) |
            ((uint32_t)pid & 0xFFFFU);
    }
}

static int wt_spm_sched_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                 int32_t partition_id)
{
    wt_co_t* co = (wt_co_t*)context;
    uint32_t passes = 0u;
    int progressed;
    size_t i;

    (void)partition_id;
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    g_spm_conf_activity++;
#endif
    /* Settle any fault recovery pended by the Secure fault dispatcher before
     * touching the target: a partition that faulted on an earlier dispatch may
     * be restartable, in which case this wake finds it BLOCKED and healthy. */
    wt_spm_recover_faulted();
    if (co == NULL || wt_co_state(co) == WT_CO_FAULTED) {
        wt_spm_sched_note(1U, co, partition_id);
        return WT_FFM_ERROR_STATE;
    }
    if (wt_spm_run_co(co) != WT_FFM_SUCCESS) {
        wt_spm_sched_note(2U, co, partition_id);
        return WT_FFM_ERROR_STATE;
    }
    /* The run above may itself have faulted the partition: recover NOW so the
     * pinned client's message is force-completed before this dispatch returns
     * and the restart budget is charged on the spot. */
    wt_spm_recover_faulted();
    do {
        progressed = 0;
        wt_spm_recover_faulted();
        for (i = 0u; i < g_spm_sp_count; i++) {
            wt_spm_sp_t* slot = &g_spm_sp[i];

            if (slot->in_use == 0u ||
                    wt_co_state(slot->co) != WT_CO_BLOCKED ||
                    wt_spm_slot_ready(runtime, slot) == 0) {
                continue;
            }
            if (wt_spm_run_co(slot->co) != WT_FFM_SUCCESS) {
                wt_spm_sched_note(3U, slot->co, slot->partition_id);
                return WT_FFM_ERROR_STATE;
            }
            progressed = 1;
        }
        if (++passes > 1000u) {
            wt_arch_diag_trap(wt_spm_sched_diag_word(runtime, 0),
                                   wt_spm_sched_diag_word(runtime, 1),
                                   wt_spm_sched_diag_word(runtime, 2));
            wt_spm_sched_note(4U, co, partition_id);
            return WT_FFM_ERROR_STATE;
        }
    } while (progressed != 0);
    if (wt_co_state(co) != WT_CO_BLOCKED) {
        wt_spm_sched_note(5U, co, partition_id);
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static int wt_spm_sched_add_common(wt_ffm_runtime_t* runtime,
                                   int32_t partition_id,
                                   wt_spm_sp_entry_fn entry, void* arg)
{
    wt_spm_sp_t* slot;
    const wt_memory_region_t* stack_region;
    size_t region_count;
    size_t i;

    if (runtime == NULL || runtime->manifest == NULL || entry == NULL) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    if (g_spm_sp_count >= WT_FFM_MAX_PARTITIONS) {
        return WT_FFM_ERROR_RESOURCE;
    }
    if (wt_ffm_resolve_secure_domain(runtime->manifest,
                                     (wt_domain_id_t)partition_id,
                                     &g_spm_sp_domain) !=
            WT_SECURE_DOMAIN_OK) {
        return WT_FFM_ERROR_STATE;
    }

    /* The SP's execution stack is the manifest domain's PRIVATE writable
     * resource — a shared band (the keystore) is never a stack; fail closed
     * if the manifest stops declaring one. When the domain declares its
     * stack explicitly, only the resource containing that range qualifies,
     * so adding a second private writable band (the vnet data band) cannot
     * silently repoint the stack. */
    stack_region = NULL;
    for (i = 0u; i < g_spm_sp_domain.region_count; i++) {
        if ((g_spm_sp_domain.regions[i].attributes & WT_MEM_ATTR_WRITE) !=
                0u &&
                (g_spm_sp_domain.regions[i].attributes &
                 WT_MEM_ATTR_DEVICE) == 0u &&
                (g_spm_sp_domain.regions[i].attributes &
                 WT_MEMORY_ATTR_SHARED) == 0u) {
            if (g_spm_sp_domain.stack_size != 0u &&
                    (g_spm_sp_domain.stack_base <
                         g_spm_sp_domain.regions[i].base ||
                     g_spm_sp_domain.stack_base +
                         g_spm_sp_domain.stack_size >
                         g_spm_sp_domain.regions[i].base +
                         g_spm_sp_domain.regions[i].size)) {
                continue;
            }
            stack_region = &g_spm_sp_domain.regions[i];
        }
    }
    if (stack_region == NULL) {
        return WT_FFM_ERROR_STATE;
    }

    slot = &g_spm_sp[g_spm_sp_count];
    slot->table.domain_id = g_spm_sp_domain.domain_id;
    /* Thread-domain table: the image windows every partition shares (the port
     * knows where executable code ends), then the domain's non-EXEC resources.
     * Every scheduled SP is confined this way; no wide privileged table exists
     * any more (WT-FFM-0011/0010). NOTE: in conformance builds the Arm client
     * SP uses exactly WT_MAX_MEMORY_REGIONS (2 flash + stack + 5 window
     * grants) — a new fixed region needs a budget re-count. */
    region_count = wt_platform_sp_shared_regions(slot->table.regions,
                                                 WT_MAX_MEMORY_REGIONS);
    for (i = 0u; i < g_spm_sp_domain.region_count &&
            region_count < WT_MAX_MEMORY_REGIONS; i++) {
        if ((g_spm_sp_domain.regions[i].attributes & WT_MEM_ATTR_EXEC) ==
                0u) {
            slot->table.regions[region_count] =
                g_spm_sp_domain.regions[i];
            region_count++;
        }
    }
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    region_count = wt_platform_conf_sp_grants(partition_id,
                                              slot->table.regions,
                                              region_count,
                                              WT_MAX_MEMORY_REGIONS);
#endif
    slot->table.region_count = region_count;

    slot->co = wt_co_create_blocked_ex(
        (uint8_t*)(uintptr_t)stack_region->base, stack_region->size,
        entry, arg);
    if (slot->co == NULL) {
        return WT_FFM_ERROR_RESOURCE;
    }
    wt_co_set_domain(slot->co, &slot->table, 1u);
    slot->partition_id = partition_id;
    slot->wait_kind = WT_SPM_WAIT_NONE;
    slot->entry = entry;
    slot->arg = arg;
    slot->scrub_base = stack_region->base;
    slot->scrub_size = stack_region->size;
    /* Record the domain's private non-stack RESTART_CLEAR band for the fault
     * scrub; more than one is unsupported, so fail closed rather than leave
     * a declared band unscrubbed. */
    slot->scrub2_base = 0u;
    slot->scrub2_size = 0u;
    for (i = 0u; i < g_spm_sp_domain.region_count; i++) {
        const wt_memory_region_t* region = &g_spm_sp_domain.regions[i];

        if (region == stack_region ||
                (region->attributes & WT_MEMORY_ATTR_RESTART_CLEAR) == 0u ||
                (region->attributes & WT_MEM_ATTR_WRITE) == 0u ||
                (region->attributes & WT_MEM_ATTR_DEVICE) != 0u ||
                (region->attributes & WT_MEMORY_ATTR_SHARED) != 0u) {
            continue;
        }
        if (slot->scrub2_size != 0u) {
            return WT_FFM_ERROR_STATE;
        }
        slot->scrub2_base = region->base;
        slot->scrub2_size = (uint32_t)region->size;
    }
    slot->restart_count = 0u;
    slot->first_restart_tick = 0u;

    /* Cache the runtime partition index so the scheduler's signal check does
     * not rescan per wake. */
    slot->partition_index = 0u;
    for (i = 0u; i < runtime->partition_count; i++) {
        if (runtime->partitions[i].manifest != NULL &&
                runtime->partitions[i].manifest->domain_id ==
                    (wt_domain_id_t)partition_id) {
            slot->partition_index = (uint16_t)i;
            break;
        }
    }
    if (i >= runtime->partition_count) {
        return WT_FFM_ERROR_STATE;
    }

    /* Transport and compute reach an SP through a dispatch context it builds
     * on its own stack, so no global-pointer read crosses the partition's MPU
     * domain. The one-shot MSP trampoline the privileged path installed would
     * panic on a PSP thread, so it is not used here. */
    g_spm_svc_runtime = runtime;
    if (wt_ffm_register_partition(runtime, partition_id,
                                  wt_spm_sched_dispatch, slot->co) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }

    /* Publish the slot last: the SVC dispatcher only scans up to
     * g_spm_sp_count, so an SP is never visible half-built. */
    slot->in_use = 1u;
    g_spm_sp_count++;
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg)
{
    return wt_spm_sched_add_common(runtime, partition_id, entry, arg);
}
