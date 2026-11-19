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

/* Host proof of the FF-M start-up pass (WT-FFM-0013) on the real SP
 * scheduler: every partition runs to its first wait before the NSPE starts,
 * start-up IPC is drained, and any fault or missing wait refuses the boot. */

#include "../../../src/arch/common/spm_gate_core.c"

#include <stdio.h>
#include <stdlib.h>

enum {
    STEP_WAIT = 0,  /* reach psa_wait */
    STEP_WAKE_NEXT, /* assert the next partition's signal, then wait */
    STEP_WAKE_FIRST, /* assert the first partition's signal, then wait */
    STEP_FAULT,     /* fault before reaching a wait */
    STEP_WAIT_REPLY, /* block on an SP-to-SP reply that never comes */
    STEP_STOP       /* return without a recorded wait */
};

#define TEST_SPS 3U

static struct wt_co g_co[TEST_SPS];
static int g_script[TEST_SPS][4];
static unsigned int g_runs[TEST_SPS];
static wt_domain_descriptor_t g_domains[TEST_SPS];
static wt_partition_manifest_t g_parts[TEST_SPS];
static wt_system_manifest_t g_manifest;
static wt_ffm_runtime_t g_rt;
static wt_scheduler_state_t g_sched;
static int g_failures;

struct wt_co* g_wt_co_pendsv_target;

wt_co_state_t wt_co_state(const wt_co_t* co)
{
    return (co == NULL) ? WT_CO_FAULTED : co->state;
}

void wt_co_wake(wt_co_t* co)
{
    if (co->state == WT_CO_BLOCKED) {
        co->state = WT_CO_RUNNABLE;
    }
}

void wt_co_mark_faulted(wt_co_t* co)
{
    co->state = WT_CO_FAULTED;
}

int wt_co_reinit(wt_co_t* co, wt_co_entry_fn entry, void* arg)
{
    (void)entry;
    (void)arg;
    co->state = WT_CO_BLOCKED;
    return 0;
}

uint32_t wt_co_run(wt_co_t* co)
{
    size_t i = (size_t)(co - g_co);
    unsigned int n = g_runs[i]++;
    int step = (n < 4U) ? g_script[i][n] : STEP_WAIT;

    co->state = WT_CO_BLOCKED;
    if (step == STEP_FAULT) {
        (void)wt_spm_sp_fault(co);
        return 1U;
    }
    if (step == STEP_STOP) {
        return 1U;
    }
    if (step == STEP_WAIT_REPLY) {
        g_spm_sp[i].wait_kind = WT_SPM_WAIT_MSG;
        return 1U;
    }
    if (step == STEP_WAKE_NEXT && i + 1U < TEST_SPS) {
        g_rt.partitions[i + 1U].asserted_signals |= 1U;
    }
    if (step == STEP_WAKE_FIRST) {
        g_rt.partitions[0].asserted_signals |= 1U;
    }
    g_spm_sp[i].wait_kind = WT_SPM_WAIT_SIG;
    g_spm_sp[i].wait_mask = 1U;
    g_rt.partitions[i].asserted_signals = 0U;
    return 1U;
}

wt_sp_recovery_decision_t wt_sp_recovery_run(
    const wt_sp_recovery_ops_t* ops, void* ctx, wt_restart_action_t action,
    uint32_t restart_limit, uint32_t restart_window_ticks,
    uint32_t monotonic_ticks, uint32_t* restart_count,
    uint32_t* first_restart_tick)
{
    (void)action;
    (void)restart_limit;
    (void)restart_window_ticks;
    (void)monotonic_ticks;
    (void)first_restart_tick;
    if (ops->restart(ctx) != 0) {
        return WT_SP_RECOVERY_ESCALATE;
    }
    (*restart_count)++;
    return WT_SP_RECOVERY_RESTART;
}

const wt_scheduler_state_t* wt_monitor_state(void)
{
    return &g_sched;
}

void wt_arch_assert_privileged_thread(void)
{
}

void wt_arch_diag_trap(uint32_t a, uint32_t b, uint32_t c)
{
    (void)a;
    (void)b;
    (void)c;
}

int wt_arch_secure_irq_claim(uint32_t irq)
{
    (void)irq;
    return 0;
}

int wt_ffm_msg_complete(const wt_ffm_runtime_t* runtime, uint16_t msg_index)
{
    (void)runtime;
    (void)msg_index;
    return 0;
}

void wt_arch_secure_irq_disable(uint32_t irq)
{
    (void)irq;
}

void wt_arch_sp_band_reset(uintptr_t base, size_t size)
{
    (void)base;
    (void)size;
}

void wt_arch_zero_guest_memory(uintptr_t base, size_t size)
{
    (void)base;
    (void)size;
}

int wt_ffm_partition_restarted(wt_ffm_runtime_t* runtime,
                               int32_t partition_id, psa_status_t status)
{
    (void)runtime;
    (void)partition_id;
    (void)status;
    return WT_FFM_SUCCESS;
}

void wt_hsm_release_locks(struct wt_co* co)
{
    (void)co;
}

void wt_nvm_client_partition_vault_restarted(void)
{
}

void wt_platform_all_guests_faulted(void)
{
    (void)printf("FAIL: unexpected all-guests-faulted\n");
    exit(1);
}

static void check(int ok, const char* what)
{
    (void)printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

static void test_setup(int s0, int s1, int s2)
{
    size_t i;

    (void)memset(g_co, 0, sizeof(g_co));
    (void)memset(g_script, 0, sizeof(g_script));
    (void)memset(g_runs, 0, sizeof(g_runs));
    (void)memset(g_spm_sp, 0, sizeof(g_spm_sp));
    (void)memset(&g_rt, 0, sizeof(g_rt));
    (void)memset(&g_manifest, 0, sizeof(g_manifest));
    g_script[0][0] = s0;
    g_script[1][0] = s1;
    g_script[2][0] = s2;
    for (i = 0U; i < TEST_SPS; i++) {
        g_domains[i].id = (wt_domain_id_t)(i + 1U);
        g_co[i].state = WT_CO_BLOCKED;
        g_rt.partitions[i].manifest = &g_parts[i];
        g_spm_sp[i].co = &g_co[i];
        g_spm_sp[i].partition_id = (int32_t)(i + 1U);
        g_spm_sp[i].partition_index = (uint16_t)i;
        g_spm_sp[i].in_use = 1U;
    }
    g_manifest.domains = g_domains;
    g_manifest.domain_count = TEST_SPS;
    g_rt.manifest = &g_manifest;
    g_rt.partition_count = TEST_SPS;
    g_spm_sp_count = TEST_SPS;
    g_spm_svc_runtime = &g_rt;
}

int main(void)
{
    test_setup(STEP_WAIT, STEP_WAIT, STEP_WAIT);
    check(wt_spm_sched_start_all() == WT_FFM_SUCCESS &&
          g_runs[0] == 1U && g_runs[1] == 1U && g_runs[2] == 1U,
          "WT-FFM-0013 every partition runs once to its first wait");

    test_setup(STEP_WAIT, STEP_WAIT, STEP_WAKE_FIRST);
    check(wt_spm_sched_start_all() == WT_FFM_SUCCESS &&
          g_runs[0] == 2U && g_rt.partitions[0].asserted_signals == 0U,
          "WT-FFM-0013 start-up IPC is drained before the NSPE starts");

    test_setup(STEP_WAKE_NEXT, STEP_FAULT, STEP_WAIT);
    check(wt_spm_sched_start_all() == WT_FFM_ERROR_STATE,
          "WT-FFM-0013 a fault in a drained partition refuses the boot");

    test_setup(STEP_WAIT, STEP_FAULT, STEP_WAIT);
    check(wt_spm_sched_start_all() == WT_FFM_ERROR_STATE,
          "WT-FFM-0013 a partition faulting on first entry refuses the boot");

    test_setup(STEP_WAIT, STEP_WAIT, STEP_STOP);
    check(wt_spm_sched_start_all() == WT_FFM_ERROR_STATE,
          "WT-FFM-0013 a partition that never reaches a wait refuses the "
          "boot");

    test_setup(STEP_WAIT, STEP_WAIT_REPLY, STEP_WAIT);
    check(wt_spm_sched_start_all() == WT_FFM_ERROR_STATE,
          "WT-FFM-0013 a partition left waiting on a reply refuses the boot");

    g_spm_svc_runtime = NULL;
    check(wt_spm_sched_start_all() == WT_FFM_ERROR_STATE,
          "start-up before the SPM runtime exists is refused");

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: spm_start (FF-M start-up pass)\n");
    return 0;
}
