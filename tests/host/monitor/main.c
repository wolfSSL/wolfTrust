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

#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "wolftrust/arch.h"

/* The architecture boundary is simulated; the scheduler itself is production. */
#include "../../../src/monitor.c"

enum { DISPATCHED = 1, HALTED, PANICKED, TIMED_OUT };
static jmp_buf g_exit;
static int g_event;
static wt_guest_config_t g_configs[2];
static wt_guest_runtime_t g_runtime[2];
static int g_contexts[2];
static int g_failures;
static unsigned int g_idle_ticks;
static unsigned int g_idle_entries;
static unsigned int g_resets;
static bool g_handler;
static int g_verify_result;
static wt_guest_measurement_t g_record;
static bool g_trap_handler;
static unsigned int g_abandoned;

static void check(int ok, const char* name)
{
    (void)printf("%s: WT-SYS-0008 %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        g_failures++;
    }
}

static void setup(size_t count, uint32_t delay)
{
    size_t i;

    (void)memset(g_configs, 0, sizeof(g_configs));
    (void)memset(g_runtime, 0, sizeof(g_runtime));
    (void)memset(&g_scheduler, 0, sizeof(g_scheduler));
    g_scheduler.configs = g_configs;
    g_scheduler.runtime = g_runtime;
    g_scheduler.guest_count = count;
    for (i = 0U; i < count; ++i) {
        g_configs[i].guest_id = (wt_guest_id_t)i;
        g_configs[i].timeslice_ms = 1U;
        g_configs[i].restart_policy.restart_limit = 3U;
        g_configs[i].restart_policy.initial_delay_ticks = delay;
        g_runtime[i].context = (wt_guest_context_t*)&g_contexts[i];
        g_runtime[i].state = WT_GUEST_RUNNING;
    }
    g_idle_ticks = 0U;
    g_idle_entries = 0U;
    g_resets = 0U;
    g_handler = true;
    g_verify_result = WT_GUEST_VERIFY_OK;
    g_wt_first_dispatch_pending = 0U;
    g_trap_handler = false;
    g_abandoned = 0U;
    g_handler_slices = 0U;
}

static int tick(void)
{
    if (setjmp(g_exit) == 0) {
        wt_monitor_on_secure_timer(NULL);
        return 0;
    }
    return g_event;
}

static void finish(int event) __attribute__((noreturn));
static void finish(int event)
{
    g_event = event;
    longjmp(g_exit, 1);
}

static int fault_current(void)
{
    if (setjmp(g_exit) == 0) {
        wt_monitor_on_guest_fault(NULL, WT_FAULT_MEMORY_VIOLATION);
        return PANICKED;
    }
    return g_event;
}

static int schedule(void)
{
    if (setjmp(g_exit) == 0) {
        wt_schedule_next_guest();
    }
    return g_event;
}

void wt_arch_return_to_idle_thread(
    void (*entry)(void) __attribute__((noreturn)))
{
    if (!g_handler) {
        finish(PANICKED);
    }
    g_idle_entries++;
    g_handler = false;
    entry();
}

void wt_arch_wait_for_interrupt(void)
{
    if (g_handler) {
        finish(PANICKED);
    }
    if (++g_idle_ticks > 8U) {
        finish(TIMED_OUT);
    }
    wt_monitor_on_secure_timer(NULL);
}

bool wt_arch_in_handler_mode(void) { return g_handler; }
bool wt_arch_trap_from_guest_thread(void) { return false; }
bool wt_arch_trap_from_guest_handler(void) { return g_trap_handler; }
#ifdef CONFIG_VNET
void wt_arch_route_irq_to_guest(uint32_t irq) { (void)irq; }
void wt_arch_set_guest_irq_pending(uint32_t irq, bool asserted)
{ (void)irq; (void)asserted; }
#endif
void wt_arch_guest_abandon_handler(void) { g_abandoned++; }
void wt_arch_mask_all_guest_irqs(void) {}
void wt_arch_quarantine_pending_irqs(const wt_irq_mask_t* mask) { (void)mask; }
void wt_arch_apply_irq_mask(const wt_irq_mask_t* mask) { (void)mask; }
void wt_arch_program_guest_domain(const wt_memory_region_t* r, size_t n)
{ (void)r; (void)n; }
void wt_platform_program_memory_windows(const wt_memory_window_t* w, size_t n)
{ (void)w; (void)n; }
void wt_arch_start_secure_timer(uint32_t ms) { (void)ms; }
void wt_arch_guest_context_prepare(wt_guest_id_t id, const wt_guest_context_t* c)
{ (void)id; (void)c; }
void wt_arch_guest_context_capture(wt_guest_context_t* c,
                                   const wt_trap_frame_t* f)
{ (void)c; (void)f; }
void wt_arch_guest_context_restore(wt_guest_context_t* c)
{ (void)c; finish(DISPATCHED); }
void wt_arch_zero_guest_memory(uintptr_t base, size_t size)
{ (void)base; (void)size; }
uintptr_t wt_arch_read_fault_address(void) { return 0U; }
uintptr_t wt_arch_trap_pc(const wt_trap_frame_t* f) { (void)f; return 0U; }
void wt_platform_log_fault(wt_guest_id_t id, wt_fault_reason_t r,
                           uintptr_t a, uintptr_t pc)
{ (void)id; (void)r; (void)a; (void)pc; }
void wt_platform_all_guests_faulted(void) { finish(HALTED); }
void wt_platform_panic(void) { finish(PANICKED); }
wt_ffm_runtime_t* wt_ffm_boot_runtime_mut(void) { return NULL; }
int wt_ffm_fail_client_connections(wt_ffm_runtime_t* r, psa_client_id_t id)
{ (void)r; (void)id; return 0; }

void wt_partition_reset_runtime(const wt_guest_config_t* c,
                                wt_guest_runtime_t* r)
{
    (void)c;
    r->state = WT_GUEST_READY;
    r->remaining_delay_ticks = 0U;
    g_resets++;
}

const wt_guest_measurement_t* wt_platform_guest_measurements(size_t* count)
{ *count = 1U; return &g_record; }
int wt_guest_verify_image(const void* p, size_t n,
                          const wt_guest_measurement_t* r, uint32_t version)
{ (void)p; (void)n; (void)r; (void)version; return g_verify_result; }
size_t wt_guest_measurement_count(void) { return 0U; }
const wt_guest_measurement_t* wt_guest_measurement_get(size_t i,
                                                       const char** name)
{ (void)i; (void)name; return NULL; }
int wt_guest_measurement_record(const wt_guest_measurement_t* r,
                                const char* name)
{ (void)r; (void)name; return 0; }

#ifdef CONFIG_VNET
/* Bind guest port vm with mac and queue one frame to it from the peer. */
static int vnet_bind_and_queue(vnet_switch_t* sw, uint32_t vm,
                               const vnet_mac_t* mac, const vnet_mac_t* peer)
{
    uint8_t frame[64];

    (void)memset(frame, 0, sizeof(frame));
    (void)memcpy(&frame[0], mac->b, VNET_MAC_LEN);
    (void)memcpy(&frame[6], peer->b, VNET_MAC_LEN);
    frame[12] = 0x08U;
    return vnet_switch_open(sw, vm, NULL) == WT_VNET_OK &&
           vnet_switch_assign_mac(sw, vm, mac) == WT_VNET_OK &&
           vnet_switch_tx(sw, 1U - vm, frame, sizeof(frame), 0U) == WT_VNET_OK;
}

/* A restarted or quarantined guest's VNET port does not outlive it. */
static void test_vnet_guest_reset(void)
{
    static const vnet_mac_t mac0 = {{0x02, 0, 0, 0, 0, 0x0A}};
    static const vnet_mac_t mac1 = {{0x02, 0, 0, 0, 0, 0x0B}};
    vnet_switch_t* sw;

    wt_vnet_service_init_state();
    sw = wt_vnet_service_switch();
    check(sw != NULL && vnet_switch_open(sw, 1U, NULL) == WT_VNET_OK &&
          vnet_switch_assign_mac(sw, 1U, &mac1) == WT_VNET_OK &&
          vnet_bind_and_queue(sw, 0U, &mac0, &mac1) &&
          vnet_pool_in_use_count(&sw->pool) == 1U,
          "guest port bound with a queued frame");

    setup(2U, 2U);
    wt_monitor_quarantine_guest(0U);
    check(!sw->vnics[0].open && !sw->vnics[0].mac_set &&
          vnet_pool_in_use_count(&sw->pool) == 0U &&
          vnet_fdb_lookup(&sw->fdb, &mac0) == VNET_FDB_NO_VM &&
          sw->vnics[1].open &&
          vnet_fdb_lookup(&sw->fdb, &mac1) == 1U,
          "quarantine releases only that guest's VNET port");

    check(vnet_bind_and_queue(sw, 0U, &mac0, &mac1),
          "guest port rebound after quarantine");
    setup(2U, 2U);
    g_runtime[1].state = WT_GUEST_READY;
    check(fault_current() == DISPATCHED && !sw->vnics[0].open &&
          vnet_pool_in_use_count(&sw->pool) == 0U &&
          vnet_fdb_lookup(&sw->fdb, &mac0) == VNET_FDB_NO_VM,
          "guest restart releases its VNET port");
}
#endif

int main(void)
{
    int event;

    setup(1U, 2U);
    event = fault_current();
    check(event == DISPATCHED && g_idle_entries == 1U &&
          g_idle_ticks == 2U && g_resets == 1U &&
          g_runtime[0].restart_count == 1U,
          "guest recovery completes its bounded backoff");

    setup(1U, 0U);
    event = fault_current();
    check(event == DISPATCHED && g_idle_entries == 1U && g_idle_ticks == 1U,
          "zero-delay recovery reaches a fresh dispatch");

    setup(2U, 2U);
    g_runtime[1].state = WT_GUEST_FAULTED;
    event = fault_current();
    check(event == DISPATCHED && g_idle_ticks == 2U,
          "terminal peer does not prevent recovery");

    setup(2U, 2U);
    g_runtime[1].state = WT_GUEST_STOPPED;
    event = fault_current();
    check(event == DISPATCHED && g_idle_ticks == 2U,
          "stopped peer does not prevent recovery");

    setup(2U, 2U);
    g_runtime[1].state = WT_GUEST_RESTARTING;
    g_runtime[1].remaining_delay_ticks = 1U;
    event = fault_current();
    check(event == DISPATCHED && g_scheduler.current_guest == 1U &&
          g_idle_ticks == 1U && g_runtime[0].state == WT_GUEST_RESTARTING,
          "earliest completed recovery is dispatched");

    setup(2U, 2U);
    g_runtime[1].state = WT_GUEST_READY;
    event = fault_current();
    check(event == DISPATCHED && g_scheduler.current_guest == 1U &&
          g_idle_entries == 0U && g_idle_ticks == 0U,
          "runnable peer retains immediate scheduling");

    setup(1U, 2U);
    g_runtime[0].restart_count = 3U;
    event = fault_current();
    check(event == HALTED && g_runtime[0].state == WT_GUEST_FAULTED &&
          g_idle_entries == 0U,
          "exhausted recovery budget remains terminal");

    setup(2U, 0U);
    g_runtime[0].state = WT_GUEST_STOPPED;
    g_runtime[1].state = WT_GUEST_FAULTED;
    check(schedule() == HALTED && g_idle_entries == 0U,
          "terminal lifecycle states halt without idling");

    setup(1U, 1U);
    g_handler = false;
    g_runtime[0].state = WT_GUEST_RESTARTING;
    g_runtime[0].remaining_delay_ticks = 1U;
    check(schedule() == DISPATCHED && g_idle_entries == 0U &&
          g_idle_ticks == 1U, "thread-mode recovery uses the existing idle stack");

    setup(0U, 0U);
    check(schedule() == HALTED, "empty scheduler remains terminal");

    setup(1U, 1U);
    g_configs[0].launch_required = 1U;
    g_configs[0].memory_window_count = 1U;
    g_configs[0].memory_windows[0].attributes = WT_MEM_ATTR_EXEC;
    g_verify_result = WT_GUEST_VERIFY_ERROR_DIGEST;
    event = fault_current();
    check(event == HALTED && g_runtime[0].state == WT_GUEST_FAULTED &&
          g_resets == 0U, "recovery verification failure remains terminal");

    /* A guest that never leaves a Non-secure handler is bounded: it keeps
     * the CPU only up to the slice limit, then restarts and the peer runs. */
    setup(2U, 2U);
    g_runtime[1].state = WT_GUEST_READY;
    g_trap_handler = true;
    for (event = 0; event == 0 &&
         g_handler_slices + 1U < WT_GUEST_HANDLER_SLICE_LIMIT;) {
        event = tick();
    }
    check(event == 0 && g_runtime[0].state == WT_GUEST_RUNNING &&
          g_abandoned == 0U, "handler residency below the limit is kept");
    event = tick();
    check(event == DISPATCHED && g_scheduler.current_guest == 1U &&
          g_runtime[0].state == WT_GUEST_RESTARTING && g_abandoned == 1U,
          "handler residency past the limit restarts the guest");

    setup(2U, 2U);
    g_runtime[1].state = WT_GUEST_READY;
    for (event = 0; event == 0 &&
         g_idle_ticks < 2U * WT_GUEST_HANDLER_SLICE_LIMIT; g_idle_ticks++) {
        event = tick();
    }
    check(event == 0 && g_runtime[0].state == WT_GUEST_RUNNING &&
          g_abandoned == 0U, "Secure-side ticks never count against a guest");

#ifdef CONFIG_VNET
    test_vnet_guest_reset();
#endif
    return g_failures == 0 ? 0 : 1;
}
