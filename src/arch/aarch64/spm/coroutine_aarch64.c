/* coroutine_aarch64.c
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

/* Coroutine architecture hooks at Secure EL1. Privileged tasklets run at
 * S-EL1 through a synchronous save/restore switch. Unprivileged Secure
 * Partitions run at S-EL0: entering one ERETs into its saved register
 * state under its own translation table, and it comes back when its SVC
 * or fault handler unwinds to the bootstrap through wt_sp_el0_leave. */

#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/ffa_notif.h"
#include "wolftrust/arch/aarch64/ffa_runtime.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/spm_mem.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/arch.h"
#include "wolftrust/platform.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/spm_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* One stage-1 table per coroutine domain, so the table cap must cover every
 * coroutine (the boot self-tests keep theirs too). */
#if WT_DOMAIN_MAX_TABLES < (WT_CO_MAX + WT_DOMAIN_PROOF_TABLES + 1u)
#error "WT_DOMAIN_MAX_TABLES must cover WT_CO_MAX partitions, the boot proofs, and a borrower rebuild"
#endif

/* FF-A ids: SPMC 0x8000, SPMD 0x8001, partitions follow in creation order. */
#define WT_SP_FFA_ID_BASE 0x8001u

volatile uint32_t g_wt_spm_partitions_live;
static uint32_t g_sp_init_count;

/* The core clears this on a partition fault; the AArch64 switch is
 * synchronous and never consults it, but the symbol must resolve. */
struct wt_co* g_wt_co_pendsv_target;

uint32_t wt_spm_sp_init_count(void)
{
    return g_sp_init_count;
}

void wt_co_arch_switch(uintptr_t* save_from_sp, uintptr_t to_sp);
void wt_co_trampoline(void);

/* Frame the first switch-in restores: x19..x30 at 8-byte slots 0..11. */
#define WT_CO_FRAME_WORDS 12u
#define WT_CO_SLOT_X19 0u
#define WT_CO_SLOT_X20 1u
#define WT_CO_SLOT_X30 11u
/* EL0t with A masked and IRQ and FIQ open, so the scheduling tick (Group 0)
 * preempts a running partition into the SPMC and a pending Normal-world
 * Group 1 interrupt preempts it for the Normal world to take (Ch.9). */
#define WT_SP_SPSR_EL0T 0x100u
/* A partition whose manifest queues Non-secure interrupts runs with the GIC
 * priority mask at the top of the Non-secure range, so a Normal-world
 * interrupt stays pending until it returns there instead of preempting it
 * (ns-interrupts-action = queued); Secure priorities stay below the mask. */
static uint8_t g_ns_queued[WT_CO_MAX];
/* Non-secure interrupts stay queued for a run the SPMC scheduled for a Secure
 * interrupt (9.2.4 rule 3) and for a callee whose caller queues them (9.3.1.4). */
static uint8_t g_ns_inherited[WT_CO_MAX];

static wt_sp_arch_t* sp_arch(const struct wt_co *co);
static int endpoint_waiting(const struct wt_co* co);
static struct wt_co* sint_take_waiting_owner(void);
static void sp_release(struct wt_co* co, int32_t code);
static int run_endpoint_from(struct wt_co* co, struct wt_co* callee,
                             uint64_t* out, uint8_t spmc);
/* The endpoint a blocking partition's direct request or FFA_RUN names. */
static struct wt_co* g_ffa_call_target;
/* Set when a Secure interrupt is queued for a waiting partition while another
 * one runs; the run loop stops the runner so the owner is signaled first. */
static volatile uint32_t g_sint_signal_request;

#define WT_SP_INIT_MAX_PASSES 16u

static wt_sp_arch_t g_sp_arch[WT_CO_MAX];
/* 8.5 progress: initializing, initialized (FFA_MSG_WAIT), or failed
 * (FFA_ERROR), after which the partition waits and is never run again. */
#define WT_SP_INIT_PENDING 0u
#define WT_SP_INIT_DONE    1u
#define WT_SP_INIT_FAILED  2u
static uint8_t g_init_seen[WT_CO_MAX];
/* Set while a partition is inside the FF-M gate, where blocking (its psa_wait)
 * is how an FF-M partition, which makes no FF-A calls, completes its init. */
static uint8_t g_init_gate[WT_CO_MAX];
static uint8_t g_faulted_once[WT_CO_MAX];
static uint8_t g_retired[WT_CO_MAX];
static struct wt_co* g_created[WT_CO_MAX];
static uint32_t g_partitions_initialized;

#if defined(WT_SPM_ECHO_SP)
/* Proof that the init pass resumes a partition preempted before its first
 * wait: a tick already due is taken at the echo partition's first instruction. */
static uint8_t g_init_preempt_armed;

static void init_preempt_probe(const struct wt_co* co)
{
    if ((g_init_preempt_armed == 0u) && (co == wt_spm_ffa_echo_partition())) {
        g_init_preempt_armed = 1u;
        wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
        wt_el3_timer_arm_ms(0u);
    }
}
#else
static void init_preempt_probe(const struct wt_co* co)
{
    (void)co;
}
#endif

/* Run one partition from its entry (or its recovery re-arm) until it blocks
 * or faults, once; returns non-zero if it ran. A partition that faulted on
 * an earlier pass and has been re-armed since prints its restart marker; one
 * preempted before its first wait resumes where it was interrupted. */
static int run_pending_partition(unsigned int i)
{
    uint64_t out[WT_FFA_MSG_REGS_EXT];
    struct wt_co* co = g_created[i];
    wt_co_state_t state;

    if (co == NULL || co->unprivileged == 0u ||
        g_init_seen[i] != WT_SP_INIT_PENDING) {
        return 0;
    }
    state = wt_co_state((wt_co_t*)co);
    if (state == WT_CO_RUNNABLE) {
        wt_el3_puts("[SP] init resumed id=0x");
        wt_el3_puthex((uint64_t)WT_SP_FFA_ID_BASE + co->id, 4u);
        wt_el3_puts("\r\n");
    }
    else if (state != WT_CO_BLOCKED) {
        return 0; /* FAULTED (restart budget spent) or otherwise not runnable */
    }
    else {
        if (g_faulted_once[i] != 0u) {
            g_faulted_once[i] = 0u;
            wt_el3_puts("[SP] restarted id=0x");
            wt_el3_puthex((uint64_t)WT_SP_FFA_ID_BASE + co->id, 4u);
            wt_el3_puts("\r\n");
        }
        init_preempt_probe(co);
        wt_co_wake((wt_co_t*)co);
    }
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_NONE;
    (void)wt_co_run((wt_co_t*)co);
    if (g_wt_ffa_sp_exit == WT_FFA_SP_EXIT_CALL) {
        /* 8.5 rule 1: its callee runs now, and it resumes still initializing
         * with the reply until it waits. */
        (void)run_endpoint_from(co, g_ffa_call_target, out, 1u);
    }
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_NONE;
    if (wt_co_state((wt_co_t*)co) == WT_CO_FAULTED) {
        g_faulted_once[i] = 1u;
    }
    return 1;
}

/* FF-A init model (5.3, 8.5): before the SPMC waits for events, every
 * partition runs from its entry until it signals successful initialization
 * with FFA_MSG_WAIT (an FF-M partition by blocking in the FF-M gate). A
 * partition that faults during init is routed through the core's restart
 * policy (wt_spm_recover_faulted re-arms it) and re-run; one that faults every
 * time exhausts its budget and fails closed. */
#if defined(WT_SPM_ECHO_SP)
/* The FF-A native echo partition for the direct-message proofs: created in the
 * init pass, after the core has created the manifest partitions, so it
 * initializes (parks in FFA_MSG_WAIT) exactly like they do. It executes the
 * shared code every partition maps and owns the band enable_mmu published. */
static struct wt_co* g_echo_co;
static wt_secure_domain_t g_echo_domain;

static void create_echo_partition(void)
{
    size_t n;
    wt_co_t* co;

    if ((g_echo_co != NULL) || (g_wt_spm_echo_stack_size == 0u)) {
        return;
    }
    n = wt_platform_sp_shared_regions(g_echo_domain.regions, 2u);
    if (n != 2u) {
        return;
    }
    g_echo_domain.regions[n].base = g_wt_spm_echo_stack_base;
    g_echo_domain.regions[n].size = (size_t)g_wt_spm_echo_stack_size;
    g_echo_domain.regions[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_echo_domain.region_count = n + 1u;
    co = wt_co_create_blocked_ex((uint8_t*)(uintptr_t)g_wt_spm_echo_stack_base,
                                 (size_t)g_wt_spm_echo_stack_size,
                                 (wt_co_entry_fn)wt_sp_ffa_echo, (void*)0);
    if (co == NULL) {
        return;
    }
    wt_co_set_domain(co, &g_echo_domain, 1u);
    g_echo_co = (struct wt_co*)co;
}

struct wt_co* wt_spm_ffa_echo_partition(void)
{
    return g_echo_co;
}
#else
static void create_echo_partition(void)
{
}

struct wt_co* wt_spm_ffa_echo_partition(void)
{
    return NULL;
}
#endif

#if defined(WT_FFA_ACS) && (WT_FFA_ACS == 1)
static struct wt_co* g_native_co[WT_FFA_NATIVE_SP_MAX];
static wt_secure_domain_t g_native_domain[WT_FFA_NATIVE_SP_MAX];
static const wt_ffa_native_sp_t* g_native_list;
static size_t g_native_count;

/* Created in the init pass after the manifest partitions, so each native
 * partition initializes (runs to its first FFA_MSG_WAIT) exactly like them. */
static void create_native_partitions(void)
{
    const wt_ffa_native_sp_t* list;
    size_t count = 0u;
    size_t i;
    size_t j;
    wt_co_t* co;

    if (g_native_list != NULL) {
        return;
    }
    list = wt_platform_ffa_native_partitions(&count);
    if ((list == NULL) || (count > WT_FFA_NATIVE_SP_MAX)) {
        return;
    }
    for (i = 0u; i < count; i++) {
        if (list[i].region_count > WT_FFA_NATIVE_SP_REGIONS) {
            wt_platform_panic();
        }
        for (j = 0u; j < list[i].region_count; j++) {
            g_native_domain[i].regions[j] = list[i].regions[j];
        }
        g_native_domain[i].region_count = list[i].region_count;
        g_native_domain[i].stack_base = list[i].stack_base;
        g_native_domain[i].stack_size = list[i].stack_size;
        co = wt_co_create_blocked_ex((uint8_t*)list[i].stack_base,
                                     list[i].stack_size,
                                     (wt_co_entry_fn)list[i].entry, (void*)0);
        if (co == NULL) {
            wt_platform_panic();
        }
        wt_co_set_domain(co, &g_native_domain[i], 1u);
        g_ns_queued[((struct wt_co*)co)->id - 1u] =
            (list[i].ns_int_action == 0u) ? 1u : 0u;
        g_native_co[i] = (struct wt_co*)co;
        if (wt_spm_mem_bind(wt_spm_sp_ffa_id((struct wt_co*)co),
                            (struct wt_co*)co, &g_native_domain[i]) != 0) {
            wt_platform_panic();
        }
    }
    g_native_list = list;
    g_native_count = count;
}

const wt_ffa_native_sp_t* wt_spm_ffa_native_list(size_t* count)
{
    *count = g_native_count;
    return g_native_list;
}

uint16_t wt_spm_ffa_native_id(size_t index)
{
    return (index < g_native_count) ? wt_spm_sp_ffa_id(g_native_co[index]) : 0u;
}

struct wt_co* wt_spm_ffa_native_by_id(uint16_t id)
{
    size_t i;

    for (i = 0u; i < g_native_count; i++) {
        if ((id != 0u) && (wt_spm_sp_ffa_id(g_native_co[i]) == id)) {
            return g_native_co[i];
        }
    }
    return NULL;
}

static const wt_ffa_native_sp_t* native_of(const struct wt_co* co)
{
    size_t i;

    for (i = 0u; i < g_native_count; i++) {
        if (g_native_co[i] == co) {
            return &g_native_list[i];
        }
    }
    return NULL;
}

int wt_spm_sint_declared_any(uint32_t intid)
{
    size_t i;

    for (i = 0u; i < g_native_count; i++) {
        if (wt_spm_native_declares(&g_native_list[i], intid) != 0) {
            return 1;
        }
    }
    return 0;
}
#else
static void create_native_partitions(void)
{
}

const wt_ffa_native_sp_t* wt_spm_ffa_native_list(size_t* count)
{
    *count = 0u;
    return NULL;
}

uint16_t wt_spm_ffa_native_id(size_t index)
{
    (void)index;
    return 0u;
}

struct wt_co* wt_spm_ffa_native_by_id(uint16_t id)
{
    (void)id;
    return NULL;
}

static const wt_ffa_native_sp_t* native_of(const struct wt_co* co)
{
    (void)co;
    return NULL;
}

int wt_spm_sint_declared_any(uint32_t intid)
{
    (void)intid;
    return 0;
}
#endif

void wt_spm_init_partitions(void)
{
    size_t native_count = 0u;
    size_t n;
    unsigned int i;
    unsigned int pass;
    int progressed;

    if (g_partitions_initialized != 0u || g_wt_spm_partitions_live == 0u) {
        return;
    }
    g_partitions_initialized = 1u;
#if defined(WT_ENGINE_HSM)
    /* Seat the Normal-world guest's wolfHSM relay server. This port loads the
     * guest externally rather than as a port-managed partition, so it reports
     * zero guests to the monitor and the core boot loop never seats it; the
     * single externally-loaded guest still reaches SERVICE_HSM as guest 0. */
    if (wt_hsm_guest_init_relay((wt_guest_id_t)0) != 0) {
        wt_platform_panic();
    }
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* The core's boot-time attestation bootstrap found no seated guest; run
     * it now. A failure leaves attestation failing closed, as at boot. */
    (void)wt_hsm_attest_bootstrap();
#endif
#endif
    create_echo_partition();
    create_native_partitions();
    /* Seed the notification endpoint table: the Normal-world scheduler and
     * every native partition; a table past its bound simply lacks
     * notifications. */
    wt_ffa_notif_reset();
    (void)wt_ffa_notif_register(WT_FFA_ID_NS_PRIMARY, 0);
    (void)wt_spm_ffa_native_list(&native_count);
    for (n = 0u; n < native_count; n++) {
        (void)wt_ffa_notif_register(wt_spm_ffa_native_id(n), 1);
    }
    for (i = 0u; i < WT_CO_MAX; i++) {
        (void)run_pending_partition(i);
    }
    for (pass = 0u; pass < WT_SP_INIT_MAX_PASSES; pass++) {
        wt_spm_recover_faulted();
        progressed = 0;
        for (i = 0u; i < WT_CO_MAX; i++) {
            if (run_pending_partition(i) != 0) {
                progressed = 1;
            }
        }
        if (progressed == 0) {
            break;
        }
    }
    while (wt_co_tick(8u) != 0u) {
    }
}

/* A partition's FF-A endpoint id follows its creation order (0x8002 up). */
uint16_t wt_spm_sp_ffa_id(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0u;
    }
    return (uint16_t)(WT_SP_FFA_ID_BASE + co->id);
}

struct wt_co* wt_spm_sp_by_ffa_id(uint16_t id)
{
    uint32_t slot;

    if ((id <= WT_SP_FFA_ID_BASE) || (id > (WT_SP_FFA_ID_BASE + WT_CO_MAX))) {
        return NULL;
    }
    slot = (uint32_t)id - WT_SP_FFA_ID_BASE - 1u;
    if ((g_created[slot] == NULL) || (g_created[slot]->unprivileged == 0u)) {
        return NULL;
    }
    return g_created[slot];
}

/* The live endpoint id of the partition confined to a manifest domain, or 0
 * when no created partition runs in it. */
uint16_t wt_spm_sp_ffa_id_of_domain(uint32_t domain_id)
{
    const struct wt_co* co;
    unsigned int i;

    for (i = 0u; i < WT_CO_MAX; i++) {
        co = g_created[i];
        if ((co != NULL) && (co->id != 0u) && (co->unprivileged != 0u) &&
            (co->domain != NULL) &&
            ((uint32_t)co->domain->domain_id == domain_id)) {
            return wt_spm_sp_ffa_id(co);
        }
    }
    return 0u;
}

/* Non-zero until the partition signals successful initialization. */
int wt_spm_sp_initializing(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0;
    }
    return (g_init_seen[co->id - 1u] == WT_SP_INIT_PENDING) ? 1 : 0;
}

int wt_spm_sp_failed_init(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0;
    }
    return (g_init_seen[co->id - 1u] == WT_SP_INIT_FAILED) ? 1 : 0;
}

void wt_spm_sp_init_complete(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX) ||
        (g_init_seen[co->id - 1u] != WT_SP_INIT_PENDING)) {
        return;
    }
    g_init_seen[co->id - 1u] = WT_SP_INIT_DONE;
    if (g_wt_spm_partitions_live != 0u) {
        g_sp_init_count++;
        wt_el3_puts("[SP] init id=0x");
        wt_el3_puthex((uint64_t)WT_SP_FFA_ID_BASE + co->id, 4u);
        wt_el3_puts("\r\n");
    }
}

void wt_spm_sp_init_failed(struct wt_co* co, int32_t code)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX) ||
        (g_init_seen[co->id - 1u] != WT_SP_INIT_PENDING)) {
        return;
    }
    g_init_seen[co->id - 1u] = WT_SP_INIT_FAILED;
    sp_release(co, WT_FFA_DENIED);
    if (g_wt_spm_partitions_live != 0u) {
        wt_el3_puts("[SP] init failed id=0x");
        wt_el3_puthex((uint64_t)WT_SP_FFA_ID_BASE + co->id, 4u);
        wt_el3_puts(" err=-");
        wt_el3_putdec((uint64_t)(0 - (int64_t)code));
        wt_el3_puts("\r\n");
    }
}

void wt_spm_sp_in_gate(const struct wt_co* co, unsigned int inside)
{
    if ((co != NULL) && (co->id != 0u) && (co->id <= WT_CO_MAX)) {
        g_init_gate[co->id - 1u] = (inside != 0u) ? 1u : 0u;
    }
}

static wt_sp_arch_t* sp_arch(const struct wt_co *co)
{
    if (co->id == 0u || co->id > WT_CO_MAX) {
        wt_platform_panic();
    }
    return &g_sp_arch[co->id - 1u];
}

/* FF-A runtime state of one S-EL0 endpoint (Ch.8): busy while it processes a
 * direct request, yielded after FFA_YIELD until FFA_RUN resumes it. */
typedef struct wt_sp_msg {
    uint16_t requester;
    uint16_t self;
    uint8_t busy;
    uint8_t yielded;
    uint8_t calling;
    uint8_t req2;
    /* The requester left service while this endpoint was yielded to it:
     * anyone may run it, and its response has no receiver. */
    uint8_t orphaned;
} wt_sp_msg_t;

static wt_sp_msg_t g_sp_msg[WT_CO_MAX];
volatile uint32_t g_wt_ffa_sp_exit;

int wt_spm_ffa_sp_requester(const struct wt_co* co, uint16_t* requester,
                            uint16_t* self)
{
    const wt_sp_msg_t* m;

    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0;
    }
    m = &g_sp_msg[co->id - 1u];
    if (m->busy == 0u) {
        return 0;
    }
    *requester = m->requester;
    *self = m->self;
    return 1;
}

int wt_spm_ffa_sp_req2(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0;
    }
    return (int)g_sp_msg[co->id - 1u].req2;
}

int wt_spm_ffa_sp_yielded_to(const struct wt_co* co, uint16_t caller)
{
    const wt_sp_msg_t* m;

    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0;
    }
    m = &g_sp_msg[co->id - 1u];
    return ((m->yielded != 0u) && (m->busy != 0u) &&
            (m->requester == caller)) ? 1 : 0;
}

/* Hand a blocked partition an 8-register event (fid, w1) as the return of the
 * call it is blocked in. */
static void deliver_event(struct wt_co* co, uint32_t fid, uint64_t w1)
{
    uint64_t msg[WT_FFA_MSG_REGS];
    unsigned int i;

    for (i = 0u; i < WT_FFA_MSG_REGS; i++) {
        msg[i] = 0u;
    }
    msg[0] = fid;
    msg[1] = w1;
    wt_ffa_msg_deliver(sp_arch(co)->frame.x, msg);
}

/* Stage a queued Secure interrupt for delivery: its FFA_INTERRUPT becomes the
 * return of the call the partition is blocked in, with w1/w2 zero as an S-EL0
 * partition reads the id with the get call (12.4.1 item 3). Returns 1 if one
 * was. */
static unsigned int sint_stage(struct wt_co* co)
{
    if (wt_spm_sint_take_pending(co) == 0u) {
        return 0u;
    }
    deliver_event(co, WT_FFA_INTERRUPT, 0u);
    return 1u;
}

/* Run one endpoint until it hands the CPU back, and turn how it did so into
 * the registers its invoker sees: its direct response, FFA_YIELD, or
 * FFA_MSG_WAIT. WT_FFA_SP_EXIT_CALL and WT_FFA_SP_EXIT_SIGNAL are returned
 * as-is for the chain below; *deliver is set when a Secure interrupt queued
 * while it ran is staged for it after its response (Table 9.1). */
static int run_one(struct wt_co* co, uint64_t* out, uint32_t* reason,
                   unsigned int* deliver)
{
    wt_sp_msg_t* m = &g_sp_msg[co->id - 1u];
    unsigned int i;

    *deliver = 0u;
    g_wt_ffa_direct_resp_ready = 0u;
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_NONE;
    wt_co_wake((wt_co_t*)co);
    (void)wt_co_run((wt_co_t*)co);
    while ((wt_co_state((wt_co_t*)co) == WT_CO_RUNNABLE) &&
           (g_wt_ffa_sp_exit == WT_FFA_SP_EXIT_NONE) &&
           (g_sint_signal_request == 0u)) {
        (void)wt_co_run((wt_co_t*)co);
    }
    if ((wt_co_state((wt_co_t*)co) == WT_CO_RUNNABLE) &&
        (g_wt_ffa_sp_exit == WT_FFA_SP_EXIT_NONE)) {
        g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_SIGNAL;
    }
    *reason = g_wt_ffa_sp_exit;
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_NONE;
    for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
        out[i] = 0u;
    }
    if (wt_co_state((wt_co_t*)co) == WT_CO_FAULTED) {
        (void)memset(m, 0, sizeof(*m));
        *reason = WT_FFA_SP_EXIT_NONE;
        return WT_FFA_ABORTED;
    }
    if ((*reason == WT_FFA_SP_EXIT_CALL) || (*reason == WT_FFA_SP_EXIT_SIGNAL)) {
        return 0;
    }
    if ((*reason == WT_FFA_SP_EXIT_RESP) && (g_wt_ffa_direct_resp_ready != 0u)) {
        for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
            out[i] = g_wt_ffa_direct_resp[i];
        }
        wt_ffa_regs_normalize(out);
        wt_ffa_direct_clear_sbz(out);
        if (m->orphaned != 0u) {
            /* No requester is left to take the response: the endpoint is
             * waiting again, which is what whoever ran it is told. */
            for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
                out[i] = 0u;
            }
            out[0] = WT_FFA_MSG_WAIT;
            out[1] = (uint64_t)wt_spm_sp_ffa_id(co) << 16;
            m->orphaned = 0u;
        }
        m->busy = 0u;
        *deliver = sint_stage(co);
        return 0;
    }
    if (*reason == WT_FFA_SP_EXIT_NSINT) {
        out[0] = WT_FFA_INTERRUPT;
        out[1] = (uint64_t)wt_spm_sp_ffa_id(co) << 16;
        return 0;
    }
    if (*reason == WT_FFA_SP_EXIT_YIELD) {
        m->yielded = 1u;
        out[0] = WT_FFA_YIELD;
        out[1] = (uint64_t)wt_spm_sp_ffa_id(co) << 16;
        return 0;
    }
    if (*reason == WT_FFA_SP_EXIT_WAIT) {
        out[0] = WT_FFA_MSG_WAIT;
        return 0;
    }
    m->busy = 0u;
    return WT_FFA_DENIED;
}

/* The core scheduler does not nest, so an endpoint that messages another one
 * blocks and names its callee; this loop, on the scheduler's stack, runs the
 * callee and writes what it hands back into the caller's saved frame. A
 * partition staged a Secure interrupt after its response, or a waiting owner
 * an interrupt is signaled to, runs detached: stacked on top with its own
 * result discarded, before the frame below resumes (Table 9.1). A detached
 * run, and a root run with spmc set, is in the SPMC scheduled mode. */
static int run_endpoint_from(struct wt_co* co, struct wt_co* callee,
                             uint64_t* out, uint8_t spmc)
{
    struct wt_co* chain[WT_CO_MAX];
    uint8_t detached[WT_CO_MAX];
    uint64_t root_out[WT_FFA_MSG_REGS_EXT];
    struct wt_co* top;
    struct wt_co* caller;
    struct wt_co* waiting;
    unsigned int depth = 1u;
    unsigned int deliver = 0u;
    unsigned int i;
    uint32_t reason = WT_FFA_SP_EXIT_NONE;
    int root_ret = 0;
    int ret;

    chain[0] = co;
    detached[0] = 0u;
    g_ns_inherited[co->id - 1u] = spmc;
    if (callee != NULL) {
        /* co already blocked calling callee, which holds the request. */
        chain[1] = callee;
        detached[1] = 0u;
        g_ns_inherited[callee->id - 1u] =
            ((g_ns_queued[co->id - 1u] != 0u) || (spmc != 0u)) ? 1u : 0u;
        depth = 2u;
    }
    for (;;) {
        top = chain[depth - 1u];
        ret = run_one(top, out, &reason, &deliver);
        if ((ret == 0) && (reason == WT_FFA_SP_EXIT_CALL)) {
            if ((depth == WT_CO_MAX) || (g_ffa_call_target == NULL)) {
                wt_platform_panic();
            }
            chain[depth] = g_ffa_call_target;
            detached[depth] = 0u;
            g_ns_inherited[g_ffa_call_target->id - 1u] =
                ((g_ns_queued[top->id - 1u] != 0u) ||
                 (g_ns_inherited[top->id - 1u] != 0u)) ? 1u : 0u;
            depth++;
            continue;
        }
        if ((ret == 0) && (reason == WT_FFA_SP_EXIT_SIGNAL)) {
            waiting = sint_take_waiting_owner();
            if (waiting != NULL) {
                if (depth == WT_CO_MAX) {
                    wt_platform_panic();
                }
                chain[depth] = waiting;
                detached[depth] = 1u;
                g_ns_inherited[waiting->id - 1u] = 1u;
                depth++;
            }
            continue;
        }
        if (detached[depth - 1u] != 0u) {
            depth--;
            g_ns_inherited[top->id - 1u] = 0u;
            if (depth == 0u) {
                for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
                    out[i] = root_out[i];
                }
                return root_ret;
            }
            continue;
        }
        if (depth == 1u) {
            if (deliver == 0u) {
                g_ns_inherited[top->id - 1u] = 0u;
                return ret;
            }
            for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
                root_out[i] = out[i];
            }
            root_ret = ret;
            detached[0] = 1u;
            g_ns_inherited[top->id - 1u] = 1u;
            continue;
        }
        depth--;
        g_ns_inherited[top->id - 1u] = 0u;
        caller = chain[depth - 1u];
        g_sp_msg[caller->id - 1u].calling = 0u;
        if (ret != 0) {
            for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
                out[i] = 0u;
            }
            out[0] = WT_FFA_ERROR;
            out[2] = (uint64_t)(uint32_t)ret;
        }
        wt_ffa_msg_deliver(sp_arch(caller)->frame.x, out);
        if (deliver != 0u) {
            chain[depth] = top;
            detached[depth] = 1u;
            g_ns_inherited[top->id - 1u] = 1u;
            depth++;
        }
    }
}

/* Waiting (4.10) is only reached through a completed initialization. */
static int run_endpoint(struct wt_co* co, uint64_t* out, uint8_t spmc)
{
    return run_endpoint_from(co, NULL, out, spmc);
}

static int endpoint_waiting(const struct wt_co* co)
{
    const wt_sp_msg_t* m = &g_sp_msg[co->id - 1u];

    return ((wt_co_state((wt_co_t*)co) == WT_CO_BLOCKED) && (m->busy == 0u) &&
            (m->yielded == 0u) && (m->calling == 0u) &&
            (g_init_seen[co->id - 1u] == WT_SP_INIT_DONE)) ? 1 : 0;
}

static void endpoint_load_request(struct wt_co* co, const uint64_t* req)
{
    wt_sp_arch_t* a = sp_arch(co);
    wt_sp_msg_t* m = &g_sp_msg[co->id - 1u];
    unsigned int count = wt_ffa_msg_reg_count(req[0]);

    wt_ffa_msg_deliver(a->frame.x, req);
    wt_ffa_regs_normalize(a->frame.x);
    wt_ffa_direct_clear_sbz(a->frame.x);
    m->busy = 1u;
    m->req2 = (count == WT_FFA_MSG_REGS_EXT) ? 1u : 0u;
    m->requester = (uint16_t)(req[1] >> 16);
    m->self = (uint16_t)(req[1] & 0xFFFFu);
}

/* FFA_MSG_SEND_DIRECT_REQ2 names a service by UUID in x2/x3 (15.4): it must be
 * Nil or the receiver's own. */
static int req2_uuid_ok(const struct wt_co* co, const uint64_t* req)
{
    const wt_ffa_native_sp_t* natives;
    size_t count = 0u;
    size_t i;
    unsigned int j;
    int match;

    if ((uint32_t)req[0] != WT_FFA_MSG_SEND_DIRECT_REQ2) {
        return 1;
    }
    if ((req[2] == 0u) && (req[3] == 0u)) {
        return 1;
    }
    natives = wt_spm_ffa_native_list(&count);
    for (i = 0u; i < count; i++) {
        if (wt_spm_ffa_native_by_id(wt_spm_ffa_native_id(i)) != co) {
            continue;
        }
        match = 1;
        for (j = 0u; j < 16u; j++) {
            if (natives[i].uuid[j] !=
                (uint8_t)(req[2u + (j / 8u)] >> (8u * (j % 8u)))) {
                match = 0;
            }
        }
        return match;
    }
    return 0;
}

/* A partition's own direct request (req != NULL) or its FFA_RUN of a callee
 * that yielded to it (req == NULL): arm the callee; the gate then blocks the
 * caller with WT_FFA_SP_EXIT_CALL and the chain above does the rest. */
int wt_spm_ffa_sp_call(const struct wt_co* caller, struct wt_co* target,
                       const uint64_t* req)
{
    wt_sp_msg_t* m;
    unsigned int preempted;

    int ret;

    if ((caller == NULL) || (target == NULL) || (target == caller) ||
        (target->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (wt_spm_sp_unavailable(target) == WT_FFA_ABORTED) {
        return WT_FFA_ABORTED;
    }
    if (wt_spm_sp_initializing(caller) != 0) {
        ret = wt_ffa_rt_init_call((req != NULL) ? (uint32_t)req[0] : WT_FFA_RUN,
                                  (g_init_seen[target->id - 1u] ==
                                   WT_SP_INIT_DONE) ? 1 : 0);
        if (ret != 0) {
            return ret;
        }
    }
    if (req != NULL) {
        if (req2_uuid_ok(target, req) == 0) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if (wt_spm_sp_failed_init(target) != 0) {
            return WT_FFA_DENIED;
        }
        if (endpoint_waiting(target) == 0) {
            return WT_FFA_BUSY;
        }
        endpoint_load_request(target, req);
    }
    else {
        m = &g_sp_msg[target->id - 1u];
        preempted = (wt_co_state((wt_co_t*)target) == WT_CO_RUNNABLE) ? 1u : 0u;
        if ((m->busy == 0u) ||
            (wt_ffa_run_busy_check(m->requester, wt_spm_sp_ffa_id(caller),
                                   m->yielded, preempted) != 0)) {
            return WT_FFA_DENIED;
        }
        m->yielded = 0u;
    }
    g_sp_msg[caller->id - 1u].calling = 1u;
    g_ffa_call_target = target;
    return 0;
}

/* The waiting partition's saved frame holds the registers its FFA_MSG_WAIT
 * returns with, so the request is written there and the partition resumed. */
int wt_spm_ffa_direct_deliver(struct wt_co* co, const uint64_t* req,
                              uint64_t* resp)
{
    if ((co == NULL) || (req == NULL) || (resp == NULL) || (co->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (wt_spm_sp_unavailable(co) == WT_FFA_ABORTED) {
        return WT_FFA_ABORTED;
    }
    if (req2_uuid_ok(co, req) == 0) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (wt_spm_sp_failed_init(co) != 0) {
        return WT_FFA_DENIED;
    }
    if (endpoint_waiting(co) == 0) {
        return WT_FFA_BUSY;
    }
    endpoint_load_request(co, req);
    return run_endpoint(co, resp, 0u);
}

/* FFA_RUN: resume an endpoint that yielded, or give cycles to a waiting one
 * (it sees FFA_RUN as the return of its FFA_MSG_WAIT). */
int wt_spm_ffa_run(struct wt_co* co, uint16_t caller, uint64_t* out)
{
    wt_sp_msg_t* m;

    if ((co == NULL) || (out == NULL) || (co->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (wt_spm_sp_unavailable(co) == WT_FFA_ABORTED) {
        return WT_FFA_ABORTED;
    }
    if (wt_spm_sp_failed_init(co) != 0) {
        return WT_FFA_DENIED;
    }
    m = &g_sp_msg[co->id - 1u];
    if (wt_co_state((wt_co_t*)co) != WT_CO_BLOCKED) {
        /* A partition an NS interrupt preempted mid-request resumes at the
         * interrupted instruction and finishes its response, for its
         * requester only. */
        if ((wt_co_state((wt_co_t*)co) == WT_CO_RUNNABLE) &&
            (m->busy != 0u)) {
            if (wt_ffa_run_busy_check(m->requester, caller, 0u, 1u) != 0) {
                return WT_FFA_DENIED;
            }
            return run_endpoint(co, out, 0u);
        }
        return WT_FFA_BUSY;
    }
    if (m->yielded != 0u) {
        if ((m->busy != 0u) && (m->requester != caller) &&
            (m->orphaned == 0u)) {
            return WT_FFA_DENIED;
        }
        m->yielded = 0u;
    }
    else if ((m->busy != 0u) || (m->calling != 0u) ||
             (wt_spm_sp_initializing(co) != 0)) {
        return WT_FFA_DENIED;
    }
    else {
        deliver_event(co, WT_FFA_RUN, (uint64_t)wt_spm_sp_ffa_id(co) << 16);
    }
    return run_endpoint(co, out, 0u);
}

/* A Secure interrupt taken while its owner runs at S-EL0 is queued here and
 * delivered as FFA_INTERRUPT on the owner's next FFA_MSG_WAIT (Table 9.1). */
static wt_spm_sint_fifo_t g_sp_sint_pending[WT_CO_MAX];
volatile uint32_t g_wt_spm_sint_queued;

void wt_spm_sint_queue(uint32_t intid)
{
    struct wt_co* current = g_wt_co_current;

    if ((current == &g_wt_co_bootstrap) || (current->unprivileged == 0u)) {
        return;
    }
    if (wt_spm_sint_fifo_push(&g_sp_sint_pending[current->id - 1u],
                              intid) == 0) {
        g_wt_spm_sint_queued = intid;
    }
}

void wt_spm_sint_queue_for(struct wt_co* co, uint32_t intid)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return;
    }
    if (wt_spm_sint_fifo_push(&g_sp_sint_pending[co->id - 1u], intid) == 0) {
        g_wt_spm_sint_queued = intid;
    }
}

/* Ownership a partition claims through the para-virtual interrupt enable,
 * and the id its last FFA_INTERRUPT carried, answered by the get. */
#define WT_SPM_SINT_OWNERS 4u
static struct wt_co* g_sint_owner_co[WT_SPM_SINT_OWNERS];
static uint32_t g_sint_owner_id[WT_SPM_SINT_OWNERS];
static uint32_t g_sint_delivered[WT_CO_MAX];

int wt_spm_sint_own(struct wt_co* co, uint32_t intid, unsigned int enable)
{
    unsigned int i;

    if ((co == NULL) || (intid < 32u) || (intid >= WT_GIC_INTID_LIMIT)) {
        return -1;
    }
    for (i = 0u; i < WT_SPM_SINT_OWNERS; i++) {
        if (g_sint_owner_id[i] == intid) {
            if (g_sint_owner_co[i] != co) {
                return -1;
            }
            g_sint_owner_co[i] = (enable != 0u) ? co : NULL;
            if (enable == 0u) {
                g_sint_owner_id[i] = 0u;
            }
            return 0;
        }
    }
    /* Only an interrupt the platform declares for this partition. */
    if ((enable == 0u) || (wt_spm_native_declares(native_of(co), intid) == 0)) {
        return -1;
    }
    for (i = 0u; i < WT_SPM_SINT_OWNERS; i++) {
        if (g_sint_owner_id[i] == 0u) {
            g_sint_owner_id[i] = intid;
            g_sint_owner_co[i] = co;
            return 0;
        }
    }
    return -1;
}

struct wt_co* wt_spm_sint_owner(uint32_t intid)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_SINT_OWNERS; i++) {
        if ((g_sint_owner_id[i] == intid) && (g_sint_owner_co[i] != NULL)) {
            return g_sint_owner_co[i];
        }
    }
    return NULL;
}

void wt_spm_sint_set_delivered(const struct wt_co* co, uint32_t intid)
{
    if ((co != NULL) && (co->id != 0u) && (co->id <= WT_CO_MAX)) {
        g_sint_delivered[co->id - 1u] = intid;
    }
}

uint32_t wt_spm_sint_delivered(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0u;
    }
    return g_sint_delivered[co->id - 1u];
}

uint32_t wt_spm_sint_take_pending(const struct wt_co* co)
{
    uint32_t intid;

    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0u;
    }
    intid = wt_spm_sint_fifo_pop(&g_sp_sint_pending[co->id - 1u]);
    if (intid != 0u) {
        g_sint_delivered[co->id - 1u] = intid;
    }
    return intid;
}

/* A partition out of service lets go of every Secure interrupt it owns, what
 * was queued for it, its direct-message state, RX/TX pair, and memory
 * transactions, and its notification bindings, which answer code for it. */
static void sp_release(struct wt_co* co, int32_t code)
{
    unsigned int i;

    wt_spm_mem_endpoint_teardown(co);
    for (i = 0u; i < WT_SPM_SINT_OWNERS; i++) {
        if ((g_sint_owner_co[i] == co) && (g_sint_owner_id[i] != 0u)) {
            wt_gic->disable(g_sint_owner_id[i]);
            g_sint_owner_co[i] = NULL;
            g_sint_owner_id[i] = 0u;
        }
    }
    wt_spm_twdog_stop(co);
    (void)memset(&g_sp_sint_pending[co->id - 1u], 0,
                 sizeof(g_sp_sint_pending[0]));
    g_sint_delivered[co->id - 1u] = 0u;
    (void)memset(&g_sp_msg[co->id - 1u], 0, sizeof(g_sp_msg[0]));
    for (i = 0u; i < WT_CO_MAX; i++) {
        if ((i != (co->id - 1u)) && (g_sp_msg[i].busy != 0u) &&
            (g_sp_msg[i].yielded != 0u) &&
            (g_sp_msg[i].requester == wt_spm_sp_ffa_id(co))) {
            g_sp_msg[i].orphaned = 1u;
        }
    }
    wt_spm_sp_ffa_reset(co);
    wt_ffa_notif_retire(wt_spm_sp_ffa_id(co), code);
}

void wt_spm_sp_retire(struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return;
    }
    wt_co_mark_faulted((wt_co_t*)co);
    g_retired[co->id - 1u] = 1u;
    sp_release(co, WT_FFA_ABORTED);
}

int32_t wt_spm_sp_unavailable(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0;
    }
    if (g_retired[co->id - 1u] != 0u) {
        return WT_FFA_ABORTED;
    }
    return (wt_spm_sp_failed_init(co) != 0) ? WT_FFA_DENIED : 0;
}

/* A waiting partition owed a queued Secure interrupt, staged for delivery;
 * clears the signal request once none is left. */
static struct wt_co* sint_take_waiting_owner(void)
{
    struct wt_co* co;
    unsigned int i;

    for (i = 0u; i < WT_CO_MAX; i++) {
        co = g_created[i];
        if ((co != NULL) && (co->unprivileged != 0u) &&
            (g_sp_sint_pending[i].count != 0u) && (endpoint_waiting(co) != 0) &&
            (sint_stage(co) != 0u)) {
            return co;
        }
    }
    g_sint_signal_request = 0u;
    return NULL;
}

int wt_spm_sint_signal_needed(struct wt_co* owner)
{
    if ((owner == NULL) || (owner == g_wt_co_current) ||
        (owner->unprivileged == 0u) || (endpoint_waiting(owner) == 0)) {
        return 0;
    }
    g_sint_signal_request = 1u;
    return 1;
}

/* Signal a waiting partition: FFA_INTERRUPT, w1/w2 zero with the id left to the
 * get call, becomes the return of its wait and it runs, with any partition it
 * messages, until it waits again. With the interrupt also pending in the GIC
 * this drives the queued path instead. */
int wt_spm_ffa_signal_deliver(struct wt_co* co, uint32_t intid)
{
    uint64_t out[WT_FFA_MSG_REGS_EXT];

    if ((co == NULL) || (co->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (endpoint_waiting(co) == 0) {
        return WT_FFA_BUSY;
    }
    deliver_event(co, WT_FFA_INTERRUPT, 0u);
    wt_spm_sint_set_delivered(co, intid);
    return (run_endpoint(co, out, 1u) == WT_FFA_ABORTED) ? WT_FFA_ABORTED : 0;
}

static void write_tpidrro(uint64_t value)
{
    __asm__ volatile("msr TPIDRRO_EL0, %0\n\tisb" : : "r"(value));
}

static uint64_t read_tpidr(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(value));
    return value;
}

static void write_tpidr(uint64_t value)
{
    __asm__ volatile("msr TPIDR_EL0, %0" : : "r"(value));
}

void wt_co_arch_init_stack(struct wt_co *co, wt_co_entry_fn entry, void *arg)
{
    uintptr_t top = ((uintptr_t)co->stack_base + co->stack_size) &
                    ~(uintptr_t)15u;
    uint64_t* frame = (uint64_t*)(top - WT_CO_FRAME_WORDS * sizeof(uint64_t));
    wt_sp_arch_t* a = sp_arch(co);
    unsigned int i;

    for (i = 0u; i < WT_CO_FRAME_WORDS; i++) {
        frame[i] = 0u;
    }
    frame[WT_CO_SLOT_X19] = (uint64_t)(uintptr_t)entry;
    frame[WT_CO_SLOT_X20] = (uint64_t)(uintptr_t)arg;
    frame[WT_CO_SLOT_X30] = (uint64_t)(uintptr_t)&wt_co_trampoline;
    co->sp = (uintptr_t)frame;

    /* The S-EL0 form of the same start: the domain flag arrives later. */
    g_init_seen[co->id - 1u] = WT_SP_INIT_PENDING;
    g_retired[co->id - 1u] = 0u;
    g_init_gate[co->id - 1u] = 0u;
    g_created[co->id - 1u] = co;
    (void)memset(&g_sp_msg[co->id - 1u], 0, sizeof(g_sp_msg[0]));
    wt_spm_sp_ffa_reset(co);
    (void)memset(&a->frame, 0, sizeof(a->frame));
    a->tpidr_el0 = 0u;
    a->frame.x[0] = (uint64_t)(uintptr_t)arg;
    a->frame.elr = (uint64_t)(uintptr_t)entry;
    a->frame.sp_el0 = (uint64_t)top;
    a->frame.spsr = WT_SP_SPSR_EL0T;
}

/* The S-EL1 context wt_sp_el0_enter parks for wt_sp_el0_leave to unwind to
 * (x19-x30 and sp): one slot, so a nested entry must save and put it back. */
extern uint64_t g_wt_sp_kernel_ctx[14];

/* Runs `to` until it blocks, faults or is preempted, then resumes whoever
 * entered it. That is the scheduler on the bootstrap stack, or, for an
 * SP-to-SP message, the exception handler of the partition whose call is being
 * served: the callee's unwind slot, the handler bookkeeping, the current
 * coroutine, and the caller's translation table and thread ids are all
 * single-valued, so they are parked here and restored as soon as `to` comes
 * back so the caller's handler completes (and may itself block) as if the
 * nested run never happened. From the scheduler this reduces to the bootstrap. */
void wt_co_arch_enter(struct wt_co *to)
{
    const struct wt_secure_domain *domain = to->domain;
    uint64_t kernel_ctx[14];
    wt_trap_frame_t* live_frame = g_wt_spm_live_frame;
    uint64_t trap_spsr = g_wt_spm_trap_spsr;
    uint32_t handler_depth = g_wt_spm_handler_depth;
    struct wt_co *handler_co = g_wt_spm_handler_co;
    struct wt_co *prev = (handler_depth != 0u) ? handler_co : &g_wt_co_bootstrap;
    uint64_t tpidr = 0u;
    uint32_t pmr = 0u;
    unsigned int masked = 0u;

    /* No FF-A path allocates cycles to a partition that failed to initialize;
     * one that tries anyway (the FF-M gate on a pending signal) finds it gone. */
    if ((to->unprivileged != 0u) &&
        (g_init_seen[to->id - 1u] == WT_SP_INIT_FAILED)) {
        wt_co_mark_faulted((wt_co_t*)to);
        g_wt_co_current = prev;
        return;
    }
    (void)memcpy(kernel_ctx, g_wt_sp_kernel_ctx, sizeof(kernel_ctx));
    if (domain != NULL) {
        wt_arch_program_sp_thread_domain(domain->regions, domain->region_count);
    }
    if (to->unprivileged != 0u) {
        write_tpidrro((uint64_t)to->id);
        tpidr = read_tpidr();
        write_tpidr(sp_arch(to)->tpidr_el0);
        if ((g_ns_queued[to->id - 1u] != 0u) ||
            (g_ns_inherited[to->id - 1u] != 0u)) {
            pmr = wt_gic->swap_pmr(WT_GIC_PMR_MASK_NS);
            masked = 1u;
        }
        wt_sp_el0_enter(&sp_arch(to)->frame);
        if (masked != 0u) {
            (void)wt_gic->swap_pmr(pmr);
        }
        sp_arch(to)->tpidr_el0 = read_tpidr();
        write_tpidr(tpidr);
    }
    else {
        wt_co_arch_switch(&g_wt_co_bootstrap.sp, to->sp);
    }
    /* `to` blocked, faulted or was preempted. */
    (void)memcpy(g_wt_sp_kernel_ctx, kernel_ctx, sizeof(kernel_ctx));
    g_wt_spm_live_frame = live_frame;
    g_wt_spm_trap_spsr = trap_spsr;
    g_wt_spm_handler_depth = handler_depth;
    g_wt_spm_handler_co = handler_co;
    g_wt_co_current = prev;
    write_tpidrro((prev->unprivileged != 0u) ? (uint64_t)prev->id : 0u);
    if (prev->domain != NULL) {
        wt_arch_program_sp_thread_domain(prev->domain->regions,
                                         prev->domain->region_count);
    }
    else if (domain != NULL) {
        wt_arch_restore_spm_domain();
    }
}

void wt_co_arch_leave(void)
{
    struct wt_co *current = g_wt_co_current;

    if (current->unprivileged != 0u) {
        if (g_wt_spm_live_frame == NULL) {
            wt_platform_panic();
        }
        sp_arch(current)->frame = *g_wt_spm_live_frame;
        g_wt_spm_live_frame = NULL;
        g_wt_spm_handler_depth = 0u;
        if ((wt_co_state((wt_co_t*)current) == WT_CO_BLOCKED) &&
            (g_init_gate[current->id - 1u] != 0u)) {
            wt_spm_sp_init_complete(current);
        }
        g_init_gate[current->id - 1u] = 0u;
        wt_sp_el0_leave();
    }
    wt_co_arch_switch(&current->sp, g_wt_co_bootstrap.sp);
}

/* No deferred trigger: AArch64 has no PendSV, so a preempting tick unwinds
 * synchronously from the FIQ handler (wt_spm_preempt_from_fiq) instead. */
void wt_co_arch_request_preempt(void)
{
}

/* A Group 0 tick took the running S-EL0 partition to the SPMC. Preserve its
 * full interrupted state in the partition's saved frame, mark it runnable
 * again, and unwind to the scheduler exactly as a block does; the partition
 * resumes at the interrupted instruction the next time it is run. Returns
 * without preempting when the SPMC itself (or a privileged tasklet) was
 * running, since only an S-EL0 partition can be resumed from a saved frame. */
void wt_spm_preempt_from_fiq(wt_trap_frame_t* frame)
{
    struct wt_co* current = g_wt_co_current;

    if ((current == &g_wt_co_bootstrap) || (current->unprivileged == 0u)) {
        return;
    }
    g_wt_spm_live_frame = frame;
    g_wt_spm_handler_depth = 1u;
    if (wt_co_request_preempt() == false) {
        g_wt_spm_live_frame = NULL;
        g_wt_spm_handler_depth = 0u;
        return;
    }
    wt_co_arch_leave();
}

/* Non-zero while an S-EL0 partition (not the SPMC or a privileged tasklet) is
 * the running coroutine, so the test-timer only makes its interrupt pending
 * while the partition under test executes. */
int wt_spm_current_is_partition(void)
{
    struct wt_co* current = g_wt_co_current;

    return ((current != &g_wt_co_bootstrap) && (current->unprivileged != 0u)) ?
           1 : 0;
}

/* A Normal-world Group 1 interrupt asserted while the partition ran: the
 * partition is preempted for the Normal world to take it, and the invoker
 * sees FFA_INTERRUPT until FFA_RUN resumes the partition (Ch.9). The GIC is
 * left untouched; the interrupt is the Normal world's to acknowledge. */
void wt_spm_preempt_from_irq(wt_trap_frame_t* frame)
{
    struct wt_co* current = g_wt_co_current;

    if ((current == &g_wt_co_bootstrap) || (current->unprivileged == 0u)) {
        return;
    }
    g_wt_spm_live_frame = frame;
    g_wt_spm_handler_depth = 1u;
    if (wt_co_request_preempt() == false) {
        g_wt_spm_live_frame = NULL;
        g_wt_spm_handler_depth = 0u;
        return;
    }
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_NSINT;
    wt_co_arch_leave();
}
