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
#if WT_DOMAIN_MAX_TABLES < WT_CO_MAX
#error "WT_DOMAIN_MAX_TABLES must be at least WT_CO_MAX"
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
/* EL0t with A and I masked and FIQ open (bit 6 clear), so the scheduling tick
 * preempts a running partition and reaches the SPMC at S-EL1. */
#define WT_SP_SPSR_EL0T 0x180u

#define WT_SP_INIT_MAX_PASSES 16u

static wt_sp_arch_t g_sp_arch[WT_CO_MAX];
static uint8_t g_init_seen[WT_CO_MAX];
static uint8_t g_faulted_once[WT_CO_MAX];
static struct wt_co* g_created[WT_CO_MAX];
static uint32_t g_partitions_initialized;

/* Run one partition from its entry (or its recovery re-arm) until it blocks
 * or faults, once; returns non-zero if it ran. A partition that faulted on
 * an earlier pass and has been re-armed since prints its restart marker. */
static int run_pending_partition(unsigned int i)
{
    struct wt_co* co = g_created[i];

    if (co == NULL || co->unprivileged == 0u || g_init_seen[i] != 0u) {
        return 0;
    }
    if (wt_co_state((wt_co_t*)co) != WT_CO_BLOCKED) {
        return 0; /* FAULTED (restart budget spent) or otherwise not runnable */
    }
    if (g_faulted_once[i] != 0u) {
        g_faulted_once[i] = 0u;
        wt_el3_puts("[SP] restarted id=0x");
        wt_el3_puthex((uint64_t)WT_SP_FFA_ID_BASE + co->id, 4u);
        wt_el3_puts("\r\n");
    }
    wt_co_wake((wt_co_t*)co);
    (void)wt_co_run((wt_co_t*)co);
    if (wt_co_state((wt_co_t*)co) == WT_CO_FAULTED) {
        g_faulted_once[i] = 1u;
    }
    return 1;
}

/* FF-A init model (5.3, 8.5): before the SPMC waits for events, every
 * partition runs once from its entry until it blocks, which is its
 * initialization complete. A partition that faults during init is routed
 * through the core's restart policy (wt_spm_recover_faulted re-arms it) and
 * re-run, bounded so one that faults every time stays quarantined. */
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

void wt_spm_init_partitions(void)
{
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
#endif
    create_echo_partition();
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

static wt_sp_arch_t* sp_arch(const struct wt_co *co)
{
    if (co->id == 0u || co->id > WT_CO_MAX) {
        wt_platform_panic();
    }
    return &g_sp_arch[co->id - 1u];
}

/* The waiting partition's saved frame holds the registers its FFA_MSG_WAIT
 * returns with, so the request is written there and the partition resumed;
 * the gate captures its response and blocks it again before we return. */
int wt_spm_ffa_direct_deliver(struct wt_co* co, const uint64_t* req,
                              uint64_t* resp)
{
    wt_sp_arch_t* a;
    unsigned int i;

    if ((co == NULL) || (req == NULL) || (resp == NULL) || (co->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (wt_co_state((wt_co_t*)co) != WT_CO_BLOCKED) {
        return WT_FFA_BUSY;
    }
    a = sp_arch(co);
    for (i = 0u; i < 8u; i++) {
        a->frame.x[i] = req[i];
    }
    g_wt_ffa_direct_resp_ready = 0u;
    wt_co_wake((wt_co_t*)co);
    (void)wt_co_run((wt_co_t*)co);
    if (wt_co_state((wt_co_t*)co) == WT_CO_FAULTED) {
        return WT_FFA_ABORTED;
    }
    if (g_wt_ffa_direct_resp_ready == 0u) {
        return WT_FFA_DENIED;
    }
    for (i = 0u; i < 8u; i++) {
        resp[i] = g_wt_ffa_direct_resp[i];
    }
    return 0;
}

/* A Secure interrupt taken while its owner runs at S-EL0 is queued here and
 * delivered as FFA_INTERRUPT on the owner's next FFA_MSG_WAIT (Table 9.1). */
static uint32_t g_sp_sint_pending[WT_CO_MAX];
volatile uint32_t g_wt_spm_sint_queued;

void wt_spm_sint_queue(uint32_t intid)
{
    struct wt_co* current = g_wt_co_current;

    if ((current == &g_wt_co_bootstrap) || (current->unprivileged == 0u)) {
        return;
    }
    g_sp_sint_pending[current->id - 1u] = intid;
    g_wt_spm_sint_queued = intid;
}

uint32_t wt_spm_sint_take_pending(const struct wt_co* co)
{
    uint32_t intid;

    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0u;
    }
    intid = g_sp_sint_pending[co->id - 1u];
    g_sp_sint_pending[co->id - 1u] = 0u;
    return intid;
}

/* Signal a waiting partition: write an FFA_INTERRUPT message into its saved
 * frame and resume it. It acknowledges by returning to waiting, so there is no
 * response to capture; the call returns once it blocks again. Used both to
 * signal a waiting owner directly and, with the owned interrupt already made
 * pending in the GIC, to drive the queued path (the partition takes it as a
 * lower-EL FIQ on entry, then the gate delivers the queued interrupt). */
int wt_spm_ffa_signal_deliver(struct wt_co* co, uint32_t intid)
{
    wt_sp_arch_t* a;
    unsigned int i;

    if ((co == NULL) || (co->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (wt_co_state((wt_co_t*)co) != WT_CO_BLOCKED) {
        return WT_FFA_BUSY;
    }
    a = sp_arch(co);
    for (i = 0u; i < 8u; i++) {
        a->frame.x[i] = 0u;
    }
    a->frame.x[0] = WT_FFA_INTERRUPT;
    a->frame.x[1] = (uint64_t)intid;
    wt_co_wake((wt_co_t*)co);
    (void)wt_co_run((wt_co_t*)co);
    if (wt_co_state((wt_co_t*)co) == WT_CO_FAULTED) {
        return WT_FFA_ABORTED;
    }
    return 0;
}

static void write_tpidrro(uint64_t value)
{
    __asm__ volatile("msr TPIDRRO_EL0, %0\n\tisb" : : "r"(value));
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
    g_init_seen[co->id - 1u] = 0u;
    g_created[co->id - 1u] = co;
    (void)memset(&a->frame, 0, sizeof(a->frame));
    a->frame.x[0] = (uint64_t)(uintptr_t)arg;
    a->frame.elr = (uint64_t)(uintptr_t)entry;
    a->frame.sp_el0 = (uint64_t)top;
    a->frame.spsr = WT_SP_SPSR_EL0T;
}

void wt_co_arch_enter(struct wt_co *to)
{
    const struct wt_secure_domain *domain = to->domain;

    if (domain != NULL) {
        wt_arch_program_sp_thread_domain(domain->regions, domain->region_count);
    }
    if (to->unprivileged != 0u) {
        write_tpidrro((uint64_t)to->id);
        wt_sp_el0_enter(&sp_arch(to)->frame);
        write_tpidrro(0u);
    }
    else {
        wt_co_arch_switch(&g_wt_co_bootstrap.sp, to->sp);
    }
    /* Back on the bootstrap stack: `to` blocked or faulted. */
    g_wt_co_current = &g_wt_co_bootstrap;
    if (domain != NULL) {
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
        if (g_wt_spm_partitions_live != 0u && g_init_seen[current->id - 1u] == 0u) {
            g_init_seen[current->id - 1u] = 1u;
            g_sp_init_count++;
            wt_el3_puts("[SP] init id=0x");
            wt_el3_puthex((uint64_t)WT_SP_FFA_ID_BASE + current->id, 4u);
            wt_el3_puts("\r\n");
        }
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
