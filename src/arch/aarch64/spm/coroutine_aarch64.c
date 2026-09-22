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
#include "wolftrust/arch/aarch64/ffa_notif.h"
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
 * re-run; one that faults every time exhausts its budget and fails closed. */
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

/* Non-zero until the partition's first block, which completes its init. */
int wt_spm_sp_initializing(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return 0;
    }
    return (g_init_seen[co->id - 1u] == 0u) ? 1 : 0;
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

/* Run one endpoint until it hands the CPU back, and turn how it did so into
 * the registers its invoker sees: its direct response, FFA_YIELD, or
 * FFA_MSG_WAIT. WT_FFA_SP_EXIT_CALL is returned as-is for the chain below. */
static int run_one(struct wt_co* co, uint64_t* out, uint32_t* reason)
{
    wt_sp_msg_t* m = &g_sp_msg[co->id - 1u];
    unsigned int i;

    g_wt_ffa_direct_resp_ready = 0u;
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_NONE;
    wt_co_wake((wt_co_t*)co);
    (void)wt_co_run((wt_co_t*)co);
    while ((wt_co_state((wt_co_t*)co) == WT_CO_RUNNABLE) &&
           (g_wt_ffa_sp_exit == WT_FFA_SP_EXIT_NONE)) {
        (void)wt_co_run((wt_co_t*)co);
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
    if (*reason == WT_FFA_SP_EXIT_CALL) {
        return 0;
    }
    if ((*reason == WT_FFA_SP_EXIT_RESP) && (g_wt_ffa_direct_resp_ready != 0u)) {
        for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
            out[i] = g_wt_ffa_direct_resp[i];
        }
        wt_ffa_regs_normalize(out);
        m->busy = 0u;
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

static struct wt_co* g_ffa_call_target;

/* The core scheduler does not nest, so an endpoint that messages another one
 * blocks and names its callee; this loop, on the scheduler's stack, runs the
 * callee and writes what it hands back into the caller's saved frame. */
static int run_endpoint(struct wt_co* co, uint64_t* out)
{
    struct wt_co* chain[WT_CO_MAX];
    struct wt_co* caller;
    unsigned int depth = 1u;
    unsigned int count;
    unsigned int i;
    uint32_t reason = WT_FFA_SP_EXIT_NONE;
    int ret;

    chain[0] = co;
    for (;;) {
        ret = run_one(chain[depth - 1u], out, &reason);
        if ((ret == 0) && (reason == WT_FFA_SP_EXIT_CALL)) {
            if ((depth == WT_CO_MAX) || (g_ffa_call_target == NULL)) {
                wt_platform_panic();
            }
            chain[depth] = g_ffa_call_target;
            depth++;
            continue;
        }
        if (depth == 1u) {
            return ret;
        }
        depth--;
        caller = chain[depth - 1u];
        g_sp_msg[caller->id - 1u].calling = 0u;
        if (ret != 0) {
            for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
                out[i] = 0u;
            }
            out[0] = WT_FFA_ERROR;
            out[2] = (uint64_t)(uint32_t)ret;
        }
        count = wt_ffa_msg_reg_count(out[0]);
        for (i = 0u; i < count; i++) {
            sp_arch(caller)->frame.x[i] = out[i];
        }
    }
}

static int endpoint_waiting(const struct wt_co* co)
{
    const wt_sp_msg_t* m = &g_sp_msg[co->id - 1u];

    return ((wt_co_state((wt_co_t*)co) == WT_CO_BLOCKED) && (m->busy == 0u) &&
            (m->yielded == 0u) && (m->calling == 0u)) ? 1 : 0;
}

static void endpoint_load_request(struct wt_co* co, const uint64_t* req)
{
    wt_sp_arch_t* a = sp_arch(co);
    wt_sp_msg_t* m = &g_sp_msg[co->id - 1u];
    unsigned int count = wt_ffa_msg_reg_count(req[0]);
    unsigned int i;

    for (i = 0u; i < count; i++) {
        a->frame.x[i] = req[i];
    }
    wt_ffa_regs_normalize(a->frame.x);
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
    if ((caller == NULL) || (target == NULL) || (target == caller) ||
        (target->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* Nothing runs the call chain for a partition still in its init pass. */
    if (wt_spm_sp_initializing(caller) != 0) {
        return WT_FFA_DENIED;
    }
    if (req != NULL) {
        if (req2_uuid_ok(target, req) == 0) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if (endpoint_waiting(target) == 0) {
            return WT_FFA_BUSY;
        }
        endpoint_load_request(target, req);
    }
    else {
        if (wt_spm_ffa_sp_yielded_to(target, wt_spm_sp_ffa_id(caller)) == 0) {
            return WT_FFA_DENIED;
        }
        g_sp_msg[target->id - 1u].yielded = 0u;
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
    if (req2_uuid_ok(co, req) == 0) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (endpoint_waiting(co) == 0) {
        return WT_FFA_BUSY;
    }
    endpoint_load_request(co, req);
    return run_endpoint(co, resp);
}

/* FFA_RUN: resume an endpoint that yielded, or give cycles to a waiting one
 * (it sees FFA_RUN as the return of its FFA_MSG_WAIT). */
int wt_spm_ffa_run(struct wt_co* co, uint16_t caller, uint64_t* out)
{
    wt_sp_arch_t* a;
    wt_sp_msg_t* m;
    unsigned int i;

    if ((co == NULL) || (out == NULL) || (co->unprivileged == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    m = &g_sp_msg[co->id - 1u];
    if (wt_co_state((wt_co_t*)co) != WT_CO_BLOCKED) {
        return WT_FFA_BUSY;
    }
    if (m->yielded != 0u) {
        if ((m->busy != 0u) && (m->requester != caller)) {
            return WT_FFA_DENIED;
        }
        m->yielded = 0u;
    }
    else if ((m->busy != 0u) || (m->calling != 0u)) {
        return WT_FFA_DENIED;
    }
    else {
        a = sp_arch(co);
        for (i = 0u; i < 8u; i++) {
            a->frame.x[i] = 0u;
        }
        a->frame.x[0] = WT_FFA_RUN;
        a->frame.x[1] = (uint64_t)wt_spm_sp_ffa_id(co) << 16;
    }
    return run_endpoint(co, out);
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
    (void)memset(&g_sp_msg[co->id - 1u], 0, sizeof(g_sp_msg[0]));
    (void)memset(&a->frame, 0, sizeof(a->frame));
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
 * coroutine, and the caller's translation table and thread id are all
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

    (void)memcpy(kernel_ctx, g_wt_sp_kernel_ctx, sizeof(kernel_ctx));
    if (domain != NULL) {
        wt_arch_program_sp_thread_domain(domain->regions, domain->region_count);
    }
    if (to->unprivileged != 0u) {
        write_tpidrro((uint64_t)to->id);
        wt_sp_el0_enter(&sp_arch(to)->frame);
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
