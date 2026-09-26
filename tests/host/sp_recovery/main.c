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

/* WT-SYS-0008 / WT-FFM-0017: a restartable Secure Partition that faults is
 * recovered gracefully — locks dropped, pinned clients failed, domain scrubbed,
 * partition restarted under its budget — without resetting the platform. This
 * suite proves the architecture-neutral halves: the restart/escalate decision
 * and its ordered orchestration (wt_sp_recovery_*), and the in-place coroutine
 * restart primitive (wt_co_reinit) that reclaims the same slot. The real
 * fault-and-run recovery is proved on M33MU (target/spfaultneg). */

#include "wolftrust/sp_recovery.h"
#include "wolftrust/sched/coroutine.h"
#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/sync/mutex.h"

#include <stdio.h>
#include <stdint.h>

static unsigned int g_checks;
static unsigned int g_failures;

#define EXPECT_INT(actual, expected) \
    do { \
        long actual_value = (long)(actual); \
        long expected_value = (long)(expected); \
        g_checks++; \
        if (actual_value != expected_value) { \
            (void)fprintf(stderr, "line %d: expected %ld, received %ld\n", \
                          __LINE__, expected_value, actual_value); \
            g_failures++; \
        } \
    } while (0)

#define EXPECT_TRUE(cond) \
    do { \
        g_checks++; \
        if (!(cond)) { \
            (void)fprintf(stderr, "line %d: condition failed\n", __LINE__); \
            g_failures++; \
        } \
    } while (0)

/* ---- Host stubs for the coroutine arch backend -------------------------- */
/* wt_co_reinit's slot bookkeeping is architecture-neutral; only the register
 * frame setup is arch code. The stubs make that setup a no-op so the reuse and
 * state logic runs on the host. The real frame init runs on M33MU. */

struct wt_co *g_wt_co_pendsv_target;

void wt_co_arch_init_stack(struct wt_co *co, wt_co_entry_fn entry, void *arg)
{
    (void)co;
    (void)entry;
    (void)arg;
}

void wt_co_arch_enter(struct wt_co *to) { (void)to; }
void wt_co_arch_leave(void) {}
void wt_co_arch_request_preempt(void) {}

static int g_panicked;
void wt_platform_panic(void) { g_panicked = 1; }

/* ---- Part 1: the restart-vs-escalate decision --------------------------- */

static void test_decide(void)
{
    uint32_t count;
    uint32_t first;
    unsigned int i;

    /* DOMAIN within budget restarts and advances the counter each time; the
     * (limit+1)th fault in the window exhausts the budget and escalates,
     * leaving the counter untouched. This is the fault->restart->recover
     * state machine: three restarts, then fail closed. */
    count = 0U;
    first = 0U;
    for (i = 0U; i < 3U; i++) {
        EXPECT_INT(wt_sp_recovery_decide(WT_RESTART_ACTION_DOMAIN, 3U, 8000U,
                                         100U, &count, &first),
                   WT_SP_RECOVERY_RESTART);
    }
    EXPECT_INT(count, 3U);
    EXPECT_INT(wt_sp_recovery_decide(WT_RESTART_ACTION_DOMAIN, 3U, 8000U, 200U,
                                     &count, &first),
               WT_SP_RECOVERY_ESCALATE);
    EXPECT_INT(count, 3U);

    /* NEVER and PLATFORM escalate immediately and never spend budget. */
    count = 0U;
    first = 0U;
    EXPECT_INT(wt_sp_recovery_decide(WT_RESTART_ACTION_NEVER, 3U, 8000U, 100U,
                                     &count, &first),
               WT_SP_RECOVERY_ESCALATE);
    EXPECT_INT(count, 0U);
    EXPECT_INT(wt_sp_recovery_decide(WT_RESTART_ACTION_PLATFORM, 3U, 8000U,
                                     100U, &count, &first),
               WT_SP_RECOVERY_ESCALATE);
    EXPECT_INT(count, 0U);

    /* A zero restart_limit is unlimited restarts. */
    count = 0U;
    first = 0U;
    for (i = 0U; i < 100U; i++) {
        EXPECT_INT(wt_sp_recovery_decide(WT_RESTART_ACTION_DOMAIN, 0U, 8000U,
                                         100U, &count, &first),
                   WT_SP_RECOVERY_RESTART);
    }

    /* NULL counters fail closed. */
    EXPECT_INT(wt_sp_recovery_decide(WT_RESTART_ACTION_DOMAIN, 3U, 8000U, 100U,
                                     NULL, &first),
               WT_SP_RECOVERY_ESCALATE);

    (void)printf("PASS: WT-SYS-0008 restart budget decision\n");
}

/* ---- Part 2: the ordered recovery orchestration ------------------------- */

/* Records the sequence of hook calls so the order can be asserted. */
#define OP_RELEASE 1
#define OP_FAIL    2
#define OP_SCRUB   3
#define OP_RESTART 4
#define OP_ESCALATE 5

typedef struct recovery_probe {
    int seq[8];
    unsigned int seq_len;
    int restart_result;
    wt_restart_action_t escalate_action;
} recovery_probe_t;

static void probe_record(recovery_probe_t* p, int op)
{
    if (p->seq_len < (sizeof(p->seq) / sizeof(p->seq[0]))) {
        p->seq[p->seq_len++] = op;
    }
}

static void probe_release(void* ctx) { probe_record(ctx, OP_RELEASE); }
static void probe_fail(void* ctx) { probe_record(ctx, OP_FAIL); }
static void probe_scrub(void* ctx) { probe_record(ctx, OP_SCRUB); }

static int probe_restart(void* ctx)
{
    recovery_probe_t* p = ctx;

    probe_record(p, OP_RESTART);
    return p->restart_result;
}

static void probe_escalate(void* ctx, wt_restart_action_t action)
{
    recovery_probe_t* p = ctx;

    probe_record(p, OP_ESCALATE);
    p->escalate_action = action;
}

static const wt_sp_recovery_ops_t g_probe_ops = {
    probe_release, probe_fail, probe_scrub, probe_restart, probe_escalate
};

static void test_run(void)
{
    recovery_probe_t p;
    uint32_t count;
    uint32_t first;

    /* Transient DOMAIN fault: release + fail happen first, then scrub + restart
     * in order; escalate is never called. */
    p = (recovery_probe_t){ 0 };
    count = 0U;
    first = 0U;
    EXPECT_INT(wt_sp_recovery_run(&g_probe_ops, &p, WT_RESTART_ACTION_DOMAIN,
                                  3U, 8000U, 100U, &count, &first),
               WT_SP_RECOVERY_RESTART);
    EXPECT_INT(p.seq_len, 4U);
    EXPECT_INT(p.seq[0], OP_RELEASE);
    EXPECT_INT(p.seq[1], OP_FAIL);
    EXPECT_INT(p.seq[2], OP_SCRUB);
    EXPECT_INT(p.seq[3], OP_RESTART);
    EXPECT_INT(count, 1U);

    /* Budget exhausted: release + fail still run so nothing hangs, then the
     * partition is quarantined via escalate — no scrub, no restart. */
    p = (recovery_probe_t){ 0 };
    count = 3U;
    first = 100U;
    EXPECT_INT(wt_sp_recovery_run(&g_probe_ops, &p, WT_RESTART_ACTION_DOMAIN,
                                  3U, 8000U, 200U, &count, &first),
               WT_SP_RECOVERY_ESCALATE);
    EXPECT_INT(p.seq_len, 3U);
    EXPECT_INT(p.seq[0], OP_RELEASE);
    EXPECT_INT(p.seq[1], OP_FAIL);
    EXPECT_INT(p.seq[2], OP_ESCALATE);
    EXPECT_INT(p.escalate_action, WT_RESTART_ACTION_DOMAIN);

    /* Platform-fatal service: escalate carries PLATFORM so the port can fail
     * the whole platform closed rather than quarantine one partition. */
    p = (recovery_probe_t){ 0 };
    count = 0U;
    first = 0U;
    EXPECT_INT(wt_sp_recovery_run(&g_probe_ops, &p, WT_RESTART_ACTION_PLATFORM,
                                  3U, 8000U, 100U, &count, &first),
               WT_SP_RECOVERY_ESCALATE);
    EXPECT_INT(p.seq[p.seq_len - 1U], OP_ESCALATE);
    EXPECT_INT(p.escalate_action, WT_RESTART_ACTION_PLATFORM);

    /* A restart that cannot re-arm the partition downgrades to escalate: the
     * decision was RESTART, restart ran and failed, so escalate fires. */
    p = (recovery_probe_t){ 0 };
    p.restart_result = -1;
    count = 0U;
    first = 0U;
    EXPECT_INT(wt_sp_recovery_run(&g_probe_ops, &p, WT_RESTART_ACTION_DOMAIN,
                                  3U, 8000U, 100U, &count, &first),
               WT_SP_RECOVERY_ESCALATE);
    EXPECT_INT(p.seq_len, 5U);
    EXPECT_INT(p.seq[3], OP_RESTART);
    EXPECT_INT(p.seq[4], OP_ESCALATE);

    /* No ops table fails closed. */
    EXPECT_INT(wt_sp_recovery_run(NULL, &p, WT_RESTART_ACTION_DOMAIN, 3U,
                                  8000U, 100U, &count, &first),
               WT_SP_RECOVERY_ESCALATE);

    (void)printf("PASS: WT-FFM-0017 graceful recovery orchestration\n");
}

/* ---- Part 3: in-place coroutine restart --------------------------------- */

#define TEST_CO_COUNT (WT_CO_MAX - 1u)  /* creatable slots (bootstrap is 0) */
#define TEST_STACK_WORDS (WT_CO_STACK_MIN / sizeof(uint64_t))

static uint64_t g_stacks[TEST_CO_COUNT + 1u][TEST_STACK_WORDS];

static void test_entry(void* arg) { (void)arg; }
static void test_entry_b(void* arg) { (void)arg; }

static void test_reinit(void)
{
    wt_co_t* co[TEST_CO_COUNT + 1u];
    struct wt_secure_domain* dom = (struct wt_secure_domain*)(uintptr_t)0x1000;
    unsigned int i;

    wt_co_init();

    /* Fill every creatable slot but one. */
    for (i = 0U; i < TEST_CO_COUNT - 1u; i++) {
        co[i] = wt_co_create_blocked_ex((uint8_t*)g_stacks[i],
                                        sizeof(g_stacks[i]), test_entry, NULL);
        EXPECT_TRUE(co[i] != NULL);
    }

    /* Give one coroutine an MPU domain, fault it, and restart it in place 50
     * times. Each restart reclaims the SAME slot (identity stable), leaves it
     * BLOCKED, and preserves the domain binding — none of this consumes a new
     * table slot. */
    wt_co_set_domain(co[0], dom, 1u);
    for (i = 0U; i < 50U; i++) {
        wt_co_mark_faulted(co[0]);
        EXPECT_INT(wt_co_state(co[0]), WT_CO_FAULTED);
        EXPECT_INT(wt_co_reinit(co[0], test_entry_b, NULL), 0);
        EXPECT_INT(wt_co_state(co[0]), WT_CO_BLOCKED);
    }
    EXPECT_TRUE(((const struct wt_co*)co[0])->domain == dom);
    EXPECT_INT(((const struct wt_co*)co[0])->unprivileged, 1);

    /* The 50 restarts consumed zero slots: exactly one free slot remains, so
     * one more create succeeds and the next fails on a full pool. */
    co[TEST_CO_COUNT - 1u] =
        wt_co_create_blocked_ex((uint8_t*)g_stacks[TEST_CO_COUNT - 1u],
                                sizeof(g_stacks[TEST_CO_COUNT - 1u]),
                                test_entry, NULL);
    EXPECT_TRUE(co[TEST_CO_COUNT - 1u] != NULL);
    EXPECT_TRUE(wt_co_create_blocked_ex((uint8_t*)g_stacks[TEST_CO_COUNT],
                                        sizeof(g_stacks[TEST_CO_COUNT]),
                                        test_entry, NULL) == NULL);

    /* Bad inputs are rejected without a panic. */
    EXPECT_INT(wt_co_reinit(NULL, test_entry, NULL), -1);
    EXPECT_INT(wt_co_reinit(co[0], NULL, NULL), -1);
    EXPECT_INT(wt_co_reinit(&g_wt_co_bootstrap, test_entry, NULL), -1);
    EXPECT_INT(g_panicked, 0);

    (void)printf("PASS: WT-SYS-0008 in-place coroutine restart\n");
}

/* A coroutine that faults while parked as a mutex waiter must be removed from
 * the wait queue so the mutex is never handed to a dead waiter (which would
 * deadlock every later acquirer behind a holder that can never release). */
static void test_mutex_faulted_waiter(void)
{
    wt_co_t *a, *b, *c;
    wt_mutex_t m;

    wt_co_init();
    a = wt_co_create_blocked_ex((uint8_t*)g_stacks[0], sizeof(g_stacks[0]),
                                test_entry, NULL);
    b = wt_co_create_blocked_ex((uint8_t*)g_stacks[1], sizeof(g_stacks[1]),
                                test_entry, NULL);
    c = wt_co_create_blocked_ex((uint8_t*)g_stacks[2], sizeof(g_stacks[2]),
                                test_entry, NULL);
    EXPECT_TRUE(a != NULL && b != NULL && c != NULL);

    /* A holds the mutex; B then C queue behind it. */
    wt_mutex_init(&m);
    EXPECT_INT(wt_mutex_acquire_queued(&m, a), 0);
    EXPECT_INT(wt_mutex_acquire_queued(&m, b), 1);
    EXPECT_INT(wt_mutex_acquire_queued(&m, b), 1);
    EXPECT_TRUE(m.wait_head == b && m.wait_tail == b &&
                b->next_wait == NULL);
    EXPECT_INT(wt_mutex_acquire_queued(&m, c), 1);
    EXPECT_TRUE(wt_mutex_holder(&m) == a);

    /* B faults as the head waiter; recovery unlinks it. */
    wt_co_mark_faulted(b);
    EXPECT_INT(wt_co_state(b), WT_CO_FAULTED);
    wt_mutex_remove_waiter(&m, b);

    /* Release must hand the mutex to the live waiter C, never the dead B. */
    wt_mutex_release_if_holder(&m, a);
    EXPECT_TRUE(wt_mutex_holder(&m) == c);
    EXPECT_TRUE(wt_mutex_holder(&m) != b);

    /* remove_waiter on a coroutine that is not queued is a no-op. */
    wt_co_init();
    a = wt_co_create_blocked_ex((uint8_t*)g_stacks[0], sizeof(g_stacks[0]),
                                test_entry, NULL);
    b = wt_co_create_blocked_ex((uint8_t*)g_stacks[1], sizeof(g_stacks[1]),
                                test_entry, NULL);
    c = wt_co_create_blocked_ex((uint8_t*)g_stacks[2], sizeof(g_stacks[2]),
                                test_entry, NULL);
    wt_mutex_init(&m);
    EXPECT_INT(wt_mutex_acquire_queued(&m, a), 0);
    EXPECT_INT(wt_mutex_acquire_queued(&m, b), 1);
    wt_mutex_remove_waiter(&m, c);
    wt_mutex_release_if_holder(&m, a);
    EXPECT_TRUE(wt_mutex_holder(&m) == b);
    EXPECT_TRUE(m.wait_head == NULL && m.wait_tail == NULL);
    EXPECT_INT(wt_mutex_acquire_queued(&m, b), 0);

    (void)printf("PASS: mutex waiter handoff and fault cleanup\n");
}

int main(void)
{
    test_decide();
    test_run();
    test_reinit();
    test_mutex_faulted_waiter();
    if (g_failures != 0U) {
        (void)fprintf(stderr, "SP recovery checks failed: %u/%u\n",
                      g_failures, g_checks);
        return 1;
    }
    (void)printf("PASS: SP recovery checks: %u\n", g_checks);
    return 0;
}
