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

/* S-EL1 Group 0 interrupt routing (DEN0077A Ch.9, Table 9.1): a Secure
 * interrupt a partition declared is queued (and its waiting owner signaled)
 * whether the FIQ is taken from an S-EL0 partition or at S-EL1 itself, and
 * the tick the boot proofs wait on is still recorded. */

#include "wolftrust/arch/aarch64/context.h"
#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/spm_svc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define OWNED_SPI   41u
#define STRAY_SPI   45u
#define CLAIMABLE_SPI 56u
#define NS_TEST_SPI 59u

uint64_t g_host_cntpct;
unsigned int g_host_fiq_masked;
volatile uint32_t g_wt_spm_sint_queued;
extern volatile uint32_t g_wt_spm_tick_intid;

void wt_spm_fiq(void);
void wt_spm_lower_fiq(wt_trap_frame_t* frame);

static int checks;
static int failures;
static int g_owner_token;
static uint32_t g_next_intid;
static uint32_t g_eoi;
static struct wt_co* g_queued_for;
static uint32_t g_queued_for_id;
static uint32_t g_queued_any;
static int g_signal_needed;
static int g_signal_asked;
static wt_trap_frame_t* g_preempted;

#define OWNER ((struct wt_co*)(void*)&g_owner_token)
static int g_other_token;
#define OTHER ((struct wt_co*)(void*)&g_other_token)

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

static void gic_none(void)
{
}

static void gic_id(uint32_t intid)
{
    (void)intid;
}

static void gic_prio(uint32_t intid, uint8_t priority)
{
    (void)intid;
    (void)priority;
}

static uint32_t gic_ack(void)
{
    return g_next_intid;
}

static void gic_eoi(uint32_t intid)
{
    g_eoi = intid;
}

static uint32_t gic_pmr(uint32_t pmr)
{
    return pmr;
}

static uint32_t g_pended;

static void gic_pend(uint32_t intid)
{
    g_pended = intid;
}

static const struct wt_gic_ops g_host_gic = {
    gic_none, gic_id, gic_id, gic_id, gic_prio, gic_ack, gic_eoi, gic_pend,
    gic_id, gic_pmr, 2u
};
const struct wt_gic_ops* const wt_gic = &g_host_gic;

void wt_el3_timer_arm_ms(uint32_t ms)
{
    (void)ms;
}

void wt_el3_timer_disable(void)
{
}

static struct wt_co* g_owned_by = OWNER;
static int g_partition_running;

struct wt_co* wt_spm_sint_owner(uint32_t intid)
{
    return (intid == OWNED_SPI) ? g_owned_by : NULL;
}

void wt_spm_sint_queue_for(struct wt_co* co, uint32_t intid)
{
    g_queued_for = co;
    g_queued_for_id = intid;
}

void wt_spm_sint_queue(uint32_t intid)
{
    g_queued_any = intid;
}

int wt_spm_sint_signal_needed(struct wt_co* owner)
{
    g_signal_asked = (owner == OWNER) ? 1 : 0;
    return g_signal_needed;
}

void wt_spm_preempt_from_fiq(wt_trap_frame_t* frame)
{
    g_preempted = frame;
}

void wt_spm_preempt_from_irq(wt_trap_frame_t* frame)
{
    (void)frame;
}

int wt_spm_current_is_partition(void)
{
    return g_partition_running;
}

int wt_spm_sint_declared_any(uint32_t intid)
{
    return ((intid == OWNED_SPI) || (intid == CLAIMABLE_SPI)) ? 1 : 0;
}

static void reset(uint32_t intid, int signal_needed)
{
    g_next_intid = intid;
    g_eoi = 0u;
    g_queued_for = NULL;
    g_queued_for_id = 0u;
    g_queued_any = 0u;
    g_signal_needed = signal_needed;
    g_signal_asked = 0;
    g_preempted = NULL;
    g_wt_spm_tick_intid = 0u;
}

/* Two different interrupts queued for one partition before it next waits are
 * both delivered, oldest first; neither overwrites the other (9.2.1). */
static void fifo_rows(void)
{
    wt_spm_sint_fifo_t q;
    uint32_t i;
    int ok = 1;

    memset(&q, 0, sizeof(q));
    check(wt_spm_sint_fifo_pop(&q) == 0u, "an empty queue delivers nothing");
    check(wt_spm_sint_fifo_push(&q, OWNED_SPI) == 0 &&
              wt_spm_sint_fifo_push(&q, STRAY_SPI) == 0,
          "two different interrupts queue for one partition");
    check(wt_spm_sint_fifo_pop(&q) == OWNED_SPI &&
              wt_spm_sint_fifo_pop(&q) == STRAY_SPI &&
              wt_spm_sint_fifo_pop(&q) == 0u,
          "both are delivered, oldest first, and the queue drains");
    check(wt_spm_sint_fifo_push(&q, OWNED_SPI) == 0 &&
              wt_spm_sint_fifo_push(&q, OWNED_SPI) == 0 &&
              wt_spm_sint_fifo_pop(&q) == OWNED_SPI &&
              wt_spm_sint_fifo_pop(&q) == 0u,
          "an id already queued is delivered once, as one GIC pending state");
    check(wt_spm_sint_fifo_push(&q, 0u) == -1 && q.count == 0u,
          "id 0 is never queued, as it reads as none");
    for (i = 0u; i < WT_SPM_SINT_QUEUE_MAX; i++) {
        ok = ok && (wt_spm_sint_fifo_push(&q, 32u + i) == 0);
    }
    check(ok != 0 && wt_spm_sint_fifo_push(&q, 100u) == -1 &&
              wt_spm_sint_fifo_pop(&q) == 32u,
          "a full queue refuses another id and keeps what it holds");
}

/* The ACS test partitions' para-virtual interrupt controls: a partition may
 * claim only an interrupt the platform declares for it, and the test timer
 * raises only an interrupt its caller owns (the Normal world: only an SPI no
 * partition owns or may claim). */
static void authorization_rows(void)
{
    wt_ffa_native_sp_t sp;

    memset(&sp, 0, sizeof(sp));
    sp.intids[0] = CLAIMABLE_SPI;
    sp.intid_count = 1u;
    check(wt_spm_native_declares(&sp, CLAIMABLE_SPI) == 1,
          "a partition may claim the interrupt its platform declares");
    check(wt_spm_native_declares(&sp, STRAY_SPI) == 0 &&
              wt_spm_native_declares(NULL, CLAIMABLE_SPI) == 0,
          "but no other, and nothing without a declaration");
    sp.intid_count = WT_FFA_NATIVE_SP_INTIDS + 1u;
    check(wt_spm_native_declares(&sp, CLAIMABLE_SPI) == 0,
          "a declaration past its bound declares nothing");

    check(wt_spm_twdog_arm(OWNER, OWNED_SPI, 1u) == 0,
          "the owner arms the timer for its own interrupt");
    wt_spm_twdog_stop(OWNER);
    check(wt_spm_twdog_arm(OTHER, OWNED_SPI, 1u) == -1,
          "another partition cannot raise that interrupt");
    check(wt_spm_twdog_arm(OWNER, STRAY_SPI, 1u) == -1,
          "nor can the owner raise an interrupt it does not own");
    check(wt_spm_twdog_arm(NULL, OWNED_SPI, 1u) == -1 &&
              wt_spm_twdog_arm(NULL, CLAIMABLE_SPI, 1u) == -1,
          "the Normal world cannot raise a partition's interrupt, claimed or not");
    check(wt_spm_twdog_arm(NULL, WT_GIC_INTID_SECURE_TIMER, 1u) == -1,
          "nor a private interrupt");
    check(wt_spm_twdog_arm(NULL, NS_TEST_SPI, 1u) == 0,
          "the Normal world arms its own test interrupt");
    wt_spm_twdog_stop(NULL);
}

/* A partition's timer stays bound to the partition that armed it: it is never
 * raised once another partition owns its interrupt, nor once none does, and
 * only its arming owner can stop it. */
static void timer_owner_rows(void)
{
    g_owned_by = OWNER;
    g_host_cntpct = 1000u;
    check(wt_spm_twdog_arm(OWNER, OWNED_SPI, 5u) == 0,
          "the owner arms a timer for its interrupt");
    g_owned_by = OTHER;
    g_host_cntpct = 2000u;
    g_pended = 0u;
    wt_spm_twdog_tick();
    check(g_pended == 0u,
          "once another partition owns the interrupt the expired timer does "
          "not raise it for that partition");

    g_owned_by = OWNER;
    g_host_cntpct = 1000u;
    check(wt_spm_twdog_arm(OWNER, OWNED_SPI, 5u) == 0, "the owner re-arms it");
    g_owned_by = NULL;
    g_partition_running = 1;
    g_host_cntpct = 1001u;
    g_pended = 0u;
    wt_spm_twdog_tick();
    check(g_pended == 0u,
          "a released interrupt's timer is not taken for the Normal world's");
    g_partition_running = 0;

    g_owned_by = OWNER;
    g_host_cntpct = 1000u;
    check(wt_spm_twdog_arm(OWNER, OWNED_SPI, 5u) == 0, "the owner arms it again");
    wt_spm_twdog_stop(OTHER);
    g_host_cntpct = 2000u;
    g_pended = 0u;
    wt_spm_twdog_tick();
    check(g_pended == OWNED_SPI,
          "another partition cannot stop it, and it fires for its owner at "
          "its deadline");
}

/* A Normal-world timer waits for its deadline and for a partition to run. */
static void ns_timer_rows(void)
{
    g_host_cntpct = 1000u;
    check(wt_spm_twdog_arm(NULL, NS_TEST_SPI, 5u) == 0,
          "the Normal world arms its test interrupt for 5 ms");
    g_partition_running = 1;
    g_host_cntpct = 1003u;
    g_pended = 0u;
    wt_spm_twdog_tick();
    check(g_pended == 0u,
          "a partition running before the deadline is not interrupted yet");
    g_partition_running = 0;
    g_host_cntpct = 1010u;
    wt_spm_twdog_tick();
    check(g_pended == 0u,
          "past the deadline it still waits for a partition to run");
    g_partition_running = 1;
    wt_spm_twdog_tick();
    check(g_pended == NS_TEST_SPI,
          "and is raised on the first tick past it that lands on a partition");
    g_partition_running = 0;
}

int main(void)
{
    wt_trap_frame_t frame;

    printf("spm_irq: Secure interrupt routing at S-EL1\n");
    memset(&frame, 0, sizeof(frame));

    reset(OWNED_SPI, 1);
    wt_spm_lower_fiq(&frame);
    check(g_queued_for == OWNER && g_queued_for_id == OWNED_SPI &&
              g_signal_asked == 1 && g_preempted == &frame &&
              g_eoi == OWNED_SPI,
          "from S-EL0 a declared interrupt is queued for its owner and the "
          "running partition preempted to signal it");

    reset(OWNED_SPI, 1);
    wt_spm_fiq();
    check(g_queued_for == OWNER && g_queued_for_id == OWNED_SPI &&
              g_signal_asked == 1 && g_eoi == OWNED_SPI,
          "at S-EL1 a declared interrupt is queued and its waiting owner "
          "signaled too, never dropped");
    check(g_preempted == NULL,
          "with no partition running at S-EL1 nothing is preempted");
    check(g_wt_spm_tick_intid == OWNED_SPI,
          "the id taken is still recorded for the boot proofs");

    reset(STRAY_SPI, 0);
    wt_spm_fiq();
    check(g_queued_any == STRAY_SPI && g_queued_for == NULL,
          "an undeclared interrupt takes the same queue path as from S-EL0");

    reset(WT_GIC_INTID_SECURE_TIMER, 0);
    wt_spm_fiq();
    check(g_wt_spm_tick_intid == WT_GIC_INTID_SECURE_TIMER &&
              g_eoi == WT_GIC_INTID_SECURE_TIMER && g_queued_any == 0u &&
              g_queued_for == NULL,
          "the secure tick at S-EL1 is recorded for the tick proof, not routed");

    reset(WT_GIC_INTID_SPURIOUS, 0);
    wt_spm_fiq();
    check(g_wt_spm_tick_intid == 0u && g_eoi == 0u && g_queued_any == 0u,
          "a spurious acknowledge is neither ended nor routed");

    reset(OWNED_SPI, 0);
    check(wt_spm_ns_sint_take() == OWNED_SPI && g_eoi == OWNED_SPI &&
              g_queued_for == NULL && g_queued_any == 0u,
          "the SPMC acknowledges and ends the interrupt that preempted the "
          "Normal world itself, leaving the routing to its caller");
    reset(WT_GIC_INTID_SPURIOUS, 0);
    check(wt_spm_ns_sint_take() == WT_GIC_INTID_SPURIOUS && g_eoi == 0u,
          "with nothing pending it reports spurious and ends nothing");

    fifo_rows();
    authorization_rows();
    timer_owner_rows();
    ns_timer_rows();

    printf("spm_irq: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
