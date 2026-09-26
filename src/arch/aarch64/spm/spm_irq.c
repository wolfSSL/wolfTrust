/* spm_irq.c
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

/* S-EL1 Group 0 interrupt handling for the SPMC (DEN0077A Ch.9: every
 * interrupt reaches the SPMC while the Secure world runs). The secure timer
 * is the only source until the partitions arrive. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/sysreg.h"
#include "wolftrust/spm_transport.h"

#include <stddef.h>

#define WT_SPM_TICK_PERIOD_MS 10u
#define WT_SPM_TWDOG_PERIOD_MS 1u
#define WT_SPM_TICK_WAIT_MS 100u
/* A shared-peripheral interrupt id used only by the secure-interrupt tests. */
#define WT_SPM_TEST_SPI 40u

volatile uint32_t g_wt_spm_tick_intid;

void wt_spm_fiq(void);
void wt_spm_lower_fiq(wt_trap_frame_t* frame);
int wt_spm_prove_tick(void);
uint32_t wt_spm_prove_sint(void);

static uint32_t ack_group0_tick(void)
{
    uint32_t intid = wt_gic->ack_group0();

    if (intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_el3_timer_disable();
    }
    if (intid != WT_GIC_INTID_SPURIOUS) {
        g_wt_spm_tick_intid = intid;
        wt_gic->eoi_group0(intid);
    }
    return intid;
}

int wt_spm_sint_fifo_push(wt_spm_sint_fifo_t* q, uint32_t intid)
{
    uint32_t i;

    if ((q == NULL) || (intid == 0u)) {
        return -1;
    }
    for (i = 0u; i < q->count; i++) {
        if (q->intid[i] == intid) {
            return 0;
        }
    }
    if (q->count >= WT_SPM_SINT_QUEUE_MAX) {
        return -1;
    }
    q->intid[q->count] = intid;
    q->count++;
    return 0;
}

uint32_t wt_spm_sint_fifo_pop(wt_spm_sint_fifo_t* q)
{
    uint32_t intid;
    uint32_t i;

    if ((q == NULL) || (q->count == 0u)) {
        return 0u;
    }
    intid = q->intid[0];
    for (i = 1u; i < q->count; i++) {
        q->intid[i - 1u] = q->intid[i];
    }
    q->count--;
    q->intid[q->count] = 0u;
    return intid;
}

/* The Secure interrupt that preempted the Normal world: the SPMD hands it over
 * still pending, so the SPMC acknowledges it here. Returns its id, or
 * WT_GIC_INTID_SPURIOUS when none is pending. */
uint32_t wt_spm_ns_sint_take(void)
{
    return ack_group0_tick();
}

/* Lower-EL FIQ: an S-EL0 partition was running. The scheduling tick preempts
 * it (an NS-Int, DEV-04) and the handler does not return here; any other
 * declared Secure interrupt is queued for the partition and delivered as
 * FFA_INTERRUPT on its next FFA_MSG_WAIT (Table 9.1). */
/* A Group 0 interrupt other than the tick: a manifest-declared partition
 * interrupt becomes that partition's FF-M signal (consumed by psa_wait and
 * released by psa_eoi); the FF-A test SPI is queued for its waiting endpoint. */
static void wt_spm_declared_irq(uint32_t intid, wt_trap_frame_t* frame)
{
    struct wt_co* owner = wt_spm_sint_owner(intid);

    /* An interrupt a partition claimed through the para-virtual enable is
     * queued for that owner; an owner that is waiting is signaled, so the
     * partition that was running is preempted to let the SPMC do it. */
    if (owner != NULL) {
        wt_spm_sint_queue_for(owner, intid);
        if ((wt_spm_sint_signal_needed(owner) != 0) && (frame != NULL)) {
            wt_spm_preempt_from_fiq(frame);
        }
        return;
    }
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    if (intid != WT_SPM_TEST_SPI) {
        wt_spm_conf_irq(intid);
        return;
    }
#endif
    wt_spm_sint_queue(intid);
}

/* Current-EL FIQ: the SPMC itself was running (only the boot proofs unmask
 * FIQ at S-EL1), so acknowledge and resume; a declared interrupt still takes
 * the routing above, with no partition to preempt. */
void wt_spm_fiq(void)
{
    uint32_t intid = ack_group0_tick();

    if ((intid != WT_GIC_INTID_SECURE_TIMER) &&
        (intid != WT_GIC_INTID_SPURIOUS)) {
        wt_spm_declared_irq(intid, NULL);
    }
}

void wt_spm_lower_fiq(wt_trap_frame_t* frame)
{
    uint32_t intid = ack_group0_tick();

    if (intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_spm_twdog_tick();
        wt_spm_preempt_from_fiq(frame);
    }
    else if (intid != WT_GIC_INTID_SPURIOUS) {
        wt_spm_declared_irq(intid, frame);
    }
    else if (wt_gic->version == 3u) {
        /* GICv3 signals a Group 1 Non-secure interrupt as FIQ while the PE is
         * Secure; nothing Group 0 is pending, so it is the Normal world's. */
        wt_spm_preempt_from_irq(frame);
    }
}

/* A Normal-world Group 1 interrupt asserted while an S-EL0 partition ran:
 * hand the CPU back so the Normal world can take it (Ch.9). Nothing is
 * acknowledged here; the interrupt is not this world's. */
void wt_spm_lower_irq(wt_trap_frame_t* frame)
{
    wt_spm_preempt_from_irq(frame);
}

/* The test-timer service of the ACS platform layer, one slot per armed
 * interrupt on the shared secure timer, bound to whoever armed it. A
 * partition's expires at its deadline whatever runs, and the declared routing
 * above delivers it by the owner's state, as long as its arming partition
 * still owns the interrupt; a Normal-world one stands for a peripheral that
 * fires while a partition works, so it is made pending on the first tick at or
 * past its deadline that lands on a partition. */
#define WT_SPM_TWDOG_SLOTS 4u

static uint32_t g_twdog_intid[WT_SPM_TWDOG_SLOTS];
static uint64_t g_twdog_deadline[WT_SPM_TWDOG_SLOTS];
/* The partition that armed each slot, NULL for the Normal world. */
static const struct wt_co* g_twdog_owner[WT_SPM_TWDOG_SLOTS];

int wt_spm_native_declares(const wt_ffa_native_sp_t* sp, uint32_t intid)
{
    uint32_t i;

    if ((sp == NULL) || (sp->intid_count > WT_FFA_NATIVE_SP_INTIDS)) {
        return 0;
    }
    for (i = 0u; i < sp->intid_count; i++) {
        if (sp->intids[i] == intid) {
            return 1;
        }
    }
    return 0;
}

/* A partition's timer raises only an interrupt it owns; the Normal world's
 * only an SPI no partition owns or may claim. */
static int twdog_arm_allowed(const struct wt_co* caller, uint32_t intid)
{
    if ((intid < 32u) || (intid >= WT_GIC_INTID_LIMIT)) {
        return 0;
    }
    if (caller != NULL) {
        return (wt_spm_sint_owner(intid) == caller) ? 1 : 0;
    }
    return ((wt_spm_sint_owner(intid) == NULL) &&
            (wt_spm_sint_declared_any(intid) == 0)) ? 1 : 0;
}

int wt_spm_twdog_arm(const struct wt_co* caller, uint32_t intid, uint32_t ms)
{
    unsigned int slot = WT_SPM_TWDOG_SLOTS;
    unsigned int i;

    if (twdog_arm_allowed(caller, intid) == 0) {
        return -1;
    }
    for (i = 0u; i < WT_SPM_TWDOG_SLOTS; i++) {
        if (g_twdog_intid[i] == intid) {
            slot = i;
        }
    }
    for (i = 0u; (i < WT_SPM_TWDOG_SLOTS) && (slot == WT_SPM_TWDOG_SLOTS); i++) {
        if (g_twdog_intid[i] == 0u) {
            slot = i;
        }
    }
    if ((intid == 0u) || (intid >= WT_GIC_INTID_LIMIT) ||
        (slot == WT_SPM_TWDOG_SLOTS)) {
        return -1;
    }
    g_twdog_deadline[slot] = wt_read_cntpct_el0() +
                             ((wt_read_cntfrq_el0() * (uint64_t)ms) / 1000u);
    g_twdog_intid[slot] = intid;
    g_twdog_owner[slot] = caller;
    wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
    wt_el3_timer_arm_ms(WT_SPM_TWDOG_PERIOD_MS);
    return 0;
}

/* Stop the timers the caller armed: a partition's, or with no owner the
 * Normal world's. */
void wt_spm_twdog_stop(const struct wt_co* owner)
{
    unsigned int i;

    for (i = 0u; i < WT_SPM_TWDOG_SLOTS; i++) {
        if ((g_twdog_intid[i] != 0u) && (g_twdog_owner[i] == owner)) {
            g_twdog_intid[i] = 0u;
        }
    }
}

void wt_spm_twdog_tick(void)
{
    uint64_t now = wt_read_cntpct_el0();
    unsigned int armed = 0u;
    unsigned int i;
    int due;

    for (i = 0u; i < WT_SPM_TWDOG_SLOTS; i++) {
        if (g_twdog_intid[i] != 0u) {
            if (g_twdog_owner[i] == NULL) {
                due = ((now >= g_twdog_deadline[i]) &&
                       (wt_spm_current_is_partition() != 0)) ? 1 : 0;
            }
            else if (wt_spm_sint_owner(g_twdog_intid[i]) != g_twdog_owner[i]) {
                /* Released or reclaimed since it was armed: never raised. */
                g_twdog_intid[i] = 0u;
                continue;
            }
            else {
                due = (now >= g_twdog_deadline[i]) ? 1 : 0;
            }
            if (due != 0) {
                wt_gic->set_pending(g_twdog_intid[i]);
                g_twdog_intid[i] = 0u;
            }
            else {
                armed = 1u;
            }
        }
    }
    if (armed != 0u) {
        wt_el3_timer_arm_ms(WT_SPM_TWDOG_PERIOD_MS);
    }
}

/* Arm the secure timer for a preemption tick with S-EL1 FIQ masked, so only
 * the running S-EL0 partition takes it (a current-EL tick would consume the
 * one-shot before the partition ever runs). */
void wt_spm_preempt_timer_arm(void)
{
    wt_daif_set_fiq();
    g_wt_spm_tick_intid = 0u;
    wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
    wt_el3_timer_arm_ms(WT_SPM_TICK_PERIOD_MS);
}

void wt_spm_preempt_timer_stop(void)
{
    wt_el3_timer_disable();
    wt_gic->disable(WT_GIC_INTID_SECURE_TIMER);
}

/* Raise a Secure shared-peripheral interrupt in software and confirm it
 * reaches the SPMC as a Group 0 FIQ, so the GIC path a manifest-declared
 * Secure interrupt uses is proven before it is routed to a partition.
 * Returns the received interrupt id, or 0 if it did not arrive. */
uint32_t wt_spm_prove_sint(void)
{
    uint64_t deadline = wt_read_cntpct_el0() +
                        ((wt_read_cntfrq_el0() * WT_SPM_TICK_WAIT_MS) / 1000u);

    g_wt_spm_tick_intid = 0u;
    wt_gic->set_group0(WT_SPM_TEST_SPI);
    wt_gic->set_priority(WT_SPM_TEST_SPI, 0x00u);
    wt_gic->enable(WT_SPM_TEST_SPI);
    wt_gic->set_pending(WT_SPM_TEST_SPI);
    wt_daif_clear_fiq();
    while ((g_wt_spm_tick_intid == 0u) && (wt_read_cntpct_el0() < deadline)) {
    }
    wt_daif_set_fiq();
    wt_gic->disable(WT_SPM_TEST_SPI);
    return (g_wt_spm_tick_intid == WT_SPM_TEST_SPI) ? WT_SPM_TEST_SPI : 0u;
}

#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
/* The monitor ABI is host-untranslatable, so the driver alone includes it. */
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/sched/coroutine.h"

/* A Normal-world interrupt: Group 1 with a Non-secure priority. */
#define WT_SPM_TEST_NS_SPI  41u
#define WT_SPM_TEST_NS_PRIO 0xA0u

static int test_ns_int_hold(void)
{
    if (wt_mon_call(WT_MON_FID_TEST_NS_GROUP, 1u) != 0u) {
        return -1;
    }
    wt_gic->set_priority(WT_SPM_TEST_NS_SPI, WT_SPM_TEST_NS_PRIO);
    wt_gic->enable(WT_SPM_TEST_NS_SPI);
    wt_gic->set_pending(WT_SPM_TEST_NS_SPI);
    return 0;
}

static void test_ns_int_release(void)
{
    wt_gic->disable(WT_SPM_TEST_NS_SPI);
    (void)wt_mon_call(WT_MON_FID_TEST_NS_GROUP, 0u);
}

/* Route the test Secure interrupt to a partition both ways (Table 9.1). First
 * signalled: raise it while the SPMC runs (proven by wt_spm_prove_sint) so it
 * is taken at S-EL1, then hand FFA_INTERRUPT to the waiting owner with a
 * Normal-world interrupt pending: the chain the SPMC scheduled keeps it queued
 * (9.2.4 rule 3), so the owner finishes and waits again. Then queued:
 * raise it with S-EL1 FIQ masked while the owner handles another interrupt (the
 * tick's id stands in), so the lower-EL FIQ queues it and the gate delivers it
 * on the owner's next FFA_MSG_WAIT; the get must then name it, not the tick. */
void wt_spm_prove_sint_route(struct wt_co* co)
{
    if (co == NULL) {
        return;
    }
    if ((wt_spm_prove_sint() == WT_SPM_TEST_SPI) &&
        (test_ns_int_hold() == 0) &&
        (wt_spm_ffa_signal_deliver(co, WT_SPM_TEST_SPI) == 0) &&
        (wt_co_state((const wt_co_t*)co) == WT_CO_BLOCKED)) {
        wt_el3_puts("[SPM] sint signaled id=0x");
        wt_el3_puthex(WT_SPM_TEST_SPI, 2u);
        wt_el3_puts("\r\n");
    }
    test_ns_int_release();
    g_wt_spm_sint_queued = 0u;
    wt_gic->set_group0(WT_SPM_TEST_SPI);
    wt_gic->set_priority(WT_SPM_TEST_SPI, 0x00u);
    wt_gic->enable(WT_SPM_TEST_SPI);
    wt_gic->set_pending(WT_SPM_TEST_SPI);
    (void)wt_spm_ffa_signal_deliver(co, WT_GIC_INTID_SECURE_TIMER);
    wt_gic->disable(WT_SPM_TEST_SPI);
    if ((g_wt_spm_sint_queued == WT_SPM_TEST_SPI) &&
        (wt_spm_sint_delivered(co) == WT_SPM_TEST_SPI)) {
        wt_el3_puts("[SPM] sint queued id=0x");
        wt_el3_puthex(WT_SPM_TEST_SPI, 2u);
        wt_el3_puts("\r\n");
    }
}
#endif

/* One secure timer period with FIQ unmasked at S-EL1: the tick must arrive
 * as INTID 29 through the S-EL1 vector table before the deadline. */
int wt_spm_prove_tick(void)
{
    uint64_t deadline = wt_read_cntpct_el0() +
                        ((wt_read_cntfrq_el0() * WT_SPM_TICK_WAIT_MS) / 1000u);

    g_wt_spm_tick_intid = 0u;
    wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
    wt_el3_timer_arm_ms(WT_SPM_TICK_PERIOD_MS);
    wt_daif_clear_fiq();
    while ((g_wt_spm_tick_intid == 0u) && (wt_read_cntpct_el0() < deadline)) {
    }
    wt_daif_set_fiq();
    wt_el3_timer_disable();
    wt_gic->disable(WT_GIC_INTID_SECURE_TIMER);
    return (g_wt_spm_tick_intid == WT_GIC_INTID_SECURE_TIMER) ? 1 : 0;
}
