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

#include <stddef.h>

#define WT_SPM_TICK_PERIOD_MS 10u
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

/* Current-EL FIQ: the SPMC itself was running, so acknowledge and resume. */
void wt_spm_fiq(void)
{
    (void)ack_group0_tick();
}

/* Lower-EL FIQ: an S-EL0 partition was running. The scheduling tick preempts
 * it (an NS-Int, DEV-04) and the handler does not return here; any other
 * declared Secure interrupt is queued for the partition and delivered as
 * FFA_INTERRUPT on its next FFA_MSG_WAIT (Table 9.1). */
void wt_spm_lower_fiq(wt_trap_frame_t* frame)
{
    uint32_t intid = ack_group0_tick();

    if (intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_spm_preempt_from_fiq(frame);
    }
    else if (intid != WT_GIC_INTID_SPURIOUS) {
        wt_spm_sint_queue(intid);
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
/* Route the test Secure interrupt to a partition both ways (Table 9.1). First
 * signalled: raise it while the SPMC runs (proven by wt_spm_prove_sint) so it
 * is taken at S-EL1, then hand FFA_INTERRUPT to the waiting owner. Then queued:
 * raise it with S-EL1 FIQ masked so it stays pending until the owner runs at
 * S-EL0, where the lower-EL FIQ queues it and the gate delivers it on the
 * owner's next FFA_MSG_WAIT. */
void wt_spm_prove_sint_route(struct wt_co* co)
{
    if (co == NULL) {
        return;
    }
    if ((wt_spm_prove_sint() == WT_SPM_TEST_SPI) &&
        (wt_spm_ffa_signal_deliver(co, WT_SPM_TEST_SPI) == 0)) {
        wt_el3_puts("[SPM] sint signaled id=0x");
        wt_el3_puthex(WT_SPM_TEST_SPI, 2u);
        wt_el3_puts("\r\n");
    }
    g_wt_spm_sint_queued = 0u;
    wt_gic->set_group0(WT_SPM_TEST_SPI);
    wt_gic->set_priority(WT_SPM_TEST_SPI, 0x00u);
    wt_gic->enable(WT_SPM_TEST_SPI);
    wt_gic->set_pending(WT_SPM_TEST_SPI);
    (void)wt_spm_ffa_signal_deliver(co, WT_SPM_TEST_SPI);
    wt_gic->disable(WT_SPM_TEST_SPI);
    if (g_wt_spm_sint_queued == WT_SPM_TEST_SPI) {
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
