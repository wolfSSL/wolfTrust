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
#include "wolftrust/arch/aarch64/sysreg.h"

#define WT_SPM_TICK_PERIOD_MS 10u
#define WT_SPM_TICK_WAIT_MS 100u

volatile uint32_t g_wt_spm_tick_intid;

void wt_spm_fiq(void);
int wt_spm_prove_tick(void);

void wt_spm_fiq(void)
{
    uint32_t intid = wt_gic->ack_group0();

    if (intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_el3_timer_disable();
    }
    if (intid != WT_GIC_INTID_SPURIOUS) {
        g_wt_spm_tick_intid = intid;
        wt_gic->eoi_group0(intid);
    }
}

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
