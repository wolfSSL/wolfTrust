/* el3_main.c
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

/* EL3 boot core: bring up the board and the GIC, account for the parked
 * secondaries, prove the secure timer reaches EL3 as a Group 0 FIQ, print
 * the banner, and drop into the Secure EL1 entry. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/sysreg.h"

#ifndef WT_PORT_BOOT_CPUS
#define WT_PORT_BOOT_CPUS 1u
#endif
#define WT_EL3_PARK_WAIT_MS 200u
#define WT_EL3_TICK_PERIOD_MS 10u
#define WT_EL3_TICK_WAIT_MS 100u

volatile uint8_t g_wt_el3_parked[WT_EL3_MAX_CPUS];
volatile uint32_t g_wt_el3_ready;

extern uint8_t __spm_stack_top[];

static uint64_t deadline_after_ms(uint32_t ms)
{
    return wt_read_cntpct_el0() + ((wt_read_cntfrq_el0() * ms) / 1000u);
}

static uint32_t parked_mask(void)
{
    uint32_t mask = 0u;
    uint32_t i;

    for (i = 0u; i < WT_EL3_MAX_CPUS; i++) {
        if (g_wt_el3_parked[i] != 0u) {
            mask |= (1u << i);
        }
    }
    return mask;
}

static uint32_t wait_for_secondaries(void)
{
    uint32_t expected = (uint32_t)((1u << WT_PORT_BOOT_CPUS) - 2u);
    uint64_t deadline = deadline_after_ms(WT_EL3_PARK_WAIT_MS);
    uint32_t mask;

    do {
        mask = parked_mask();
    } while ((mask != expected) && (wt_read_cntpct_el0() < deadline));
    return mask;
}

/* One secure timer period with FIQ unmasked at EL3: the tick must arrive as
 * INTID 29 through the vector table before the deadline. */
static void prove_tick(void)
{
    uint64_t deadline = deadline_after_ms(WT_EL3_TICK_WAIT_MS);

    g_wt_el3_tick_intid = 0u;
    wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
    wt_el3_timer_arm_ms(WT_EL3_TICK_PERIOD_MS);
    wt_daif_clear_fiq();
    while ((g_wt_el3_tick_intid == 0u) && (wt_read_cntpct_el0() < deadline)) {
    }
    wt_daif_set_fiq();
    wt_el3_timer_disable();
    wt_gic->disable(WT_GIC_INTID_SECURE_TIMER);

    if (g_wt_el3_tick_intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_el3_puts("[EL3] tick ok intid=29\r\n");
    }
    else {
        wt_el3_puts("[EL3] tick TIMEOUT intid=");
        wt_el3_putdec(g_wt_el3_tick_intid);
        wt_el3_puts("\r\n");
    }
}

void wt_el3_main(void)
{
    uint32_t mask;

    wt_platform_board_init();
    wt_gic->init_secure();
    mask = wait_for_secondaries();

    wt_el3_puts("[EL3] wolfTrust monitor cntfrq=");
    wt_el3_putdec(wt_read_cntfrq_el0());
    wt_el3_puts(" gic=v");
    wt_el3_putdec(wt_gic->version);
    wt_el3_puts(" rdist_woken=");
    wt_el3_putdec(wt_gic_rdist_woken());
    wt_el3_puts(" secondaries parked mask=0x");
    wt_el3_puthex(mask, 1u);
    wt_el3_puts("\r\n");

    prove_tick();

    wt_write_sctlr_el1(WT_SCTLR_EL1_RES1);
    wt_el3_enter_secure_el1(wt_spm_entry, (uintptr_t)__spm_stack_top);
}
