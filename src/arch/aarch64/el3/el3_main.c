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

/* EL3 boot core: bring up the board, account for the parked secondaries,
 * print the banner, and drop into the Secure EL1 entry. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/sysreg.h"

#ifndef WT_PORT_BOOT_CPUS
#define WT_PORT_BOOT_CPUS 1u
#endif
#define WT_EL3_PARK_WAIT_MS 200u

volatile uint8_t g_wt_el3_parked[WT_EL3_MAX_CPUS];
volatile uint32_t g_wt_el3_ready;

extern uint8_t __spm_stack_top[];

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
    uint64_t deadline;
    uint32_t mask;

    deadline = wt_read_cntpct_el0() +
               ((wt_read_cntfrq_el0() * WT_EL3_PARK_WAIT_MS) / 1000u);
    do {
        mask = parked_mask();
    } while ((mask != expected) && (wt_read_cntpct_el0() < deadline));
    return mask;
}

void wt_el3_main(void)
{
    uint32_t mask;

    wt_platform_board_init();
    mask = wait_for_secondaries();

    wt_el3_puts("[EL3] wolfTrust monitor cntfrq=");
    wt_el3_putdec(wt_read_cntfrq_el0());
    wt_el3_puts(" secondaries parked mask=0x");
    wt_el3_puthex(mask, 1u);
    wt_el3_puts("\r\n");

    wt_write_sctlr_el1(WT_SCTLR_EL1_RES1);
    wt_el3_enter_secure_el1(wt_spm_entry, (uintptr_t)__spm_stack_top);
}
