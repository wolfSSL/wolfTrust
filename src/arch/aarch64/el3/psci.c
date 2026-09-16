/* psci.c
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

/* PSCI (DEN0022) at the NS physical instance: the subset a single-core
 * Normal-world guest needs (WT-FFM-0067). Power-off and reset end the run
 * through the monitor; a PSCI reply is a single value in x0. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/psci.h"

extern void wt_el3_warm_reset(void) __attribute__((noreturn));

/* Boot counter in the .noinit band: 0 on the cold boot, 1 after the one warm
 * reset, so the first SYSTEM_RESET re-enters the chain and the second ends the
 * run instead of looping. */
static uint32_t g_reset_count __attribute__((section(".noinit")));

static void psci_return(wt_ffa_regs_t* r, uint64_t x0)
{
    unsigned int i;

    for (i = 1u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = x0;
}

static int psci_implements(uint32_t fid)
{
    switch (fid) {
        case WT_PSCI_VERSION:
        case WT_PSCI_CPU_ON32:
        case WT_PSCI_CPU_ON64:
        case WT_PSCI_AFFINITY_INFO32:
        case WT_PSCI_AFFINITY_INFO64:
        case WT_PSCI_SYSTEM_OFF:
        case WT_PSCI_SYSTEM_RESET:
        case WT_PSCI_FEATURES:
            return 1;
        default:
            return 0;
    }
}

void wt_psci_ns_call(wt_ffa_regs_t* r)
{
    uint32_t fid = (uint32_t)r->x[0];

    switch (fid) {
        case WT_PSCI_VERSION:
            psci_return(r, (uint64_t)WT_PSCI_VERSION_1_1);
            break;
        case WT_PSCI_FEATURES:
            psci_return(r, psci_implements((uint32_t)r->x[1]) ?
                              (uint64_t)(uint32_t)WT_PSCI_SUCCESS :
                              (uint64_t)(uint32_t)WT_PSCI_NOT_SUPPORTED);
            break;
        case WT_PSCI_AFFINITY_INFO32:
        case WT_PSCI_AFFINITY_INFO64:
            psci_return(r, (uint64_t)WT_PSCI_AFFINITY_ON);
            break;
        case WT_PSCI_CPU_ON32:
        case WT_PSCI_CPU_ON64:
            /* Single-core Normal world: the secondaries stay parked at EL3. */
            psci_return(r, (uint64_t)(uint32_t)WT_PSCI_DENIED);
            break;
        case WT_PSCI_SYSTEM_OFF:
            wt_el3_puts("[EL3] psci system_off\r\n");
            wt_platform_console_flush();
            (void)wt_el3_monitor_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
            break;
        case WT_PSCI_SYSTEM_RESET:
            if (g_reset_count == 0u) {
                g_reset_count = 1u;
                wt_el3_puts("[EL3] psci system_reset reboot\r\n");
                wt_platform_console_flush();
                wt_el3_warm_reset();
            }
            wt_el3_puts("[EL3] psci system_reset done\r\n");
            wt_platform_console_flush();
            (void)wt_el3_monitor_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
            break;
        default:
            psci_return(r, (uint64_t)(uint32_t)WT_PSCI_NOT_SUPPORTED);
            break;
    }
}
