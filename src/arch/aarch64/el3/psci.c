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

/* PSCI 1.1 (DEN0022) at the NS physical instance (WT-FFM-0067). The Normal
 * world runs on the boot core only, where the uniprocessor SPMC is resident:
 * the parked secondaries report DISABLED and cannot be turned on, and the boot
 * core cannot be turned off. A PSCI reply is a single value in x0. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/psci.h"
#include "wolftrust/arch/aarch64/sysreg.h"

#ifndef WT_PORT_BOOT_CPUS
#define WT_PORT_BOOT_CPUS 1u
#endif

/* target_cpu affinity fields (5.1.4): Aff3 and Aff2-Aff0; the rest MBZ. */
#define WT_PSCI_AFF_MASK64 0x000000FF00FFFFFFull
#define WT_PSCI_AFF_MASK32 0x0000000000FFFFFFull

#define WT_PSCI_TARGET_BOOT      0
#define WT_PSCI_TARGET_PARKED    1
#define WT_PSCI_TARGET_INVALID (-1)

extern void wt_el3_warm_reset(void) __attribute__((noreturn));

/* Boot counter in the .noinit band, 0 on the cold boot. An emulator target
 * without a reset controller bounds its chain re-entries with
 * WT_EL3_RESET_LIMIT so a test run ends instead of looping; production
 * builds leave it unset and every reset proceeds. */
static uint32_t g_reset_count __attribute__((section(".noinit")));

unsigned int wt_el3_reset_count(void)
{
    return g_reset_count;
}

void wt_el3_system_reset(const char* tag)
{
#if defined(WT_EL3_RESET_LIMIT) && (WT_EL3_RESET_LIMIT > 0)
    if (g_reset_count >= (uint32_t)WT_EL3_RESET_LIMIT) {
        wt_el3_puts("[EL3] ");
        wt_el3_puts(tag);
        wt_el3_puts(" system_reset done\r\n");
        wt_platform_console_flush();
        (void)wt_el3_monitor_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
    }
#endif
    g_reset_count++;
    wt_el3_puts("[EL3] ");
    wt_el3_puts(tag);
    wt_el3_puts(" system_reset reboot\r\n");
    wt_platform_console_flush();
    wt_platform_board_system_reset();
    wt_el3_warm_reset();
}

static void psci_return(wt_ffa_regs_t* r, uint64_t x0)
{
    unsigned int i;

    for (i = 1u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = x0;
}

static int psci_is_smc64(uint32_t fid)
{
    return (fid & 0x40000000u) != 0u;
}

/* Classify a target_cpu: the boot core, a parked secondary in its cluster, or
 * an MPIDR this system does not have. */
static int psci_target(uint64_t target, uint32_t fid)
{
    uint64_t mask = psci_is_smc64(fid) ? WT_PSCI_AFF_MASK64 : WT_PSCI_AFF_MASK32;
    uint64_t self = wt_read_mpidr_el1() & mask;

    if (!psci_is_smc64(fid)) {
        target &= 0xFFFFFFFFull;
    }
    if ((target & ~mask) != 0u) {
        return WT_PSCI_TARGET_INVALID;
    }
    if (target == self) {
        return WT_PSCI_TARGET_BOOT;
    }
    if ((((target ^ self) & ~0xFFull) == 0u) &&
        ((target & 0xFFull) < (uint64_t)WT_PORT_BOOT_CPUS)) {
        return WT_PSCI_TARGET_PARKED;
    }
    return WT_PSCI_TARGET_INVALID;
}

static int64_t psci_cpu_on(uint64_t target, uint32_t fid)
{
    int kind = psci_target(target, fid);

    if (kind == WT_PSCI_TARGET_BOOT) {
        return WT_PSCI_ALREADY_ON;
    }
    if (kind == WT_PSCI_TARGET_PARKED) {
        return WT_PSCI_INTERNAL_FAILURE;
    }
    return WT_PSCI_INVALID_PARAMS;
}

static int64_t psci_affinity_info(uint64_t target, uint64_t level, uint32_t fid)
{
    int kind;

    /* From PSCI 1.0 only level 0 must be supported (5.7.1). */
    if ((uint32_t)level != 0u) {
        return WT_PSCI_INVALID_PARAMS;
    }
    kind = psci_target(target, fid);
    if (kind == WT_PSCI_TARGET_BOOT) {
        return WT_PSCI_AFFINITY_ON;
    }
    if (kind == WT_PSCI_TARGET_PARKED) {
        return WT_PSCI_DISABLED;
    }
    return WT_PSCI_INVALID_PARAMS;
}

/* Core standby is the only state offered; to the core it is a WFI (5.4.9). */
static int64_t psci_cpu_suspend(uint64_t power_state)
{
    if ((uint32_t)power_state != WT_PSCI_STATE_CORE_STANDBY) {
        return WT_PSCI_INVALID_PARAMS;
    }
    __asm__ volatile("dsb sy\n\twfi" ::: "memory");
    return WT_PSCI_SUCCESS;
}

static int psci_implements(uint32_t fid)
{
    switch (fid) {
        case WT_PSCI_VERSION:
        case WT_PSCI_CPU_SUSPEND32:
        case WT_PSCI_CPU_SUSPEND64:
        case WT_PSCI_CPU_OFF:
        case WT_PSCI_CPU_ON32:
        case WT_PSCI_CPU_ON64:
        case WT_PSCI_AFFINITY_INFO32:
        case WT_PSCI_AFFINITY_INFO64:
        case WT_PSCI_MIGRATE32:
        case WT_PSCI_MIGRATE64:
        case WT_PSCI_MIGRATE_INFO_TYPE:
        case WT_PSCI_MIGRATE_INFO_UP_CPU32:
        case WT_PSCI_MIGRATE_INFO_UP_CPU64:
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
            /* Every implemented function reports flags 0: CPU_SUSPEND uses the
             * original power_state format, platform-coordinated only. */
            psci_return(r, psci_implements((uint32_t)r->x[1]) ?
                              (uint64_t)(uint32_t)WT_PSCI_SUCCESS :
                              (uint64_t)(uint32_t)WT_PSCI_NOT_SUPPORTED);
            break;
        case WT_PSCI_CPU_SUSPEND32:
        case WT_PSCI_CPU_SUSPEND64:
            psci_return(r, (uint64_t)(uint32_t)psci_cpu_suspend(r->x[1]));
            break;
        case WT_PSCI_CPU_OFF:
            /* The uniprocessor SPMC is resident on the only running core. */
            psci_return(r, (uint64_t)(uint32_t)WT_PSCI_DENIED);
            break;
        case WT_PSCI_CPU_ON32:
        case WT_PSCI_CPU_ON64:
            psci_return(r, (uint64_t)(uint32_t)psci_cpu_on(r->x[1], fid));
            break;
        case WT_PSCI_AFFINITY_INFO32:
        case WT_PSCI_AFFINITY_INFO64:
            psci_return(r, (uint64_t)(uint32_t)psci_affinity_info(r->x[1],
                                                                  r->x[2], fid));
            break;
        case WT_PSCI_MIGRATE32:
        case WT_PSCI_MIGRATE64:
            psci_return(r, (uint64_t)(uint32_t)WT_PSCI_DENIED);
            break;
        case WT_PSCI_MIGRATE_INFO_TYPE:
            psci_return(r, (uint64_t)WT_PSCI_TOS_UP_NOT_MIGRATABLE);
            break;
        case WT_PSCI_MIGRATE_INFO_UP_CPU32:
        case WT_PSCI_MIGRATE_INFO_UP_CPU64:
            psci_return(r, wt_read_mpidr_el1() &
                               (psci_is_smc64(fid) ? WT_PSCI_AFF_MASK64 :
                                                     WT_PSCI_AFF_MASK32));
            break;
        case WT_PSCI_SYSTEM_OFF:
            wt_el3_puts("[EL3] psci system_off\r\n");
            wt_platform_console_flush();
            (void)wt_el3_monitor_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
            break;
        case WT_PSCI_SYSTEM_RESET:
            wt_el3_system_reset("psci");
            break;
        default:
            psci_return(r, (uint64_t)(uint32_t)WT_PSCI_NOT_SUPPORTED);
            break;
    }
}
