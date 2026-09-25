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
 * world's machine view (4.4) is the boot core alone, where the uniprocessor
 * SPMC is resident: the secondaries the monitor keeps parked are not part of
 * it, so no target_cpu but the boot core is a valid MPIDR, and the boot core
 * cannot be turned off. A PSCI reply is a single value in x0. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/psci.h"
#include "wolftrust/arch/aarch64/sysreg.h"

/* target_cpu affinity fields (5.1.4): Aff3 and Aff2-Aff0; the rest MBZ. */
#define WT_PSCI_AFF_MASK64 0x000000FF00FFFFFFull
#define WT_PSCI_AFF_MASK32 0x0000000000FFFFFFull

#define WT_PSCI_TARGET_BOOT      0
#define WT_PSCI_TARGET_INVALID (-1)

/* A port whose reset hook returns has no machine reset. */
#define WT_EL3_PANIC_NO_RESET 0xB5u

/* Boot counter in the .noinit band, 0 on the first power-on. Emulator test
 * builds bound their resets with WT_EL3_RESET_LIMIT so a run ends instead of
 * looping; production builds leave it unset and every reset proceeds. */
static uint32_t g_reset_count __attribute__((section(".noinit")));

/* DEN0022 5.11: SYSTEM_RESET is a cold reset of the machine, so only an
 * emulated one, whose runner stands in for the power cycle, may end instead. */
#if defined(WT_EL3_RESET_LIMIT) && (WT_EL3_RESET_LIMIT > 0) && \
    (!defined(WT_PORT_EMULATED) || (WT_PORT_EMULATED != 1))
#error "WT_EL3_RESET_LIMIT ends the run on a reset: emulated targets only"
#endif

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
    /* DEN0022 5.11: a cold reset of the caller's machine, never a warm
     * re-entry of the firmware; the port's hook does not return. */
    wt_platform_board_system_reset();
    (void)wt_el3_monitor_call(WT_MON_FID_PANIC, WT_EL3_PANIC_NO_RESET);
}

/* SMCCC 1.1 and later preserve x4-x17 across a call that returns only x0. */
static void psci_return(wt_ffa_regs_t* r, uint64_t x0)
{
    unsigned int i;

    for (i = 1u; i < 4u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = x0;
}

static int psci_is_smc64(uint32_t fid)
{
    return (fid & 0x40000000u) != 0u;
}

/* An int32 PSCI result (DEN0022 5.2.1) is W0 for SMC32; SMC64 returns it as a
 * 64-bit signed X0 (DEN0028 2.8, 5.1), so negative codes are sign-extended. */
static uint64_t psci_status(uint32_t fid, int64_t status)
{
    if (psci_is_smc64(fid)) {
        return (uint64_t)status;
    }
    return (uint64_t)(uint32_t)status;
}

/* Classify a target_cpu: the boot core, or an MPIDR outside the Normal
 * world's machine view (a parked secondary is one). */
static int psci_target(uint64_t target, uint32_t fid)
{
    uint64_t mask = psci_is_smc64(fid) ? WT_PSCI_AFF_MASK64 : WT_PSCI_AFF_MASK32;
    uint64_t self = wt_read_mpidr_el1() & mask;

    if (!psci_is_smc64(fid)) {
        target &= 0xFFFFFFFFull;
    }
    /* Only self is masked: a target with an MBZ bit (5.1.4) never equals it. */
    if (target == self) {
        return WT_PSCI_TARGET_BOOT;
    }
    return WT_PSCI_TARGET_INVALID;
}

/* The only core in the machine view is on, so no OFF-to-ON path exists. */
static int64_t psci_cpu_on(uint64_t target, uint32_t fid)
{
    if (psci_target(target, fid) == WT_PSCI_TARGET_BOOT) {
        return WT_PSCI_ALREADY_ON;
    }
    return WT_PSCI_INVALID_PARAMS;
}

/* The resident SPMC is not migrate capable (5.9.1), and a target outside the
 * machine view is an invalid MPIDR (5.8.2). */
static int64_t psci_migrate(uint64_t target, uint32_t fid)
{
    if (psci_target(target, fid) == WT_PSCI_TARGET_BOOT) {
        return WT_PSCI_DENIED;
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
        case WT_SMCCC_VERSION:
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
            psci_return(r, psci_status(fid, psci_cpu_suspend(r->x[1])));
            break;
        case WT_PSCI_CPU_OFF:
            /* The uniprocessor SPMC is resident on the only running core. */
            psci_return(r, (uint64_t)(uint32_t)WT_PSCI_DENIED);
            break;
        case WT_PSCI_CPU_ON32:
        case WT_PSCI_CPU_ON64:
            psci_return(r, psci_status(fid, psci_cpu_on(r->x[1], fid)));
            break;
        case WT_PSCI_AFFINITY_INFO32:
        case WT_PSCI_AFFINITY_INFO64:
            psci_return(r, psci_status(fid, psci_affinity_info(r->x[1],
                                                               r->x[2], fid)));
            break;
        case WT_PSCI_MIGRATE32:
        case WT_PSCI_MIGRATE64:
            psci_return(r, psci_status(fid, psci_migrate(r->x[1], fid)));
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
            /* SMCCC 5.2: the unknown-function result is -1 sign-extended. */
            psci_return(r, (uint64_t)(int64_t)WT_PSCI_NOT_SUPPORTED);
            break;
    }
}
