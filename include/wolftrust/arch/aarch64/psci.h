/* psci.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_PSCI_H
#define WOLFTRUST_ARCH_AARCH64_PSCI_H

#include <stdint.h>

/* PSCI (Arm DEN0022) function ids: the SMCCC Standard Secure Service range
 * 0x84000000-0x8400001F (SMC32) and 0xC4000000-0xC400001F (SMC64), below the
 * FF-A range so the SPMD routes by id. The Normal world runs on the boot core
 * only, next to the uniprocessor SPMC (WT-FFM-0067). */
#define WT_PSCI_FID32_FIRST     0x84000000u
#define WT_PSCI_FID32_LAST      0x8400001Fu
#define WT_PSCI_FID64_FIRST     0xC4000000u
#define WT_PSCI_FID64_LAST      0xC400001Fu

#define WT_PSCI_VERSION         0x84000000u
#define WT_PSCI_CPU_SUSPEND32   0x84000001u
#define WT_PSCI_CPU_SUSPEND64   0xC4000001u
#define WT_PSCI_CPU_OFF         0x84000002u
#define WT_PSCI_CPU_ON32        0x84000003u
#define WT_PSCI_CPU_ON64        0xC4000003u
#define WT_PSCI_AFFINITY_INFO32 0x84000004u
#define WT_PSCI_AFFINITY_INFO64 0xC4000004u
#define WT_PSCI_MIGRATE32       0x84000005u
#define WT_PSCI_MIGRATE64       0xC4000005u
#define WT_PSCI_MIGRATE_INFO_TYPE 0x84000006u
#define WT_PSCI_MIGRATE_INFO_UP_CPU32 0x84000007u
#define WT_PSCI_MIGRATE_INFO_UP_CPU64 0xC4000007u
#define WT_PSCI_SYSTEM_OFF      0x84000008u
#define WT_PSCI_SYSTEM_RESET    0x84000009u
#define WT_PSCI_FEATURES        0x8400000Au
#define WT_PSCI_CPU_FREEZE      0x8400000Bu
#define WT_PSCI_SYSTEM_SUSPEND64 0xC400000Eu

/* PSCI 1.1 (major 1, minor 1). */
#define WT_PSCI_VERSION_1_1     0x00010001u

/* Return codes (5.2.2). */
#define WT_PSCI_SUCCESS          0
#define WT_PSCI_NOT_SUPPORTED    (-1)
#define WT_PSCI_INVALID_PARAMS   (-2)
#define WT_PSCI_DENIED           (-3)
#define WT_PSCI_ALREADY_ON       (-4)
#define WT_PSCI_INTERNAL_FAILURE (-6)
#define WT_PSCI_DISABLED         (-8)

/* AFFINITY_INFO states: the running core is ON. */
#define WT_PSCI_AFFINITY_ON      0

/* MIGRATE_INFO_TYPE 1: a uniprocessor Trusted OS that cannot migrate. */
#define WT_PSCI_TOS_UP_NOT_MIGRATABLE 1u

/* The one power_state offered (original format): core standby, StateID 0. */
#define WT_PSCI_STATE_CORE_STANDBY 0u

/* SMCCC Arm Architecture Calls served beside PSCI (DEN0028 7.2, 7.3). */
#define WT_SMCCC_VERSION        0x80000000u
#define WT_SMCCC_ARCH_FEATURES  0x80000001u
#define WT_SMCCC_VERSION_1_2    0x00010002u
#define WT_SMCCC_NOT_SUPPORTED  (-1)

static inline int wt_psci_fid_in_range(uint32_t fid)
{
    return ((fid >= WT_PSCI_FID32_FIRST) && (fid <= WT_PSCI_FID32_LAST)) ||
           ((fid >= WT_PSCI_FID64_FIRST) && (fid <= WT_PSCI_FID64_LAST));
}

struct wt_ffa_regs;
/* EL3 handling of a PSCI call taken at the NS physical instance; fills r with
 * the reply, or ends the run for SYSTEM_OFF/SYSTEM_RESET. */
void wt_psci_ns_call(struct wt_ffa_regs* r);

/* EL3 system reset shared by the NS PSCI SYSTEM_RESET and the Secure world's
 * WT_MON_FID_SYSTEM_RESET: the port resets the machine, and a port hook that
 * returns panics the monitor. tag names the requester. */
void wt_el3_system_reset(const char* tag);

#endif /* WOLFTRUST_ARCH_AARCH64_PSCI_H */
