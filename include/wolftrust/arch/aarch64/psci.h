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
 * FF-A range so the SPMD routes by id. wolfTrust serves the subset a
 * single-core Normal-world guest needs (WT-FFM-0067). */
#define WT_PSCI_FID32_FIRST     0x84000000u
#define WT_PSCI_FID32_LAST      0x8400001Fu
#define WT_PSCI_FID64_FIRST     0xC4000000u
#define WT_PSCI_FID64_LAST      0xC400001Fu

#define WT_PSCI_VERSION         0x84000000u
#define WT_PSCI_CPU_OFF         0x84000002u
#define WT_PSCI_CPU_ON32        0x84000003u
#define WT_PSCI_CPU_ON64        0xC4000003u
#define WT_PSCI_AFFINITY_INFO32 0x84000004u
#define WT_PSCI_AFFINITY_INFO64 0xC4000004u
#define WT_PSCI_MIGRATE_INFO_TYPE 0x84000006u
#define WT_PSCI_SYSTEM_OFF      0x84000008u
#define WT_PSCI_SYSTEM_RESET    0x84000009u
#define WT_PSCI_FEATURES        0x8400000Au

/* PSCI 1.1 (major 1, minor 1). */
#define WT_PSCI_VERSION_1_1     0x00010001u

/* Return codes (5.2.2). */
#define WT_PSCI_SUCCESS          0
#define WT_PSCI_NOT_SUPPORTED    (-1)
#define WT_PSCI_INVALID_PARAMS   (-2)
#define WT_PSCI_DENIED           (-3)

/* AFFINITY_INFO states: the running core is ON. */
#define WT_PSCI_AFFINITY_ON      0

static inline int wt_psci_fid_in_range(uint32_t fid)
{
    return ((fid >= WT_PSCI_FID32_FIRST) && (fid <= WT_PSCI_FID32_LAST)) ||
           ((fid >= WT_PSCI_FID64_FIRST) && (fid <= WT_PSCI_FID64_LAST));
}

struct wt_ffa_regs;
/* EL3 handling of a PSCI call taken at the NS physical instance; fills r with
 * the reply, or ends the run for SYSTEM_OFF/SYSTEM_RESET. */
void wt_psci_ns_call(struct wt_ffa_regs* r);

#endif /* WOLFTRUST_ARCH_AARCH64_PSCI_H */
