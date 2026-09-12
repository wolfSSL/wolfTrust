/* mmu.S
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

/* void wt_mmu_enable(uint64_t ttbr0, uint64_t mair, uint64_t tcr): S-EL1
 * stage 1 on with M|C|I|SA|SA0|WXN; nTWI/nTWE cleared so EL0 wfi/wfe trap. */

#define SCTLR_M     (1 << 0)
#define SCTLR_C     (1 << 2)
#define SCTLR_SA    (1 << 3)
#define SCTLR_SA0   (1 << 4)
#define SCTLR_I     (1 << 12)
#define SCTLR_NTWI  (1 << 16)
#define SCTLR_NTWE  (1 << 18)
#define SCTLR_WXN   (1 << 19)

    .section .text.wt_mmu_enable, "ax"
    .globl wt_mmu_enable
wt_mmu_enable:
    msr     MAIR_EL1, x1
    msr     TCR_EL1, x2
    msr     TTBR0_EL1, x0
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    mrs     x3, SCTLR_EL1
    ldr     x4, =(SCTLR_M | SCTLR_C | SCTLR_SA | SCTLR_SA0 | SCTLR_I | SCTLR_WXN)
    orr     x3, x3, x4
    ldr     x4, =(SCTLR_NTWI | SCTLR_NTWE)
    bic     x3, x3, x4
    msr     SCTLR_EL1, x3
    isb
    ret

/* void wt_mmu_switch_ttbr0(uint64_t ttbr0): distinct ASIDs, no TLBI. */
    .globl wt_mmu_switch_ttbr0
wt_mmu_switch_ttbr0:
    msr     TTBR0_EL1, x0
    isb
    ret
