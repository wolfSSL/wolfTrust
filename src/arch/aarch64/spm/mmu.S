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

/* void wt_mmu_switch_ttbr0(uint64_t ttbr0): distinct ASIDs, no TLBI; the DSB
 * publishes a table built just before its first use. */
    .globl wt_mmu_switch_ttbr0
wt_mmu_switch_ttbr0:
    dsb     ishst
    msr     TTBR0_EL1, x0
    isb
    ret

/* void wt_mmu_tlbi_asid(uint64_t asid): drop one domain's cached entries once
 * the caller's descriptor stores are visible to the walker. */
    .globl wt_mmu_tlbi_asid
wt_mmu_tlbi_asid:
    lsl     x0, x0, #48
    dsb     ishst
    tlbi    aside1is, x0
    dsb     ish
    isb
    ret

/* void wt_mmu_dcache_clean_inval(uint64_t va, uint64_t size): every data cache
 * line of the range, stepped by the smallest line CTR_EL0 reports, then a
 * full-system barrier so the memory itself holds what was written. */
    .globl wt_mmu_dcache_clean_inval
wt_mmu_dcache_clean_inval:
    cbz     x1, 2f
    mrs     x3, CTR_EL0
    ubfx    x3, x3, #16, #4
    mov     x2, #4
    lsl     x2, x2, x3
    add     x1, x0, x1
    sub     x3, x2, #1
    bic     x0, x0, x3
1:
    dc      civac, x0
    add     x0, x0, x2
    cmp     x0, x1
    b.lo    1b
2:
    dsb     sy
    ret

/* void wt_mmu_sync_icache(uint64_t va, uint64_t size): make instructions
 * written as data fetchable from the range: clean each data line to the point
 * of unification, DSB ISH, invalidate each instruction line, DSB ISH, ISB. */
    .globl wt_mmu_sync_icache
wt_mmu_sync_icache:
    cbz     x1, 3f
    add     x1, x0, x1
    mrs     x3, CTR_EL0
    ubfx    x4, x3, #16, #4
    mov     x2, #4
    lsl     x2, x2, x4
    sub     x4, x2, #1
    bic     x5, x0, x4
1:
    dc      cvau, x5
    add     x5, x5, x2
    cmp     x5, x1
    b.lo    1b
    dsb     ish
    and     x4, x3, #0xf
    mov     x2, #4
    lsl     x2, x2, x4
    sub     x4, x2, #1
    bic     x5, x0, x4
2:
    ic      ivau, x5
    add     x5, x5, x2
    cmp     x5, x1
    b.lo    2b
    dsb     ish
    isb
3:
    ret
