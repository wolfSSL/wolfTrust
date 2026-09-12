/* sysreg.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_SYSREG_H
#define WOLFTRUST_ARCH_AARCH64_SYSREG_H

#include <stdint.h>

#define WT_SYSREG_READ(name, reg) \
    static inline uint64_t wt_read_##name(void) \
    { \
        uint64_t value; \
        __asm__ volatile("mrs %0, " reg : "=r"(value)); \
        return value; \
    }
#define WT_SYSREG_WRITE(name, reg) \
    static inline void wt_write_##name(uint64_t value) \
    { \
        __asm__ volatile("msr " reg ", %0" : : "r"(value) : "memory"); \
    }

WT_SYSREG_READ(currentel, "CurrentEL")
WT_SYSREG_READ(mpidr_el1, "MPIDR_EL1")
WT_SYSREG_READ(cntfrq_el0, "CNTFRQ_EL0")
WT_SYSREG_READ(cntpct_el0, "CNTPCT_EL0")
WT_SYSREG_READ(esr_el3, "ESR_EL3")
WT_SYSREG_READ(far_el3, "FAR_EL3")
WT_SYSREG_READ(elr_el3, "ELR_EL3")
WT_SYSREG_READ(spsr_el3, "SPSR_EL3")
WT_SYSREG_READ(scr_el3, "SCR_EL3")
WT_SYSREG_WRITE(scr_el3, "SCR_EL3")
WT_SYSREG_WRITE(elr_el3, "ELR_EL3")
WT_SYSREG_WRITE(spsr_el3, "SPSR_EL3")
WT_SYSREG_WRITE(sp_el1, "SP_EL1")
WT_SYSREG_WRITE(sctlr_el1, "SCTLR_EL1")

static inline void wt_isb(void)
{
    __asm__ volatile("isb" : : : "memory");
}

static inline void wt_dsb_sy(void)
{
    __asm__ volatile("dsb sy" : : : "memory");
}

static inline void wt_daif_clear_fiq(void)
{
    __asm__ volatile("msr DAIFClr, #1" : : : "memory");
}

static inline void wt_daif_set_fiq(void)
{
    __asm__ volatile("msr DAIFSet, #1" : : : "memory");
}

static inline uint64_t wt_current_el(void)
{
    return (wt_read_currentel() >> 2) & 0x3u;
}

/* SCR_EL3 */
#define WT_SCR_NS   (1u << 0)
#define WT_SCR_IRQ  (1u << 1)
#define WT_SCR_FIQ  (1u << 2)
#define WT_SCR_EA   (1u << 3)
#define WT_SCR_SMD  (1u << 7)
#define WT_SCR_HCE  (1u << 8)
#define WT_SCR_SIF  (1u << 9)
#define WT_SCR_RW   (1u << 10)
#define WT_SCR_ST   (1u << 11)
/* Secure world running: EA and the secure timer at S-EL1, FIQ left to S-EL1. */
#define WT_SCR_EL3_SECURE (WT_SCR_RW | WT_SCR_ST | WT_SCR_EA)

/* SCTLR_EL3 and SCTLR_EL1 */
#define WT_SCTLR_EL3_RES1 0x30C50830u
#define WT_SCTLR_EL1_RES1 0x30D00800u
#define WT_SCTLR_M        (1u << 0)
#define WT_SCTLR_C        (1u << 2)
#define WT_SCTLR_SA       (1u << 3)
#define WT_SCTLR_I        (1u << 12)

/* SPSR: EL1h with D, A, I, F masked. */
#define WT_SPSR_EL1H_DAIF 0x3C5u
#define WT_SPSR_M_EL(spsr) ((uint32_t)(((spsr) >> 2) & 0x3u))

/* ESR */
#define WT_ESR_EC(esr)  ((uint32_t)(((esr) >> 26) & 0x3Fu))
#define WT_ESR_ISS(esr) ((uint32_t)((esr) & 0x1FFFFFFu))
#define WT_ESR_FSC(esr) ((uint32_t)((esr) & 0x3Fu))
#define WT_ESR_EC_UNKNOWN        0x00u
#define WT_ESR_EC_FP_ACCESS      0x07u
#define WT_ESR_EC_ILLEGAL_STATE  0x0Eu
#define WT_ESR_EC_SVC64          0x15u
#define WT_ESR_EC_SMC64          0x17u
#define WT_ESR_EC_SYSREG         0x18u
#define WT_ESR_EC_IABT_LOWER     0x20u
#define WT_ESR_EC_IABT_SAME      0x21u
#define WT_ESR_EC_PC_ALIGN       0x22u
#define WT_ESR_EC_DABT_LOWER     0x24u
#define WT_ESR_EC_DABT_SAME      0x25u
#define WT_ESR_EC_SP_ALIGN       0x26u
#define WT_ESR_EC_SERROR         0x2Fu
#define WT_ESR_EC_BRK            0x3Cu
#define WT_ESR_FSC_EXTERNAL      0x10u

#endif /* WOLFTRUST_ARCH_AARCH64_SYSREG_H */
