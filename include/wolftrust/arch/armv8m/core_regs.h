/* core_regs.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFTRUST_ARCH_ARMV8M_CORE_REGS_H
#define WOLFTRUST_ARCH_ARMV8M_CORE_REGS_H

/* Armv8-M architected core registers (SCB, MPU, NVIC, SAU, SysTick) and
 * barriers. Every Cortex-M33 SoC shares these; SoC peripherals stay in the
 * port's own register header. */

#include <stdint.h>

#define WT_SCB_VTOR_S            (*(volatile uint32_t*)0xE000ED08u)
#define WT_SCB_VTOR_NS           (*(volatile uint32_t*)0xE002ED08u)
#define WT_SCB_CCR_S             (*(volatile uint32_t*)0xE000ED14u)
#define WT_SCB_SHPR3_S           (*(volatile uint32_t*)0xE000ED20u)
#define WT_SCB_SHCSR_S           (*(volatile uint32_t*)0xE000ED24u)
#define WT_SCB_SHCSR_NS          (*(volatile uint32_t*)0xE002ED24u)
#define WT_SCB_CFSR_S            (*(volatile uint32_t*)0xE000ED28u)
#define WT_SCB_HFSR_S            (*(volatile uint32_t*)0xE000ED2Cu)
#define WT_SCB_MMFAR_S           (*(volatile uint32_t*)0xE000ED34u)
#define WT_SCB_BFAR_S            (*(volatile uint32_t*)0xE000ED38u)
#define WT_SCB_ICSR_S            (*(volatile uint32_t*)0xE000ED04u)
#define WT_SCB_ICSR_NS           (*(volatile uint32_t*)0xE002ED04u)
#define WT_SCB_AIRCR_S           (*(volatile uint32_t*)0xE000ED0Cu)
#define WT_SCB_AIRCR_VECTKEY     (0x05FAu << 16)
#define WT_SCB_AIRCR_SYSRESETREQ (WT_SCB_AIRCR_VECTKEY | (1u << 2))
#define WT_SCB_AIRCR_SYSRESETREQS (1u << 3)
#define WT_SCB_AIRCR_BFHFNMINS   (1u << 13)
#define WT_SCB_AIRCR_PRIS        (1u << 14)
/* Config bits that must be preserved across an AIRCR read-modify-write. */
#define WT_SCB_AIRCR_CFG_MASK    ((1u << 3) | (1u << 13) | (1u << 14) | (7u << 8))
#define WT_SCB_ICSR_PENDSVCLR    (1u << 27)
#define WT_SCB_ICSR_PENDSVSET    (1u << 28)
#define WT_SCB_ICSR_PENDSTCLR    (1u << 25)
#define WT_SCB_ICSR_PENDSTSET    (1u << 26)

#define WT_SCB_SHPR3_PENDSV_SHIFT 16u
#define WT_SCB_SHPR3_SYSTICK_SHIFT 24u

#define WT_SCB_SHCSR_MEMFAULTENA (1u << 16)
#define WT_SCB_SHCSR_BUSFAULTENA (1u << 17)
#define WT_SCB_SHCSR_USGFAULTENA (1u << 18)
/* USG/MEM/BUS/SVCALL/HARDFAULT pended bits. */
#define WT_SCB_SHCSR_PEND_MASK   ((1u << 12) | (1u << 13) | (1u << 14) | \
                                  (1u << 15) | (1u << 21))
/* Every SHCSR exception-active bit (Armv8-M Mainline). */
#define WT_SCB_SHCSR_ACT_MASK    ((1u << 0) | (1u << 1) | (1u << 2) | (1u << 3) | \
                                  (1u << 4) | (1u << 5) | (1u << 7) | \
                                  (1u << 8) | (1u << 10) | (1u << 11))

#define WT_SCB_CFSR_MMFSR_MASK   0x000000FFu
#define WT_SCB_CFSR_BFSR_MASK    0x0000FF00u
#define WT_SCB_CFSR_UFSR_MASK    0xFFFF0000u

#define WT_SCB_CFSR_MMFSR_IACCVIOL    (1u << 0)
#define WT_SCB_CFSR_MMFSR_DACCVIOL    (1u << 1)
#define WT_SCB_CFSR_MMFSR_MUNSTKERR   (1u << 3)
#define WT_SCB_CFSR_MMFSR_MSTKERR     (1u << 4)
#define WT_SCB_CFSR_MMFSR_MLSPERR     (1u << 5)
#define WT_SCB_CFSR_MMFSR_MMARVALID   (1u << 7)

#define WT_SCB_CFSR_BFSR_IBUSERR      (1u << 8)
#define WT_SCB_CFSR_BFSR_PRECISERR    (1u << 9)
#define WT_SCB_CFSR_BFSR_IMPRECISERR  (1u << 10)
#define WT_SCB_CFSR_BFSR_UNSTKERR     (1u << 11)
#define WT_SCB_CFSR_BFSR_STKERR       (1u << 12)
#define WT_SCB_CFSR_BFSR_LSPERR       (1u << 13)
#define WT_SCB_CFSR_BFSR_BFARVALID    (1u << 15)

#define WT_SCB_HFSR_FORCED            (1u << 30)

#define WT_SCB_CFSR_UFSR_STKOF        (1u << 20)  /* UFSR bit 4 lifted to CFSR bit 20 */
/* Faults that leave no readable exception frame at the faulting SP. */
#define WT_SCB_CFSR_NO_FRAME          (WT_SCB_CFSR_MMFSR_MUNSTKERR | \
                                       WT_SCB_CFSR_MMFSR_MSTKERR | \
                                       WT_SCB_CFSR_BFSR_UNSTKERR | \
                                       WT_SCB_CFSR_BFSR_STKERR | \
                                       WT_SCB_CFSR_UFSR_STKOF)
#define WT_SCB_CFSR_UFSR_NOCP         (1u << 19)  /* UFSR bit 3: coprocessor disabled */
#define WT_SCB_CFSR_UFSR_UNDEFINSTR   (1u << 16)  /* UFSR bit 0: undefined instruction */

/* Coprocessor Access Control and the FP context/config registers. CPACR and
 * FPCCR are banked; the Secure alias is written from the Secure world. */
#define WT_SCB_CPACR_S           (*(volatile uint32_t*)0xE000ED88u)
#define WT_SCB_CPACR_NS          (*(volatile uint32_t*)0xE002ED88u)
#define WT_SCB_NSACR             (*(volatile uint32_t*)0xE000ED8Cu)
#define WT_SCB_FPCCR_S           (*(volatile uint32_t*)0xE000EF34u)
#define WT_SCB_CPACR_CP10_CP11   (0xFu << 20)     /* CP10/CP11 access field */
#define WT_SCB_NSACR_CP10_CP11   (0x3u << 10)     /* NS access to CP10/CP11 */
#define WT_SCB_FPCCR_LSPEN       (1u << 30)       /* lazy state preservation */
#define WT_SCB_FPCCR_ASPEN       (1u << 31)       /* automatic state preservation */
#define WT_SCB_FPCCR_TS          (1u << 26)       /* treat FP state as Secure */
#define WT_SCB_FPCCR_CLRONRETS   (1u << 27)       /* lock CLRONRET against NS writes */
#define WT_SCB_FPCCR_CLRONRET    (1u << 28)       /* clear FP caller regs on return */
#define WT_SCB_FPCCR_LSPENS      (1u << 29)       /* lock LSPEN against NS writes */
#define WT_SCB_FPCCR_LSPACT      (1u << 0)        /* lazy FP state pending */
#define WT_CONTROL_FPCA          (1u << 2)        /* FP context active */
#define WT_CONTROL_SFPA          (1u << 3)        /* Secure FP context active */

/* Armv8-M Secure stack seal value, written twice at the top of a stack. */
#define WT_ARMV8M_STACK_SEAL     0xFEF5EDA5u

#define WT_MPU_S_TYPE            (*(volatile uint32_t*)0xE000ED90u)
#define WT_MPU_S_CTRL            (*(volatile uint32_t*)0xE000ED94u)
#define WT_MPU_S_RNR             (*(volatile uint32_t*)0xE000ED98u)
#define WT_MPU_S_RBAR            (*(volatile uint32_t*)0xE000ED9Cu)
#define WT_MPU_S_RLAR            (*(volatile uint32_t*)0xE000EDA0u)
#define WT_MPU_S_MAIR0           (*(volatile uint32_t*)0xE000EDC0u)
#define WT_MPU_S_MAIR1           (*(volatile uint32_t*)0xE000EDC4u)

#define WT_MPU_CTRL_ENABLE       (1u << 0)
#define WT_MPU_CTRL_HFNMIENA     (1u << 1)
#define WT_MPU_CTRL_PRIVDEFENA   (1u << 2)

#define WT_NVIC_ISER0            (*(volatile uint32_t*)0xE000E100u)
#define WT_NVIC_ISER1            (*(volatile uint32_t*)0xE000E104u)
#define WT_NVIC_ICER0            (*(volatile uint32_t*)0xE000E180u)
#define WT_NVIC_ICER1            (*(volatile uint32_t*)0xE000E184u)
#define WT_NVIC_ISPR0            (*(volatile uint32_t*)0xE000E200u)
#define WT_NVIC_ISPR1            (*(volatile uint32_t*)0xE000E204u)
#define WT_NVIC_ICPR0            (*(volatile uint32_t*)0xE000E280u)
#define WT_NVIC_ICPR1            (*(volatile uint32_t*)0xE000E284u)
#define WT_NVIC_ITNS0            (*(volatile uint32_t*)0xE000E380u)
#define WT_NVIC_ITNS1            (*(volatile uint32_t*)0xE000E384u)
#define WT_NVIC_IPR_BASE         ((volatile uint8_t*)0xE000E400u)

#define WT_SAU_CTRL              (*(volatile uint32_t*)0xE000EDD0u)
#define WT_SAU_TYPE              (*(volatile const uint32_t*)0xE000EDD4u)
#define WT_SAU_RNR               (*(volatile uint32_t*)0xE000EDD8u)
#define WT_SAU_RBAR              (*(volatile uint32_t*)0xE000EDDCu)
#define WT_SAU_RLAR              (*(volatile uint32_t*)0xE000EDE0u)
#define WT_SAU_SFSR              (*(volatile uint32_t*)0xE000EDE4u)
#define WT_SAU_SFAR              (*(volatile uint32_t*)0xE000EDE8u)

#define WT_MPU_NS_TYPE           (*(volatile uint32_t*)0xE002ED90u)
#define WT_MPU_NS_CTRL           (*(volatile uint32_t*)0xE002ED94u)
#define WT_MPU_NS_RNR            (*(volatile uint32_t*)0xE002ED98u)
#define WT_MPU_NS_RBAR           (*(volatile uint32_t*)0xE002ED9Cu)
#define WT_MPU_NS_RLAR           (*(volatile uint32_t*)0xE002EDA0u)
#define WT_MPU_NS_MAIR0          (*(volatile uint32_t*)0xE002EDC0u)

#define WT_SYST_CSR              (*(volatile uint32_t*)0xE000E010u)
#define WT_SYST_RVR              (*(volatile uint32_t*)0xE000E014u)
#define WT_SYST_CVR              (*(volatile uint32_t*)0xE000E018u)

#define WT_SYST_NS_CSR           (*(volatile uint32_t*)0xE002E010u)
#define WT_SYST_NS_RVR           (*(volatile uint32_t*)0xE002E014u)
#define WT_SYST_NS_CVR           (*(volatile uint32_t*)0xE002E018u)

#define WT_SYST_CSR_ENABLE       (1u << 0)
#define WT_SYST_CSR_TICKINT      (1u << 1)
#define WT_SYST_CSR_CLKSOURCE    (1u << 2)
#define WT_SYST_CSR_COUNTFLAG    (1u << 16)

static inline void wt_dsb(void)
{
    __asm volatile("dsb 0xF" ::: "memory");
}

static inline void wt_dmb(void)
{
    __asm volatile("dmb 0xF" ::: "memory");
}

static inline void wt_isb(void)
{
    __asm volatile("isb 0xF" ::: "memory");
}

static inline uint32_t wt_thumb_insn_len(uint32_t pc)
{
    uint16_t hw = *(uint16_t*)pc;

    if ((hw & 0xF800u) == 0xE800u || (hw & 0xF800u) == 0xF000u ||
        (hw & 0xF800u) == 0xF800u) {
        return 4u;
    }

    return 2u;
}

#endif /* WOLFTRUST_ARCH_ARMV8M_CORE_REGS_H */
