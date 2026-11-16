/* stm32h563_regs.h
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

#ifndef WOLFTRUST_FW_STM32H563_REGS_H
#define WOLFTRUST_FW_STM32H563_REGS_H

#include <stdint.h>
#include <wolfHAL/platform/st/stm32h563xx.h>
#include "wolftrust/arch/armv8m/core_regs.h"
#include "memory_map.h"

#define WT_LPUART1_BASE          0x44002400u
#define WT_LPUART1_CR1           (*(volatile uint32_t*)(WT_LPUART1_BASE + 0x00u))
#define WT_LPUART1_CR1_UE        (1u << 0)
#define WT_LPUART1_CR1_TE        (1u << 3)
#define WT_LPUART1_CR1_TXEIE     (1u << 7)
#define WT_LPUART1_IRQ           63u

#define WT_DBGMCU_IDCODE         (*(volatile uint32_t*)0x44024000u)

#define WT_USART3_BASE_NS        0x40004800u
#define WT_RNG_BASE_S            0x520C0800u
#if WT_L3_SPM_PERIPHERAL_BASE != WT_RNG_BASE_S
#error "memory_map.h names a different SPM-only peripheral than WT_RNG_BASE_S"
#endif
#define WT_USART_CR1(base)       (*(volatile uint32_t*)((base) + 0x00u))
#define WT_USART_BRR(base)       (*(volatile uint32_t*)((base) + 0x0Cu))
#define WT_USART_ISR(base)       (*(volatile uint32_t*)((base) + 0x1Cu))
#define WT_USART_TDR(base)       (*(volatile uint32_t*)((base) + 0x28u))
#define WT_USART_CR1_UE          (1u << 0)
#define WT_USART_CR1_TE          (1u << 3)
#define WT_USART_ISR_TC          (1u << 6)
#define WT_USART_ISR_TXE         (1u << 7)

#define WT_RCC_BASE_S            0x54020C00u
#define WT_RCC_BASE_NS           WHAL_STM32H5_RCC_BASE
#define WT_RCC_CR                (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x00u))
#define WT_RCC_CFGR1             (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x1Cu))
#define WT_RCC_CFGR2             (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x20u))
#define WT_RCC_PLL1CFGR          (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x28u))
#define WT_RCC_PLL1DIVR          (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x34u))
#define WT_RCC_PLL1FRACR         (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x38u))
#define WT_RCC_AHB1ENR           (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x88u))
#define WT_RCC_AHB2ENR           (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x8Cu))
#define WT_RCC_APB1LENR          (*(volatile uint32_t*)(WT_RCC_BASE_S + 0x9Cu))
#define WT_RCC_CCIPR1            (*(volatile uint32_t*)(WT_RCC_BASE_S + 0xD8u))
#define WT_RCC_AHB2ENR_NS        (*(volatile uint32_t*)(WT_RCC_BASE_NS + 0x8Cu))
#define WT_RCC_APB1LENR_NS       (*(volatile uint32_t*)(WT_RCC_BASE_NS + 0x9Cu))

#define WT_RCC_CR_HSION          (1u << 0)
#define WT_RCC_CR_HSIRDY         (1u << 1)
#define WT_RCC_CR_HSIDIV_MASK    (0x3u << 3)
#define WT_RCC_CR_HSI48ON        (1u << 12)
#define WT_RCC_CR_HSI48RDY       (1u << 13)
#define WT_RCC_CR_HSEON          (1u << 16)
#define WT_RCC_CR_HSERDY         (1u << 17)
#define WT_RCC_CR_HSEBYP         (1u << 18)
#define WT_RCC_CR_PLL1ON         (1u << 24)
#define WT_RCC_CR_PLL1RDY        (1u << 25)

#define WT_RCC_CFGR1_SW_MASK     0x3u
#define WT_RCC_CFGR1_SW_HSI      0x0u
#define WT_RCC_CFGR1_SW_PLL1     0x3u
#define WT_RCC_CFGR1_SWS_SHIFT   3u
#define WT_RCC_CFGR2_HPRE_SHIFT  0u
#define WT_RCC_CFGR2_PPRE1_SHIFT 4u
#define WT_RCC_CFGR2_PPRE2_SHIFT 8u
#define WT_RCC_CFGR2_PPRE3_SHIFT 12u
#define WT_RCC_AHB_DIV_NONE      0x0u
#define WT_RCC_APB_DIV_NONE      0x0u
#define WT_RCC_APB_DIV_2         0x4u

#define WT_RCC_PLL1CFGR_SRC_HSE  0x3u
#define WT_RCC_PLL1CFGR_RGE_4_8  (0x2u << 2)
#define WT_RCC_PLL1CFGR_VCO_WIDE 0x0u
#define WT_RCC_PLL1CFGR_M_SHIFT  8u
#define WT_RCC_PLL1CFGR_PEN      (1u << 16)
#define WT_RCC_PLL1CFGR_QEN      (1u << 17)
#define WT_RCC_PLL1CFGR_REN      (1u << 18)
#define WT_RCC_PLL1DIVR_N_SHIFT  0u
#define WT_RCC_PLL1DIVR_P_SHIFT  9u
#define WT_RCC_PLL1DIVR_Q_SHIFT  16u
#define WT_RCC_PLL1DIVR_R_SHIFT  24u

#define WT_RCC_CCIPR1_USART2SEL_SHIFT 3u
#define WT_RCC_CCIPR1_USART3SEL_SHIFT 6u
#define WT_RCC_CCIPR_USARTSEL_MASK    0x7u

#define WT_FLASH_BASE_S          0x50022000u
#define WT_FLASH_ACR             (*(volatile uint32_t*)(WT_FLASH_BASE_S + 0x00u))
#define WT_FLASH_ACR_LATENCY_MASK 0xFu
#define WT_FLASH_ACR_WRHIGHFREQ_MASK (0x3u << 4)
#define WT_FLASH_LATENCY_5WS     0x5u
#define WT_FLASH_WRHIGHFREQ_2    (0x2u << 4)
#define WT_FLASH_SR              (*(volatile uint32_t*)(WT_FLASH_BASE_S + 0x24u))
#define WT_FLASH_SR_BSY          (1u << 0)
#define WT_FLASH_SR_DBNE         (1u << 3)
/* Write-protection current option bytes (RM0481): one global set, no S/NS
 * split. Each bit protects a group of 4 consecutive 8 KiB sectors; a 0 bit
 * means write-protected. Read-only here — the port never programs option
 * bytes; provisioning sets them and wolfTrust verifies them fail-closed. */
#define WT_FLASH_WRP1R_CUR       (*(volatile uint32_t*)(WT_FLASH_BASE_S + 0xE8u))
#define WT_FLASH_WRP2R_CUR       (*(volatile uint32_t*)(WT_FLASH_BASE_S + 0x1E8u))
#define WT_FLASH_WRP_SECTORS_PER_GROUP 4u

#define WT_PWR_BASE_S            0x54020800u
#define WT_PWR_CR2               (*(volatile uint32_t*)(WT_PWR_BASE_S + 0x04u))
#define WT_PWR_VOSCR             (*(volatile uint32_t*)(WT_PWR_BASE_S + 0x10u))
#define WT_PWR_VOSSR             (*(volatile uint32_t*)(WT_PWR_BASE_S + 0x14u))
#define WT_PWR_CR2_IOSV          (1u << 9)
#define WT_PWR_VOSCR_VOS_MASK    (0x3u << 4)
#define WT_PWR_VOSCR_SCALE0      (0x3u << 4)
#define WT_PWR_VOSSR_VOSRDY      (1u << 3)

#define WT_GPIOA_BASE_S          (WHAL_STM32H563_GPIO_BASE + 0x10000000u)
#define WT_GPIOD_BASE_S          (WT_GPIOA_BASE_S + 0x0C00u)
#define WT_GPIO_MODER(base)      (*(volatile uint32_t*)((base) + 0x00u))
#define WT_GPIO_OTYPER(base)     (*(volatile uint32_t*)((base) + 0x04u))
#define WT_GPIO_OSPEEDR(base)    (*(volatile uint32_t*)((base) + 0x08u))
#define WT_GPIO_PUPDR(base)      (*(volatile uint32_t*)((base) + 0x0Cu))
#define WT_GPIO_AFRL(base)       (*(volatile uint32_t*)((base) + 0x20u))
#define WT_GPIO_AFRH(base)       (*(volatile uint32_t*)((base) + 0x24u))
#define WT_GPIO_SECCFGR(base)    (*(volatile uint32_t*)((base) + 0x30u))

#define WT_GTZC1_BASE_S          0x50032400u
#define WT_GTZC1_TZSC_SECCFGR1   (*(volatile uint32_t *)(WT_GTZC1_BASE_S + 0x10u))
#define WT_GTZC1_TZSC_SECCFGR3   (*(volatile uint32_t *)(WT_GTZC1_BASE_S + 0x18u))
#define WT_GTZC1_MPCBB1_SECCFGR  ((volatile uint32_t *)(WT_GTZC1_BASE_S + 0x0800u + 0x100u))
#define WT_GTZC1_MPCBB2_SECCFGR  ((volatile uint32_t *)(WT_GTZC1_BASE_S + 0x0C00u + 0x100u))
#define WT_GTZC1_MPCBB3_SECCFGR  ((volatile uint32_t *)(WT_GTZC1_BASE_S + 0x1000u + 0x100u))
#define WT_GTZC1_MPCBB1_PRIVCFGR ((volatile uint32_t *)(WT_GTZC1_BASE_S + 0x0800u + 0x200u))
#define WT_GTZC1_MPCBB2_PRIVCFGR ((volatile uint32_t *)(WT_GTZC1_BASE_S + 0x0C00u + 0x200u))
#define WT_GTZC1_MPCBB3_PRIVCFGR ((volatile uint32_t *)(WT_GTZC1_BASE_S + 0x1000u + 0x200u))

#define WT_RCC_AHB1ENR_GTZC1EN   (1u << 24)
#define WT_RCC_AHB2ENR_GPIOAEN   (1u << 0)
#define WT_RCC_AHB2ENR_GPIODEN   (1u << 3)
#define WT_GTZC_SECCFGR1_USART2SEC (1u << 13)
#define WT_GTZC_SECCFGR1_USART3SEC (1u << 14)
#define WT_GTZC_SECCFGR3_HASHSEC   (1u << 17)
#define WT_GTZC_SECCFGR3_RNGSEC    (1u << 18)
#define WT_GTZC_SECCFGR3_PKASEC    (1u << 20)

#define WT_STM32H563_CORE_CLOCK_HZ 240000000u
#define WT_STM32H563_APB1_CLOCK_HZ 120000000u

#endif
