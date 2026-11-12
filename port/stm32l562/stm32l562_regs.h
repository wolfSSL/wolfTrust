/* stm32l562_regs.h
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

#ifndef WOLFTRUST_FW_STM32L562_REGS_H
#define WOLFTRUST_FW_STM32L562_REGS_H

#include <stdint.h>
#include "wolftrust/arch/armv8m/core_regs.h"

#define WT_REG32(address)        (*(volatile uint32_t*)(address))

/* USART1 on PA9/PA10 is the STM32L562E-DK ST-LINK virtual COM port. */
#define WT_USART1_BASE_NS        0x40013800u
#define WT_USART1_BASE_S         0x50013800u
#define WT_USART_REGION_SIZE     0x00000400u
#define WT_USART_CR1(base)       WT_REG32((base) + 0x00u)
#define WT_USART_BRR(base)       WT_REG32((base) + 0x0Cu)
#define WT_USART_ISR(base)       WT_REG32((base) + 0x1Cu)
#define WT_USART_TDR(base)       WT_REG32((base) + 0x28u)

#define WT_RNG_BASE_S            0x520C0800u
#define WT_RNG_BASE_NS           0x420C0800u
#define WT_RNG_CR                WT_REG32(WT_RNG_BASE_S + 0x00u)
#define WT_RNG_SR                WT_REG32(WT_RNG_BASE_S + 0x04u)
#define WT_RNG_DR                WT_REG32(WT_RNG_BASE_S + 0x08u)
#define WT_RNG_HTCR              WT_REG32(WT_RNG_BASE_S + 0x10u)
/* AN4230 Table 3: the NIST-compliant STM32L5 setting for a 48 MHz RNG clock */
#define WT_RNG_CR_CONFIG_48MHZ   0x00F00D00u
#define WT_RNG_HTCR_48MHZ        0x0000A2B3u
/* RM0438: HTCR takes a value only right after this key */
#define WT_RNG_HTCR_KEY          0x17590ABCu
#define WT_RNG_CR_RNGEN          (1u << 2)
#define WT_RNG_CR_CONDRST        (1u << 30)
#define WT_RNG_SR_DRDY           (1u << 0)
#define WT_RNG_SR_CECS           (1u << 1)
#define WT_RNG_SR_SECS           (1u << 2)
#define WT_RNG_SR_CEIS           (1u << 5)
#define WT_RNG_SR_SEIS           (1u << 6)

#define WT_RCC_BASE_S            0x50021000u
#define WT_RCC_BASE_NS           0x40021000u
#define WT_RCC_AHB1ENR           WT_REG32(WT_RCC_BASE_S + 0x48u)
#define WT_RCC_AHB2ENR           WT_REG32(WT_RCC_BASE_S + 0x4Cu)
#define WT_RCC_APB2ENR           WT_REG32(WT_RCC_BASE_S + 0x60u)
#define WT_RCC_APB2ENR_NS        WT_REG32(WT_RCC_BASE_NS + 0x60u)
#define WT_RCC_CCIPR1            WT_REG32(WT_RCC_BASE_S + 0x88u)
#define WT_RCC_CRRCR             WT_REG32(WT_RCC_BASE_S + 0x98u)
#define WT_RCC_AHB1ENR_GTZCEN    (1u << 22)
#define WT_RCC_AHB1ENR_DMA1EN    (1u << 0)
#define WT_RCC_AHB1ENR_DMA2EN    (1u << 1)
#define WT_RCC_AHB2ENR_GPIOAEN   (1u << 0)
#define WT_RCC_AHB2ENR_RNGEN     (1u << 18)
#define WT_RCC_APB2ENR_USART1EN  (1u << 14)
#define WT_RCC_CCIPR1_USART1SEL_MASK  0x3u
#define WT_RCC_CCIPR1_CLK48MSEL_MASK  (0x3u << 26)
#define WT_RCC_CRRCR_HSI48ON     (1u << 0)
#define WT_RCC_CRRCR_HSI48RDY    (1u << 1)

#define WT_PWR_BASE_S            0x50007000u
#define WT_PWR_CR2               WT_REG32(WT_PWR_BASE_S + 0x04u)
#define WT_PWR_CR2_IOSV          (1u << 9)

#define WT_GPIOA_BASE_S          0x52020000u
#define WT_GPIO_MODER(base)      WT_REG32((base) + 0x00u)
#define WT_GPIO_OTYPER(base)     WT_REG32((base) + 0x04u)
#define WT_GPIO_OSPEEDR(base)    WT_REG32((base) + 0x08u)
#define WT_GPIO_PUPDR(base)      WT_REG32((base) + 0x0Cu)
#define WT_GPIO_AFRL(base)       WT_REG32((base) + 0x20u)
#define WT_GPIO_AFRH(base)       WT_REG32((base) + 0x24u)
#define WT_GPIO_SECCFGR(base)    WT_REG32((base) + 0x30u)

/* DMA1/DMA2 are TrustZone-aware: a channel with SECM set is configurable only
 * from Secure, so guests cannot program it. */
#define WT_DMA1_BASE_S           0x50020000u
#define WT_DMA2_BASE_S           0x50020400u
#define WT_DMA_CHANNELS          8u
#define WT_DMA_CCR(base, ch)     WT_REG32((base) + 0x08u + 0x14u * (ch))
#define WT_DMA_CCR_EN            (1u << 0)
#define WT_DMA_CCR_SECM          (1u << 17)
#define WT_DMA_CCR_PRIV          (1u << 20)

/* One GTZC: TZSC peripheral attribution, MPCBB1 for SRAM1 (24 vector words)
 * and MPCBB2 for SRAM2 (8 words), 256-byte blocks, no per-block privilege. */
#define WT_GTZC_TZSC_BASE_S      0x50032400u
#define WT_GTZC_TZSC_SECCFGR1    WT_REG32(WT_GTZC_TZSC_BASE_S + 0x10u)
#define WT_GTZC_TZSC_SECCFGR2    WT_REG32(WT_GTZC_TZSC_BASE_S + 0x14u)
#define WT_GTZC_MPCBB1_VCTR      ((volatile uint32_t*)0x50032D00u)
#define WT_GTZC_MPCBB2_VCTR      ((volatile uint32_t*)0x50033100u)
#define WT_GTZC_MPCBB1_WORDS     24u
#define WT_GTZC_MPCBB2_WORDS     8u
#define WT_GTZC_SRAM1_BASE       0x20000000u
#define WT_GTZC_SRAM2_BASE       0x20030000u
#define WT_GTZC_BLOCK_SIZE       256u
#define WT_GTZC_SECCFGR2_USART1SEC (1u << 1)
#define WT_GTZC_SECCFGR2_AESSEC  (1u << 12)
#define WT_GTZC_SECCFGR2_HASHSEC (1u << 13)
#define WT_GTZC_SECCFGR2_RNGSEC  (1u << 14)
#define WT_GTZC_SECCFGR2_PKASEC  (1u << 15)
#define WT_GTZC_SECCFGR2_SDMMC1SEC (1u << 16)

/* Flash controller: Secure pages program through the SEC key/status/control
 * registers; a page number is relative to its bank in dual-bank mode. */
#define WT_FLASH_BASE_S          0x50022000u
#define WT_FLASH_SECKEYR         WT_REG32(WT_FLASH_BASE_S + 0x0Cu)
#define WT_FLASH_SECSR           WT_REG32(WT_FLASH_BASE_S + 0x24u)
#define WT_FLASH_SECCR           WT_REG32(WT_FLASH_BASE_S + 0x2Cu)
#define WT_FLASH_ECCR            WT_REG32(WT_FLASH_BASE_S + 0x30u)
#define WT_FLASH_OPTR            WT_REG32(WT_FLASH_BASE_S + 0x40u)
#define WT_FLASH_WRP1AR          WT_REG32(WT_FLASH_BASE_S + 0x58u)
#define WT_FLASH_WRP1BR          WT_REG32(WT_FLASH_BASE_S + 0x5Cu)
#define WT_FLASH_WRP2AR          WT_REG32(WT_FLASH_BASE_S + 0x68u)
#define WT_FLASH_WRP2BR          WT_REG32(WT_FLASH_BASE_S + 0x6Cu)
#define WT_FLASH_SR_EOP          (1u << 0)
#define WT_FLASH_SR_OPERR        (1u << 1)
#define WT_FLASH_SR_PROGERR      (1u << 3)
#define WT_FLASH_SR_WRPERR       (1u << 4)
#define WT_FLASH_SR_PGAERR       (1u << 5)
#define WT_FLASH_SR_SIZERR       (1u << 6)
#define WT_FLASH_SR_PGSERR       (1u << 7)
#define WT_FLASH_SR_BSY          (1u << 16)
#define WT_FLASH_CR_PG           (1u << 0)
#define WT_FLASH_CR_PER          (1u << 1)
#define WT_FLASH_CR_PNB_SHIFT    3u
#define WT_FLASH_CR_PNB_MASK     0x7Fu
#define WT_FLASH_CR_BKER         (1u << 11)
#define WT_FLASH_CR_STRT         (1u << 16)
#define WT_FLASH_CR_LOCK         (1u << 31)
#define WT_FLASH_ECCR_ADDR_MASK  0x0007FFFFu
#define WT_FLASH_ECCR_BK         (1u << 21)
#define WT_FLASH_ECCR_ECCD       (1u << 31)
#define WT_FLASH_OPTR_SWAP_BANK  (1u << 20)
#define WT_FLASH_OPTR_DBANK      (1u << 22)
#define WT_FLASH_WRP_PSTRT_MASK  0x7Fu
#define WT_FLASH_WRP_PEND_SHIFT  16u
#define WT_FLASH_KEY1            0x45670123u
#define WT_FLASH_KEY2            0xCDEF89ABu

#define WT_ICACHE_CR             WT_REG32(0x50030400u)
#define WT_ICACHE_SR             WT_REG32(0x50030404u)
#define WT_ICACHE_CR_EN          (1u << 0)
#define WT_ICACHE_CR_CACHEINV    (1u << 1)
#define WT_ICACHE_SR_BUSYF       (1u << 0)

#endif
