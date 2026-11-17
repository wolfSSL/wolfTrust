/* platform_stm32l562.c
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

/* STM32L562 port of the shared Armv8-M platform: the console pins, the
 * GTZC fabric filter with DMA and SDMMC1 held Secure, the SAU and Secure
 * MPU tables and the hooks platform_port.h names. The per-dispatch guest
 * RAM windows are the GTZC block curtain. */

#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/fabric_windows.h"
#include "wolftrust/platform.h"
#include "platform_port.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gtzc.h"
#include "memory_map.h"
#include "stm32l562_regs.h"

/* The whole guest RAM extent is Non-secure to the SAU, so Secure accesses
 * through the 0x20000000 alias stay Non-secure transactions; the GTZC MPCBB
 * curtain separates the guests at the bus. */
static const wt_armv8m_sau_region_t g_sau_regions[] = {
    { WT_GUEST0_FLASH_BASE,
      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u, false },
    { WT_RAM_NS_BASE, WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE - 1u, false },
    { WT_NSC_BASE, WT_NSC_END, true },
    /* The peripheral window skips the RNG page so a guest touching the SPM's
     * RNG through the NS alias takes a precise SecureFault, not a TZSC RAZ,
     * and the FLASH register page, which no guest drives. */
    { 0x40000000u, WT_FLASH_REG_BASE_NS - 1u, false },
    { WT_FLASH_REG_BASE_NS + 0x400u, WT_RNG_BASE_NS - 1u, false },
    { WT_RNG_BASE_NS + 0x400u, 0x4FFFFFFFu, false },
};

/* Secure-side MPU whitelist, programmed with PRIVDEFENA off by the arch
 * layer and replayed after every Secure Partition domain. */
static const wt_armv8m_mpu_region_t g_mpu_s_whitelist[] = {
    /* Region 0: secure image RX (vectors, NSC stubs, .text, .rodata). */
    { WT_FLASH_S_BASE, WT_FLASH_S_BASE + WT_FLASH_S_SIZE - 1u,
      WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 1: the update partition, wolfBoot's swap and both stores RW-NX
     * and non-cacheable: a program stores the double-word to its flash
     * address with SECCR.PG set, and a verify must read the controller. */
    { WT_FWU_UPDATE_FLASH_BASE_S, WT_FLASH_S_ALIAS_BASE + WT_FLASH_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NOCACHE },

    /* Region 2: secure RAM RW-NX from the boot handoff record up. */
    { WT_BOOT_HANDOFF_ADDRESS, WT_RAM_S_BASE + WT_RAM_S_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 3: NS guest RAM RW-NX through the 0x20000000 alias. */
    { WT_RAM_NS_BASE,
      WT_RAM_NS_BASE + WT_PLATFORM_GUEST_STACK_WINDOW_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 4: flash NS alias, read-only XN. */
    { WT_FLASH_NS_BASE, WT_FLASH_NS_BASE + WT_FLASH_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 5: peripheral aperture, both aliases. */
    { 0x40000000u, 0x5FFFFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 6: Cortex-M33 private peripheral bus. */
    { 0xE0000000u, 0xE00FFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 7: Secure alias of the guest images, RO-XN, for the vector and
     * measurement reads. */
    { WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE),
      WT_FLASH_TO_S_ALIAS(WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u),
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },
};

#if defined(WT_BUSFAULT_NEG_PROBE) && (WT_BUSFAULT_NEG_PROBE == 1)
/* The Secure SRAM alias ends at 0x30040000; the next 32 KiB are unmapped, so
 * an MPU-permitted read there is a precise BusFault. */
void wt_platform_busfault_probe_region(wt_memory_region_t* region)
{
    region->base = 0x30040000u;
    region->size = 0x00008000u;
    region->attributes = WT_MEM_ATTR_READ;
}
#endif

static void wt_uart_gpio_pin(uintptr_t gpio_base, uint32_t pin, uint32_t af)
{
    volatile uint32_t* afr;
    uint32_t shift;

    WT_GPIO_MODER(gpio_base) =
        (WT_GPIO_MODER(gpio_base) & ~(0x3u << (pin * 2u))) |
        (0x2u << (pin * 2u));
    WT_GPIO_OTYPER(gpio_base) &= ~(1u << pin);
    WT_GPIO_OSPEEDR(gpio_base) |= (0x3u << (pin * 2u));
    WT_GPIO_PUPDR(gpio_base) =
        (WT_GPIO_PUPDR(gpio_base) & ~(0x3u << (pin * 2u))) |
        (0x1u << (pin * 2u));
    WT_GPIO_SECCFGR(gpio_base) &= ~(1u << pin);

    if (pin < 8u) {
        afr = &WT_GPIO_AFRL(gpio_base);
        shift = pin * 4u;
    }
    else {
        afr = &WT_GPIO_AFRH(gpio_base);
        shift = (pin - 8u) * 4u;
    }
    *afr = (*afr & ~(0xFu << shift)) | ((af & 0xFu) << shift);
}

/* GTZC curtain (cross-guest isolation): NS guest kernels run privileged, so
 * the per-guest NS MPU alone cannot stop a hostile guest from reaching the
 * peer's RAM. Every dispatch marks the whole guest RAM extent Secure at the
 * fabric and reopens only the arriving guest's declared writable windows. */
static void wt_gtzc_close_all(void)
{
    wt_l5_gtzc_set_range(WT_RAM_NS_BASE,
                         WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE, 1);
}

static void wt_gtzc_open_window(uintptr_t base, size_t size)
{
    wt_l5_gtzc_set_range(base, base + size, 0);
}

static void wt_gtzc_commit(void)
{
    wt_dsb();
    wt_isb();
}

static const wt_fabric_windows_t g_gtzc_fabric = {
    WT_RAM_NS_BASE,
    WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE,
    wt_gtzc_close_all,
    wt_gtzc_open_window,
    wt_gtzc_commit
};

/* The core clock stays at the 110 MHz wolfBoot set. */
void wt_port_boot_init(void)
{
}

int wt_port_fabric_init(void)
{
    return wt_l5_gtzc_init();
}

/* The guests' console: USART1 on PA9/PA10 (AF7), clocked from PCLK2. */
int wt_port_late_init(void)
{
    WT_RCC_AHB2ENR |= WT_RCC_AHB2ENR_GPIOAEN;
    WT_RCC_APB2ENR |= WT_RCC_APB2ENR_USART1EN;
    (void)WT_RCC_APB2ENR;
    WT_RCC_CCIPR1 &= ~WT_RCC_CCIPR1_USART1SEL_MASK;
    wt_uart_gpio_pin(WT_GPIOA_BASE_S, 9u, 7u);
    wt_uart_gpio_pin(WT_GPIOA_BASE_S, 10u, 7u);
    return 0;
}

const wt_armv8m_sau_region_t* wt_port_sau_regions(size_t* count)
{
    *count = sizeof(g_sau_regions) / sizeof(g_sau_regions[0]);
    return g_sau_regions;
}

const wt_armv8m_mpu_region_t* wt_port_mpu_s_regions(size_t* count)
{
    *count = sizeof(g_mpu_s_whitelist) / sizeof(g_mpu_s_whitelist[0]);
    return g_mpu_s_whitelist;
}

const wt_fabric_windows_t* wt_port_fabric_windows(void)
{
    return &g_gtzc_fabric;
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* No peripheral drives the PAL line on the DK; the SPM pends it. */
void wt_port_conf_irq_set(int on)
{
    if (on != 0) {
        wt_platform_conf_irq_pend();
    }
}
#endif
