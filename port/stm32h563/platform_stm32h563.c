/* platform_stm32h563.c
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

/* STM32H563 port of the shared Armv8-M platform: clocks and console pins,
 * the GTZC fabric filter and its read-back, the WRP fence read-back, the
 * SAU and Secure MPU tables and the hooks platform_port.h names. The
 * per-dispatch guest RAM windows are the GTZC block curtain. */

#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/fabric_windows.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/platform.h"
#include "platform_port.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wolfHAL/clock/stm32h5_rcc.h>
#include <wolfHAL/platform/st/stm32h563xx.h>
#include <wolfHAL/reg.h>

#include "memory_map.h"
#include "silicon_rev.h"
#include "stm32h563_regs.h"

static const wt_armv8m_sau_region_t g_sau_regions[] = {
    { WT_GUEST0_FLASH_BASE,
      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u, false },
    { WT_RAM_NS_BASE, WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE - 1u, false },
    { WT_NSC_BASE, WT_NSC_END, true },
    { 0x40000000u, 0x4FFFFFFFu, false },
};

/* Secure-side MPU whitelist, programmed with PRIVDEFENA off by the arch
 * layer and replayed after every Secure Partition domain. */
static const wt_armv8m_mpu_region_t g_mpu_s_whitelist[] = {
    /* Region 0: secure flash RX (image, NSC stubs, .text). */
    { WT_FLASH_S_BASE, WT_FLASH_S_BASE + WT_FLASH_S_SIZE - 1u,
      WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 1: secure flash bank 2 RW-NX. The wolfHSM NVM partition
     * lives at 0x0C1FC000..0x0C1FFFFF and STM32H5 flash programming
     * writes data words directly to the destination flash address with
     * FLASH_CR.PG set (the FLASH controller intercepts the stores).
     * The peripheral's own LOCK / PG gating is the real write barrier.
     * Keep this region non-cacheable so an immediate verify reads the flash
     * controller rather than a cache line populated before programming. */
    { 0x0C100000u, 0x0C1FFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NOCACHE },

    /* Region 2: secure RAM RW-NX from the boot handoff record up. */
    { WT_BOOT_HANDOFF_ADDRESS,
      WT_RAM_S_BASE + WT_RAM_S_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 3: NS RAM RW-NX. Secure code touches this through the
     * 0x20000000 alias to validate and copy mediated service vectors. HSM
     * tasklet faults do not write a response through this mapping. */
    { WT_RAM_NS_BASE, WT_RAM_NS_BASE + 0x0001FFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 4: NS flash R (so secure side can read guest image
     * metadata if needed - current code does not, but the SAU window
     * exists and we keep it consistent). XN to prevent stray Secure
     * execution into NS code. */
    { WT_FLASH_NS_BASE, WT_FLASH_NS_BASE + 0x001FFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 5: SoC peripheral aperture (RCC, GTZC, GPIO, USART, FLASH
     * controller, RNG, etc.) - both the 0x40000000 NS alias and the
     * 0x50000000 secure alias fall in one 256 MiB block. */
    { 0x40000000u, 0x5FFFFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 6: Cortex private peripheral bus (SCB, NVIC, SAU, MPU,
     * SysTick - everything in the 0xE0000000..0xE00FFFFF window). */
    { 0xE0000000u, 0xE00FFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 7: Secure alias of guest flash images.
     * RO-XN - the Secure side only reads guest reset vectors and metadata
     * from here; never executes guest code in Secure state. The 0x08...
     * NS alias is reachable too (region 4), but on at least one emulator
     * the Secure-side read of that NS alias returns zero, so we keep this
     * Secure alias window for reliable access. */
    { WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE),
      WT_FLASH_TO_S_ALIAS(WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u),
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },
};

static void wt_rcc_enable_clock(uintptr_t base,
                                const whal_Stm32h5_Rcc_PeriphClk* clk)
{
    whal_Reg_Update((size_t)base, clk->regOffset, clk->enableMask,
                    clk->enableMask);
}

int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size)
{
    uint32_t wrp;
    uintptr_t bank_base;

    if (window_base >= WT_FLASH_NS_BASE + 0x00100000u) {
        wrp = WT_FLASH_WRP2R_CUR;
        bank_base = WT_FLASH_NS_BASE + 0x00100000u;
    }
    else {
        wrp = WT_FLASH_WRP1R_CUR;
        bank_base = WT_FLASH_NS_BASE;
    }

    return wt_guest_flash_wrp_covers(wrp, window_base, window_size, bank_base,
                                     WT_FLASH_SECTOR_SIZE,
                                     WT_FLASH_WRP_SECTORS_PER_GROUP);
}

#define WT_GTZC_SECCFGR3_SPM (WT_GTZC_SECCFGR3_HASHSEC | \
                              WT_GTZC_SECCFGR3_RNGSEC | \
                              WT_GTZC_SECCFGR3_PKASEC)

/* WT-FFM-0068: read the attribution back, so a register that did not take
 * (or a later write that undid it) halts boot instead of leaving the SPM's
 * peripherals or Secure SRAM reachable from Non-secure masters, DMA included. */
static int wt_gtzc_attribution_ok(size_t nsWords)
{
    size_t i;

    if ((WT_GTZC1_TZSC_SECCFGR3 & WT_GTZC_SECCFGR3_SPM) !=
            WT_GTZC_SECCFGR3_SPM) {
        return 0;
    }
    for (i = nsWords; i < 16u; ++i) {
        if (WT_GTZC1_MPCBB1_SECCFGR[i] != 0xFFFFFFFFu) {
            return 0;
        }
    }
    for (i = 0; i < 4u; ++i) {
        if (WT_GTZC1_MPCBB2_SECCFGR[i] != 0xFFFFFFFFu) {
            return 0;
        }
    }
    for (i = 0; i < 20u; ++i) {
        if (WT_GTZC1_MPCBB3_SECCFGR[i] != 0xFFFFFFFFu) {
            return 0;
        }
    }
    return 1;
}

static int wt_gtzc_init(void)
{
    size_t i;
    size_t nsWords = (WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE -
                      WT_RAM_NS_BASE) / (512u * 32u);

    WT_RCC_AHB1ENR |= WT_RCC_AHB1ENR_GTZC1EN;

    for (i = 0; i < 16u; ++i) {
        WT_GTZC1_MPCBB1_SECCFGR[i] = 0xFFFFFFFFu;
    }

    /* SRAM1 MPCBB blocks are 512 B; each SECCFGR word covers 32 blocks
     * (16 KiB). Mark the whole guest RAM extent Non-secure — derived from
     * the memory map so a layout change cannot leave a guest window
     * secure-blocked. The Secure monitor .data/.bss lives above this bank. */
    for (i = 0; i < nsWords && i < 16u; ++i) {
        WT_GTZC1_MPCBB1_SECCFGR[i] = 0x00000000u;
    }

    /* Guests own the UARTs. SAU makes the APB window non-secure, but
     * STM32H5 also gates peripheral security through GTZC/TZSC. */
    WT_GTZC1_TZSC_SECCFGR1 &= ~(WT_GTZC_SECCFGR1_USART2SEC |
                                WT_GTZC_SECCFGR1_USART3SEC);

    /* Crypto peripherals are secure-owned. Do not clear these bits when the
     * APB/AHB SAU windows are exposed to guests for other devices. STM32H563
     * has HASH, RNG and PKA in this GTZC register; AES/SAES are not present on
     * this line and future H5 derivatives should add their bits here. */
    WT_GTZC1_TZSC_SECCFGR3 |= WT_GTZC_SECCFGR3_SPM;

    for (i = 0; i < 4u; ++i) {
        WT_GTZC1_MPCBB2_SECCFGR[i] = 0xFFFFFFFFu;
    }

    for (i = 0; i < 20u; ++i) {
        WT_GTZC1_MPCBB3_SECCFGR[i] = 0xFFFFFFFFu;
    }

    /* MPCBB PRIVCFGR resets to all-privileged on real silicon, which blocks
     * every unprivileged SRAM access below the MPU — the unprivileged crypto
     * SP thread faults on its first frame access no matter what the MPU
     * grants. Privilege enforcement is the secure MPU's job here, so drop the
     * GTZC privilege filter (the M33MU does not model it). */
    for (i = 0; i < 16u; ++i) {
        WT_GTZC1_MPCBB1_PRIVCFGR[i] = 0x00000000u;
    }
    for (i = 0; i < 4u; ++i) {
        WT_GTZC1_MPCBB2_PRIVCFGR[i] = 0x00000000u;
    }
    for (i = 0; i < 20u; ++i) {
        WT_GTZC1_MPCBB3_PRIVCFGR[i] = 0x00000000u;
    }
    return (wt_gtzc_attribution_ok(nsWords) == 1) ? 0 : -1;
}

#if defined(WT_BUSFAULT_NEG_PROBE) && (WT_BUSFAULT_NEG_PROBE == 1)
/* The 32 KiB past the end of physical SRAM3 (0x300A0000) is unmapped on the
 * H563, so an MPU-permitted read there is a precise BusFault on silicon. */
void wt_platform_busfault_probe_region(wt_memory_region_t* region)
{
    region->base = 0x300A0000u;
    region->size = 0x00008000u;
    region->attributes = WT_MEM_ATTR_READ;
}
#endif

static void wt_clock_init(void)
{
    uint32_t reg;

    /* Do not inherit wolfBoot's clock (250 MHz, APB1 undivided): re-establish the
     * 240 MHz APB1/2 tree the stock nucleo_h563zi NS guest was built for, else
     * its USART3 baud is ~2x off on real silicon. */

    reg = WT_PWR_VOSCR & ~WT_PWR_VOSCR_VOS_MASK;
    WT_PWR_VOSCR = reg | WT_PWR_VOSCR_SCALE0;
    while ((WT_PWR_VOSSR & WT_PWR_VOSSR_VOSRDY) == 0u) {
    }

    reg = WT_FLASH_ACR & ~(WT_FLASH_ACR_LATENCY_MASK |
                           WT_FLASH_ACR_WRHIGHFREQ_MASK);
    WT_FLASH_ACR = reg | WT_FLASH_LATENCY_5WS | WT_FLASH_WRHIGHFREQ_2;
    while ((WT_FLASH_ACR & (WT_FLASH_ACR_LATENCY_MASK |
                            WT_FLASH_ACR_WRHIGHFREQ_MASK)) !=
           (WT_FLASH_LATENCY_5WS | WT_FLASH_WRHIGHFREQ_2)) {
    }

    WT_RCC_CFGR1 = (WT_RCC_CFGR1 & ~WT_RCC_CFGR1_SW_MASK) |
                   WT_RCC_CFGR1_SW_HSI;
    while (((WT_RCC_CFGR1 >> WT_RCC_CFGR1_SWS_SHIFT) &
            WT_RCC_CFGR1_SW_MASK) != WT_RCC_CFGR1_SW_HSI) {
    }

    WT_RCC_CR &= ~WT_RCC_CR_PLL1ON;
    while ((WT_RCC_CR & WT_RCC_CR_PLL1RDY) != 0u) {
    }

    WT_RCC_CR = (WT_RCC_CR | WT_RCC_CR_HSION | WT_RCC_CR_HSEON |
                 WT_RCC_CR_HSEBYP) & ~WT_RCC_CR_HSIDIV_MASK;
    while ((WT_RCC_CR & WT_RCC_CR_HSIRDY) == 0u) {
    }
    while ((WT_RCC_CR & WT_RCC_CR_HSERDY) == 0u) {
    }
    WT_RCC_CR |= WT_RCC_CR_HSI48ON;
    while ((WT_RCC_CR & WT_RCC_CR_HSI48RDY) == 0u) {
    }

    /* NUCLEO-H563ZI HSE is the 8 MHz ST-LINK MCO. PLL1: 8 / 2 * 120 / 2
     * gives a 240 MHz core clock. APB1/APB3 are kept at 120 MHz. */
    WT_RCC_PLL1CFGR = WT_RCC_PLL1CFGR_SRC_HSE |
                      WT_RCC_PLL1CFGR_RGE_4_8 |
                      WT_RCC_PLL1CFGR_VCO_WIDE |
                      (2u << WT_RCC_PLL1CFGR_M_SHIFT);
    WT_RCC_PLL1DIVR = ((120u - 1u) << WT_RCC_PLL1DIVR_N_SHIFT) |
                      ((2u - 1u) << WT_RCC_PLL1DIVR_P_SHIFT) |
                      ((4u - 1u) << WT_RCC_PLL1DIVR_Q_SHIFT) |
                      ((2u - 1u) << WT_RCC_PLL1DIVR_R_SHIFT);
    WT_RCC_PLL1FRACR = 0u;
    WT_RCC_PLL1CFGR |= WT_RCC_PLL1CFGR_PEN |
                       WT_RCC_PLL1CFGR_QEN |
                       WT_RCC_PLL1CFGR_REN;

    WT_RCC_CFGR2 = (WT_RCC_AHB_DIV_NONE << WT_RCC_CFGR2_HPRE_SHIFT) |
                   (WT_RCC_APB_DIV_2 << WT_RCC_CFGR2_PPRE1_SHIFT) |
                   (WT_RCC_APB_DIV_NONE << WT_RCC_CFGR2_PPRE2_SHIFT) |
                   (WT_RCC_APB_DIV_2 << WT_RCC_CFGR2_PPRE3_SHIFT);

    WT_RCC_CR |= WT_RCC_CR_PLL1ON;
    while ((WT_RCC_CR & WT_RCC_CR_PLL1RDY) == 0u) {
    }

    WT_RCC_CFGR1 = (WT_RCC_CFGR1 & ~WT_RCC_CFGR1_SW_MASK) |
                   WT_RCC_CFGR1_SW_PLL1;
    while (((WT_RCC_CFGR1 >> WT_RCC_CFGR1_SWS_SHIFT) &
            WT_RCC_CFGR1_SW_MASK) != WT_RCC_CFGR1_SW_PLL1) {
    }

    /* USART2/USART3 kernel clock source 0 is PCLK1. */
    WT_RCC_CCIPR1 &= ~((WT_RCC_CCIPR_USARTSEL_MASK <<
                        WT_RCC_CCIPR1_USART2SEL_SHIFT) |
                       (WT_RCC_CCIPR_USARTSEL_MASK <<
                        WT_RCC_CCIPR1_USART3SEL_SHIFT));
}

static void wt_configure_uart_gpio_pin(uintptr_t gpio_base, uint32_t pin,
                                       uint32_t af)
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
    } else {
        afr = &WT_GPIO_AFRH(gpio_base);
        shift = (pin - 8u) * 4u;
    }

    *afr = (*afr & ~(0xFu << shift)) | ((af & 0xFu) << shift);
}

static void wt_uart_gpio_init(void)
{
    static const whal_Stm32h5_Rcc_PeriphClk gpio_clocks[] = {
        {WHAL_STM32H563_GPIOA_CLOCK},
        {WHAL_STM32H563_GPIOD_CLOCK},
    };

    for (size_t i = 0u; i < sizeof(gpio_clocks) / sizeof(gpio_clocks[0]); ++i) {
        wt_rcc_enable_clock(WT_RCC_BASE_S, &gpio_clocks[i]);
    }
    (void)WT_RCC_AHB2ENR;
    WT_PWR_CR2 |= WT_PWR_CR2_IOSV;

    /* USART2 on PA2/PA3, USART3 VCP on PD8/PD9. */
    wt_configure_uart_gpio_pin(WT_GPIOA_BASE_S, 2u, 7u);
    wt_configure_uart_gpio_pin(WT_GPIOA_BASE_S, 3u, 7u);
    wt_configure_uart_gpio_pin(WT_GPIOD_BASE_S, 8u, 7u);
    wt_configure_uart_gpio_pin(WT_GPIOD_BASE_S, 9u, 7u);
}

/* GTZC curtain (cross-guest isolation): NS guest kernels run privileged, so
 * the per-guest NS MPU alone cannot stop a hostile guest from reprogramming
 * MPU_NS and reaching the peer's RAM. Every dispatch closes the whole shared
 * guest RAM extent at the fabric (blocks marked Secure reject Non-secure
 * transactions regardless of privilege) and reopens only the arriving
 * guest's declared writable windows. */
static void wt_gtzc_close_all(void)
{
    uintptr_t extent_end = WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE;
    size_t nsWords = (extent_end - WT_RAM_NS_BASE) / (512u * 32u);
    size_t i;

    for (i = 0; i < nsWords && i < 16u; ++i) {
        WT_GTZC1_MPCBB1_SECCFGR[i] = 0xFFFFFFFFu;
    }
}

static void wt_gtzc_open_window(uintptr_t base, size_t size)
{
    size_t first = (base - WT_RAM_NS_BASE) / 512u;
    size_t last = (base + size - WT_RAM_NS_BASE + 511u) / 512u;
    size_t block;

    for (block = first; block < last; ++block) {
        WT_GTZC1_MPCBB1_SECCFGR[block / 32u] &= ~(1u << (block % 32u));
    }
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

void wt_port_boot_init(void)
{
    wt_clock_init();
}

int wt_port_fabric_init(void)
{
    return wt_gtzc_init();
}

/* Console clocks in both security views, their pins, and the silicon guard. */
int wt_port_late_init(void)
{
    static const whal_Stm32h5_Rcc_PeriphClk uart_clocks[] = {
        {WHAL_STM32H563_USART2_CLOCK},
        {WHAL_STM32H563_USART3_CLOCK},
    };
    static const whal_Stm32h5_Rcc_PeriphClk rng_clock =
        {WHAL_STM32H563_RNG_CLOCK};
    size_t i;

    for (i = 0u; i < sizeof(uart_clocks) / sizeof(uart_clocks[0]); ++i) {
        wt_rcc_enable_clock(WT_RCC_BASE_S, &uart_clocks[i]);
        wt_rcc_enable_clock(WT_RCC_BASE_NS, &uart_clocks[i]);
    }
    wt_rcc_enable_clock(WT_RCC_BASE_S, &rng_clock);
    wt_uart_gpio_init();
    wt_h563_silicon_guard();
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
/* LPUART1 with TXEIE raises its line as soon as the transmitter is enabled
 * (TXE idles high): a real peripheral interrupt for the DRIVER partition. */
void wt_port_conf_irq_set(int on)
{
    if (on != 0) {
        WT_LPUART1_CR1 |= WT_LPUART1_CR1_UE | WT_LPUART1_CR1_TE |
                          WT_LPUART1_CR1_TXEIE;
    }
    else {
        WT_LPUART1_CR1 &= ~WT_LPUART1_CR1_TXEIE;
    }
}
#endif
