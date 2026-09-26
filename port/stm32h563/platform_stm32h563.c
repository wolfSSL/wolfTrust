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

#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/arch/armv8m/context.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/fabric_windows.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wolfHAL/clock/stm32h5_rcc.h>
#include <wolfHAL/platform/st/stm32h563xx.h>
#include <wolfHAL/reg.h>

#include "memory_map.h"
#include "stm32h563_regs.h"

#include "wolftrust/ffm_gateway.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/ffm.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/ffm_domain.h"
#include "psa_manifest/pid.h"

void* memcpy(void* destination, const void* source, size_t size);
void* memset(void* destination, int value, size_t size);

#ifdef WT_ENGINE_HSM
#include "wolftrust/services/hsm.h"
#include "wolftrust/boot_handoff.h"
#include "wolftrust/services/initial_attestation.h"
#include <string.h>
#include "wolftrust/arch/armv8m/cmse.h"
#include "wolftrust/sched/tasklet.h"
#include "wolfhsm/wh_error.h"

#endif /* WT_ENGINE_HSM */

static volatile uint32_t g_secure_service_depth;
static volatile uint32_t g_hsm_wait_skip_count;

static const wt_armv8m_sau_region_t g_sau_regions[] = {
    { WT_GUEST0_FLASH_BASE,
      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u, false },
    { WT_RAM_NS_BASE, WT_RAM_NS_BASE + 0x0009FFFFu, false },
    { WT_FLASH_NSC_BASE, WT_FLASH_NSC_END, true },
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

    /* Region 2: secure RAM RW-NX (.data/.bss/MSP_S + coroutine stacks). */
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    { WT_BOOT_HANDOFF_ADDRESS,
#else
    { WT_RAM_S_BASE,
#endif
      WT_RAM_S_BASE + WT_RAM_S_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 3: NS RAM RW-NX. Secure code touches this through the
     * 0x20000000 alias to exchange HSM transport buffers with guests
     * and to write fault-response CSRs. */
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

#ifdef WT_ENGINE_HSM
static void wt_secure_service_enter(void);
static void wt_secure_service_exit(void);
#endif

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

static void wt_gtzc_init(void)
{
    size_t i;
    size_t nsWords = (WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE -
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
    WT_GTZC1_TZSC_SECCFGR3 |= (WT_GTZC_SECCFGR3_HASHSEC |
                               WT_GTZC_SECCFGR3_RNGSEC |
                               WT_GTZC_SECCFGR3_PKASEC);

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
}

volatile void* wt_platform_boot_handoff_region(size_t* size)
{
    *size = WT_RAM_S_BASE - WT_BOOT_HANDOFF_ADDRESS;
    return (volatile void*)WT_BOOT_HANDOFF_ADDRESS;
}

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

void wt_platform_init(void)
{
    static const whal_Stm32h5_Rcc_PeriphClk uart_clocks[] = {
        {WHAL_STM32H563_USART2_CLOCK},
        {WHAL_STM32H563_USART3_CLOCK},
    };
    static const whal_Stm32h5_Rcc_PeriphClk rng_clock =
        {WHAL_STM32H563_RNG_CLOCK};

    wt_clock_init();
    /* Arm the FF-M NS-window checks before any NS guest can reach the
     * WolfTrust_FFM_* veneers; the core fails closed until this runs. */
    wt_ffm_gateway_install();
    /* The signed wolfBoot handoff reserves the manifest header at the slot
     * base; the Secure vector table begins at the image base after it. */
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    wt_gtzc_init();
    wt_armv8m_sau_init(g_sau_regions,
                       sizeof(g_sau_regions) / sizeof(g_sau_regions[0]));
    wt_armv8m_mpu_s_init(g_mpu_s_whitelist,
                         sizeof(g_mpu_s_whitelist) /
                         sizeof(g_mpu_s_whitelist[0]));
    wt_arch_init();
    /* Enable USART2/USART3 clocks in both security views before guests run. */
    for (size_t i = 0u; i < sizeof(uart_clocks) / sizeof(uart_clocks[0]); ++i) {
        wt_rcc_enable_clock(WT_RCC_BASE_S, &uart_clocks[i]);
        wt_rcc_enable_clock(WT_RCC_BASE_NS, &uart_clocks[i]);
    }
    wt_rcc_enable_clock(WT_RCC_BASE_S, &rng_clock);
    wt_uart_gpio_init();
    wt_arch_zero_guest_memory(WT_GUEST0_RAM_BASE, WT_GUEST_RAM_SIZE);
    wt_arch_zero_guest_memory(WT_GUEST1_RAM_BASE, WT_GUEST_RAM_SIZE);
    g_secure_service_depth = 0u;
    g_hsm_wait_skip_count = 0u;
}

/* GTZC curtain (cross-guest isolation): NS guest kernels run privileged, so
 * the per-guest NS MPU alone cannot stop a hostile guest from reprogramming
 * MPU_NS and reaching the peer's RAM. Every dispatch closes the whole shared
 * guest RAM extent at the fabric (blocks marked Secure reject Non-secure
 * transactions regardless of privilege) and reopens only the arriving
 * guest's declared writable windows. */
static void wt_gtzc_close_all(void)
{
    uintptr_t extent_end = WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE;
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

void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count)
{
    static const wt_fabric_windows_t fabric = {
        WT_RAM_NS_BASE,
        WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE,
        wt_gtzc_close_all,
        wt_gtzc_open_window,
        wt_gtzc_commit
    };

    wt_fabric_apply_windows(&fabric, windows, count);
}

/* End of executable image code (secure.ld): the SP thread tables grant RX up
 * to here (the manifest's 4K code window lies inside it and Armv8-M regions
 * must not overlap — task #26 tracks per-partition narrowing) and the rest of
 * the image window (constant data and the signed tail) read-only XN
 * (WT-FFM-0010). */
extern char _e_secure_text[];

size_t wt_platform_sp_shared_regions(wt_memory_region_t* regions, size_t max)
{
    if (max < 2u) {
        return 0u;
    }
    regions[0].base = WT_FLASH_S_BASE;
    regions[0].size = (uintptr_t)_e_secure_text - WT_FLASH_S_BASE;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    regions[1].base = (uintptr_t)_e_secure_text;
    regions[1].size = WT_FLASH_S_BASE + WT_FLASH_S_SIZE -
                      (uintptr_t)_e_secure_text;
    regions[1].attributes = WT_MEM_ATTR_READ;
    return 2u;
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Per-partition private data bands (secure.ld), each denied to other SPs. */
extern char _s_conf_server_data[];
extern char _e_conf_server_data[];
extern char _s_conf_driver_data[];
extern char _e_conf_driver_data[];

/* Append one RW grant segment to an SP's thread table (skips empty segments,
 * fails closed by granting nothing when the table is full). */
static size_t wt_conf_grant(wt_memory_region_t* regions, size_t count,
                            size_t max, uintptr_t base, uintptr_t end)
{
    if (base < end && count < max) {
        regions[count].base = base;
        regions[count].size = (uint32_t)(end - base);
        regions[count].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
        count++;
    }
    return count;
}

/* Hosted Arm partitions read their val_api/psa_api tables from .data, which
 * the linker places in the shared CONFDATA window; grant it so the SP
 * reaches its own data while SPM RAM stays denied. The per-partition
 * pseudo-MMIO holes at the top of the window (memory_map.h) each belong to
 * exactly one partition — every other SP gets the window with that hole
 * carved out, so the L3 MMIO-isolation panic tests (i047/i055/i057) hit a
 * genuine out-of-domain access and the must-panic reset path fires. Also
 * carve the per-partition data bands (i080/i084): a cross-partition read of
 * another SP's .data/.bss must fault. Bands are adjacent, so a non-owner's
 * empty middle segment is skipped by wt_conf_grant. */
size_t wt_platform_conf_sp_grants(int32_t partition_id,
                                  wt_memory_region_t* regions,
                                  size_t count, size_t max)
{
    uintptr_t conf_seg = WT_CONF_SP_DATA_BASE;

    if (partition_id != SERVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              (uintptr_t)_s_conf_server_data);
        conf_seg = (uintptr_t)_e_conf_server_data;
    }
    if (partition_id != DRIVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              (uintptr_t)_s_conf_driver_data);
        conf_seg = (uintptr_t)_e_conf_driver_data;
    }
    if (partition_id != SERVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              WT_CONF_SERVER_MMIO_BASE);
        conf_seg = WT_CONF_SERVER_MMIO_BASE + WT_CONF_SERVER_MMIO_SIZE;
    }
    if (partition_id != DRIVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              WT_CONF_DRV_MMIO_BASE);
        conf_seg = WT_CONF_DRV_MMIO_BASE + WT_CONF_DRV_MMIO_SIZE;
    }
    count = wt_conf_grant(regions, count, max, conf_seg,
                          WT_CONF_SP_DATA_BASE + WT_CONF_SP_DATA_SIZE);
    return count;
}
#endif

#if (defined(WT_FFM_NEGATIVE_PROBE) && (WT_FFM_NEGATIVE_PROBE == 1)) || \
    (defined(WT_VNET_NEG_PROBE) && (WT_VNET_NEG_PROBE == 1)) || \
    (defined(WT_KEYSTORE_NEG_PROBE) && (WT_KEYSTORE_NEG_PROBE == 1))
uintptr_t wt_platform_probe_address(unsigned int target)
{
    switch (target) {
    case WT_PROBE_KEYSTORE_BAND:
        return (uintptr_t)WT_KEYSTORE_BASE;
#if defined(CONFIG_VNET)
    case WT_PROBE_VNET_DATA_BAND:
        return (uintptr_t)WT_VNET_DATA_BASE;
#endif
    default:
        return (uintptr_t)WT_RAM_S_BASE;
    }
}
#endif

void wt_platform_log_fault(wt_guest_id_t guest_id,
                           wt_fault_reason_t reason,
                           uintptr_t fault_address,
                           uintptr_t pc)
{
    (void)guest_id;
    (void)reason;
    wt_armv8m_note_fault(fault_address, pc);
}

void wt_platform_all_guests_faulted(void)
{
    __asm volatile("bkpt #0x7D");
    for (;;) {
        __asm volatile("wfi");
    }
}

void wt_platform_panic(void)
{
    __asm volatile("bkpt #0x7E");
    for (;;) {
    }
}

#ifdef WT_LAUNCH_DEBUG
/* Temporary launch-verify triage: one distinct BKPT per failure reason so the
 * emulator log names the guest and error. Never built into production. */
void wt_platform_launch_debug(int code, uint32_t guest)
{
    unsigned int index = (unsigned int)(-700 - code);

    if (index > 5u) {
        index = 6u;
    }
    switch (index + (guest * 8u)) {
        case 0u:  __asm volatile("bkpt #0x50"); break;
        case 1u:  __asm volatile("bkpt #0x51"); break;
        case 2u:  __asm volatile("bkpt #0x52"); break;
        case 3u:  __asm volatile("bkpt #0x53"); break;
        case 4u:  __asm volatile("bkpt #0x54"); break;
        case 5u:  __asm volatile("bkpt #0x55"); break;
        case 8u:  __asm volatile("bkpt #0x58"); break;
        case 9u:  __asm volatile("bkpt #0x59"); break;
        case 10u: __asm volatile("bkpt #0x5A"); break;
        case 11u: __asm volatile("bkpt #0x5B"); break;
        case 12u: __asm volatile("bkpt #0x5C"); break;
        case 13u: __asm volatile("bkpt #0x5D"); break;
        default:  __asm volatile("bkpt #0x5F"); break;
    }
}
#endif

void wt_platform_system_reset(void)
{
    uint32_t spins = 0u;

    /* A flash program issued just before this reset - the conformance boot
     * flag val resumes from, an anti-rollback arming store - must physically
     * land before SYSRESETREQ, or the reset can cut it short and the value is
     * lost (on silicon the panic test then re-runs into a reboot loop; the
     * emulator programs flash instantly and never sees it). Wait for the flash
     * controller to go idle, bounded so a wedged controller still resets. */
    while ((WT_FLASH_SR & (WT_FLASH_SR_BSY | WT_FLASH_SR_DBNE)) != 0u &&
            spins < 0x00200000u) {
        spins++;
    }
    wt_dsb();
    WT_SCB_AIRCR_S = WT_SCB_AIRCR_SYSRESETREQ;
    wt_dsb();
    for (;;) {
    }
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* PAL interrupt source (P4.2c): LPUART1 with TXEIE raises its NVIC line as
 * soon as the transmitter is enabled (TXE idles high), giving the DRIVER
 * partition a real peripheral interrupt to receive and acknowledge. */
void wt_conf_uart_irq_set(int on)
{
    if (on != 0) {
        WT_LPUART1_CR1 |= WT_LPUART1_CR1_UE | WT_LPUART1_CR1_TE |
                          WT_LPUART1_CR1_TXEIE;
    } else {
        WT_LPUART1_CR1 &= ~WT_LPUART1_CR1_TXEIE;
        wt_arch_secure_irq_disable(WT_LPUART1_IRQ);
    }
}

void LPUART1_IRQHandler(void)
{
    wt_spm_conf_irq(WT_LPUART1_IRQ);
}
#endif

#if defined(WT_REMEASURE_PROBE)
/* P6-S5: prove on-demand runtime re-measurement (WT-FFM-0052) on target. After
 * boot init and launch verification, an untampered re-measure of guest0 must
 * pass; a post-launch in-flash tamper (the secure MPU maps flash
 * privileged-RO, so it is dropped for the single program) must then be caught
 * and quarantine the guest. bkpt #0x6C fires only when both are correct. */
extern int wt_hsm_flash_remeasure_tamper(uintptr_t secure_base);

void wt_platform_remeasure_probe(void)
{
    const wt_guest_config_t *configs;
    size_t cfg_count;
    const wt_memory_window_t *window = NULL;
    uint32_t mpu_ctrl;
    size_t i;
    int r1;
    int r2;

    configs = wt_partitions_config_table(&cfg_count);
    if (configs != NULL && cfg_count > 0u) {
        for (i = 0u; i < configs[0].memory_window_count; i++) {
            if ((configs[0].memory_windows[i].attributes &
                    WT_MEM_ATTR_EXEC) != 0u) {
                window = &configs[0].memory_windows[i];
                break;
            }
        }
    }
    if (window != NULL) {
        r1 = wt_runtime_verify_guest(0u);
        mpu_ctrl = WT_MPU_S_CTRL;
        WT_MPU_S_CTRL = 0u;
        wt_dsb();
        wt_isb();
        (void)wt_hsm_flash_remeasure_tamper(WT_FLASH_TO_S_ALIAS(window->base));
        WT_MPU_S_CTRL = mpu_ctrl;
        wt_dsb();
        wt_isb();
        r2 = wt_runtime_verify_guest(0u);
        /* WT_GUEST_VERIFY_OK == 0: a pass then a fail-closed is the only
         * correct outcome. */
        if (r1 == 0 && r2 != 0) {
            __asm volatile("bkpt #0x6C");
        }
    }
    for (;;) {
        __asm volatile("wfi");
    }
}
#endif

#if defined(WT_BOOTUPDATE_PROBE)
/* P6-S6: full boot-and-update gate. On the pre-update image (version 1) arm
 * wolfBoot's real update trigger for the v2 candidate pre-staged in the UPDATE
 * partition, then reboot so wolfBoot swaps it in; the swapped-in v2 (version 2)
 * skips the arm, so the swap terminates instead of looping. The secure MPU
 * maps flash privileged-RO, so it is dropped for the single trailer program
 * (as in the S5 re-measure probe). */
#include "wolftrust/services/fwu_service.h"
extern const wt_fwu_backend_t wt_fwu_flash_backend;

void wt_platform_bootupdate_probe(uint32_t running_version)
{
    uint32_t mpu_ctrl;
    int armed = -1;

    if (running_version != 1u) {
        return;
    }
    if (wt_fwu_flash_backend.begin != NULL &&
            wt_fwu_flash_backend.begin(NULL) == 0 &&
            wt_fwu_flash_backend.arm != NULL) {
        mpu_ctrl = WT_MPU_S_CTRL;
        WT_MPU_S_CTRL = 0u;
        wt_dsb();
        wt_isb();
        armed = wt_fwu_flash_backend.arm(NULL, 0u, 2u);
        WT_MPU_S_CTRL = mpu_ctrl;
        wt_dsb();
        wt_isb();
    }
    if (armed == 0) {
        wt_platform_system_reset();
    }
    /* Arm failed: fall through to a normal boot so the miss is observable
     * (the token's v2 measurement will be absent) instead of a reboot loop. */
}
#endif

#ifdef WT_ENGINE_HSM

static void wt_secure_service_enter(void)
{
    g_secure_service_depth++;
}

static void wt_secure_service_exit(void)
{
    if (g_secure_service_depth == 0u) {
        wt_platform_panic();
    }
    g_secure_service_depth--;
}

bool wt_platform_secure_service_active(void)
{
    return g_secure_service_depth != 0u;
}

void wt_platform_note_hsm_wait_skip(wt_guest_id_t guest_id)
{
    (void)guest_id;
    g_hsm_wait_skip_count++;
}

#endif /* WT_ENGINE_HSM */
