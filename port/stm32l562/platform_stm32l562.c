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

#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/arch/armv8m/context.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/fabric_windows.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "stm32l562_regs.h"
#include "gtzc.h"

#include "wolftrust/ffm_gateway.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/ffm.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/ffm_domain.h"
#include "psa_manifest/pid.h"

static volatile uint32_t g_secure_service_depth;
static volatile uint32_t g_hsm_wait_skip_count;

/* The whole guest RAM extent is Non-secure to the SAU, so Secure accesses
 * through the 0x20000000 alias stay Non-secure transactions; the GTZC MPCBB
 * curtain below separates the guests at the bus. */
static const wt_armv8m_sau_region_t g_sau_regions[] = {
    { WT_GUEST0_FLASH_BASE,
      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u, false },
    { WT_RAM_NS_BASE, WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE - 1u, false },
    { WT_FLASH_NSC_BASE, WT_FLASH_NSC_END, true },
    /* The peripheral window skips the RNG page so a guest touching the SPM's
     * RNG through the NS alias takes a precise SecureFault, not a TZSC RAZ. */
    { 0x40000000u, WT_RNG_BASE_NS - 1u, false },
    { WT_RNG_BASE_NS + 0x400u, 0x4FFFFFFFu, false },
};

/* Secure-side MPU whitelist, programmed with PRIVDEFENA off by the arch
 * layer and replayed after every Secure Partition domain. */
static const wt_armv8m_mpu_region_t g_mpu_s_whitelist[] = {
    /* Region 0: secure image RX (vectors, NSC stubs, .text, .rodata). */
    { WT_FLASH_S_BASE, WT_FLASH_S_BASE + WT_FLASH_S_SIZE - 1u,
      WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 1: the NVM stores, update and swap partitions RW-NX and
     * non-cacheable: a program stores the double-word to its flash address
     * with SECCR.PG set, and a verify must read the controller, not a cache. */
    { WT_HSM_NVM_FLASH_BASE_S,
      WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE) - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NOCACHE },

    /* Region 2: secure RAM RW-NX from the boot handoff record up. */
    { WT_BOOT_HANDOFF_ADDRESS,
      WT_RAM_S_BASE + WT_RAM_S_SIZE - 1u,
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

/* The core clock stays at the 110 MHz wolfBoot set; the guests' console is
 * USART1 on PA9/PA10 (AF7), clocked from PCLK2. */
static void wt_console_init(void)
{
    WT_RCC_AHB2ENR |= WT_RCC_AHB2ENR_GPIOAEN;
    WT_RCC_APB2ENR |= WT_RCC_APB2ENR_USART1EN;
    (void)WT_RCC_APB2ENR;
    WT_RCC_CCIPR1 &= ~WT_RCC_CCIPR1_USART1SEL_MASK;
    wt_uart_gpio_pin(WT_GPIOA_BASE_S, 9u, 7u);
    wt_uart_gpio_pin(WT_GPIOA_BASE_S, 10u, 7u);
}

void wt_platform_init(void)
{
    /* Arm the FF-M NS-window checks before any NS guest can reach the
     * WolfTrust_FFM_* veneers; the core fails closed until this runs. */
    wt_ffm_gateway_install();
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    if (wt_l5_gtzc_init() != 0) {
        wt_platform_panic();
    }
    wt_armv8m_sau_init(g_sau_regions,
                       sizeof(g_sau_regions) / sizeof(g_sau_regions[0]));
    wt_armv8m_mpu_s_init(g_mpu_s_whitelist,
                         sizeof(g_mpu_s_whitelist) /
                         sizeof(g_mpu_s_whitelist[0]));
    wt_arch_init();
    wt_console_init();
    /* The guest windows alias wolfBoot's RAM, dead after the jump. */
    wt_arch_zero_guest_memory(WT_GUEST0_RAM_BASE, WT_GUEST0_RAM_SIZE);
    wt_arch_zero_guest_memory(WT_GUEST1_RAM_BASE, WT_GUEST1_RAM_SIZE);
    g_secure_service_depth = 0u;
    g_hsm_wait_skip_count = 0u;
}

#if defined(WT_LAUNCH_DEBUG)
/* Per-guest boot launch-verification result, read over the debug port. */
volatile int32_t g_wt_launch_debug[2] __attribute__((used));

void wt_platform_launch_debug(int code, uint32_t guest)
{
    if (guest < (sizeof(g_wt_launch_debug) / sizeof(g_wt_launch_debug[0]))) {
        g_wt_launch_debug[guest] = (int32_t)code;
    }
}
#endif

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

void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count)
{
    static const wt_fabric_windows_t fabric = {
        WT_RAM_NS_BASE,
        WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE,
        wt_gtzc_close_all,
        wt_gtzc_open_window,
        wt_gtzc_commit
    };

    wt_fabric_apply_windows(&fabric, windows, count);
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* PAL interrupt source: the unprivileged DRIVER partition asks for its line
 * to fire, so the privileged side pends it in the NVIC. */
void wt_conf_uart_irq_set(int on)
{
    if (on != 0) {
#if WT_CONF_IRQ >= 32u
        WT_NVIC_ISPR1 = (1u << (WT_CONF_IRQ - 32u));
#else
        WT_NVIC_ISPR0 = (1u << WT_CONF_IRQ);
#endif
    }
    else {
        wt_arch_secure_irq_disable(WT_CONF_IRQ);
    }
}

void WT_CONF_IRQ_HANDLER(void)
{
    wt_spm_conf_irq(WT_CONF_IRQ);
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

void wt_platform_system_reset(void)
{
    uint32_t spins = 0u;

    /* A flash program issued just before this reset must land before
     * SYSRESETREQ cuts it short; bounded so a wedged controller still resets. */
    while ((WT_FLASH_SECSR & WT_FLASH_SR_BSY) != 0u && spins < 0x00200000u) {
        spins++;
    }
    /* Drop the Secure stack limits first: the next boot starts wolfBoot on
     * its own stack below MSPLIM_S. */
    __asm volatile("movs r0, #0\n msr msplim, r0\n msr psplim, r0" ::: "r0");
    wt_dsb();
    WT_SCB_AIRCR_S = WT_SCB_AIRCR_SYSRESETREQ;
    wt_dsb();
    for (;;) {
    }
}

#if defined(WT_REMEASURE_PROBE)
extern int wt_hsm_flash_remeasure_tamper(uintptr_t ns_base);

void wt_platform_remeasure_probe(void)
{
    const wt_guest_config_t *configs;
    size_t cfg_count;
    const wt_memory_window_t *window = NULL;
    uint32_t mpu_ctrl;
    size_t i;
    int r1;
    int r2;
    int tamper;

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
        tamper = wt_hsm_flash_remeasure_tamper(window->base);
        WT_MPU_S_CTRL = mpu_ctrl;
        wt_dsb();
        wt_isb();
        r2 = wt_runtime_verify_guest(0u);
        /* The verdict needs the tamper to have landed: a driver error must
         * not pass as a detected tamper. */
        if (r1 == 0 && tamper == 0 && r2 != 0) {
            __asm volatile("bkpt #0x6C");
        }
    }
    for (;;) {
        __asm volatile("wfi");
    }
}
#endif

#if defined(WT_BOOTUPDATE_PROBE)
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
}
#endif

#ifdef WT_ENGINE_HSM

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
