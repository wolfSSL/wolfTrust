/* platform_mcxn947.c
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "memory_map.h"
#include "mcxn947_regs.h"

#include "wolftrust/fabric_windows.h"

#include "wolftrust/ffm_gateway.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/ffm.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/ffm_domain.h"
#include "psa_manifest/pid.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/boot_handoff.h"
#include "wolftrust/services/initial_attestation.h"
#include "wolftrust/arch/armv8m/cmse.h"
#include "wolftrust/sched/tasklet.h"

static volatile uint32_t g_secure_service_depth;
static volatile uint32_t g_hsm_wait_skip_count;

/* The IDAU already marks every bit-28-clear alias Non-secure; the SAU must
 * agree or the more secure attribute wins. The guest RAM extent is NOT a
 * static Non-secure region: each dispatch marks only the arriving guest's
 * window Non-secure through the dynamic regions below, so the peer's window
 * stays Secure by SAU default while it runs, as on the MIMXRT700. */
static const wt_armv8m_sau_region_t g_sau_regions[] = {
    { WT_GUEST0_FLASH_BASE,
      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u, false },
    { WT_NSC_BASE, WT_NSC_END, true },
    /* Only the console: the manifest accepts no other Non-secure device grant,
     * so a guest with its MPU off still faults on every other peripheral. */
    { WT_LPUART4_BASE_NS, WT_LPUART4_BASE_NS + 0x00000FFFu, false },
};

/* Dynamic SAU regions for the per-dispatch guest RAM windows, above the static
 * table (three entries above). CM33 implements eight SAU regions; a guest
 * declares one writable RAM window, so this headroom covers every manifest. */
#define WT_SAU_DYN_FIRST  3u
#define WT_SAU_DYN_LAST   6u

static uint32_t g_sau_dyn_next;

/* Secure-side MPU whitelist, programmed with PRIVDEFENA off by the arch
 * layer and replayed after every Secure Partition domain. */
static const wt_armv8m_mpu_region_t g_mpu_s_whitelist[] = {
    /* Region 0: secure image RX (vectors, NSC stubs, .text, .rodata). */
    { WT_FLASH_S_BASE, WT_FLASH_S_BASE + WT_FLASH_S_SIZE - 1u,
      WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 1: the Secure alias of everything above the image (guest
     * images, update and swap partitions, the wolfHSM and conformance NVM
     * stores): read-only XN, written only through the ROM flash API. */
    { WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE),
      WT_FLASH_S_ALIAS_BASE + WT_FLASH_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NOCACHE },

    /* Region 2: secure RAM RW-NX from the boot handoff record up. */
    { WT_BOOT_HANDOFF_ADDRESS,
      WT_RAM_S_BASE + WT_RAM_S_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 3: NS guest RAM RW-NX through the 0x20000000 alias (HSM
     * transport buffers and fault-response CSRs). */
    { WT_RAM_NS_BASE,
      WT_RAM_NS_BASE + WT_PLATFORM_GUEST_STACK_WINDOW_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 4: flash NS alias, read-only XN for guest image metadata. */
    { WT_FLASH_NS_BASE, WT_FLASH_NS_BASE + WT_FLASH_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 5: peripheral aperture, both aliases (SYSCON, FMU, ELS,
     * LPUART, TRDC, AHBSC). */
    { WT_PERIPH_NS_BASE, WT_PERIPH_S_BASE + WT_PERIPH_ALIAS_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 6: Cortex-M33 private peripheral bus. */
    { 0xE0000000u, 0xE00FFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 7: the boot ROM through its Secure alias, privileged
     * read-execute: the flash API the SPM programs the stores with. */
    { WT_ROM_BASE_S, WT_ROM_BASE_S + WT_ROM_SIZE - 1u,
      WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },
};

/* No hardware guest-flash fence is read back yet, so a guest window is never
 * reported as protected; a WT_GUEST_FLASH_WRP=1 build refuses every guest. */
int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size)
{
    (void)window_base;
    (void)window_size;
    return WT_GUEST_VERIFY_ERROR_WRP;
}

void wt_platform_init(void)
{
    wt_ffm_gateway_install();
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    wt_armv8m_sau_init(g_sau_regions,
                       sizeof(g_sau_regions) / sizeof(g_sau_regions[0]));
    wt_armv8m_mpu_s_init(g_mpu_s_whitelist,
                         sizeof(g_mpu_s_whitelist) /
                         sizeof(g_mpu_s_whitelist[0]));
    wt_arch_init();
    /* The guest windows alias the first loader's RAM, dead after the jump. */
    wt_arch_zero_guest_memory(WT_GUEST0_RAM_BASE, WT_GUEST_RAM_SIZE);
    wt_arch_zero_guest_memory(WT_GUEST1_RAM_BASE, WT_GUEST_RAM_SIZE);
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

/* SAU guest-isolation back-end. close_all disables the dynamic regions so the
 * whole guest RAM extent falls to the SAU default (Secure); open_window marks
 * one guest window Non-secure in the next free dynamic region. A Non-secure
 * store into the peer's now-Secure window raises a SecureFault the monitor
 * contains. Mirrors the STM32H5 GTZC path through the shared window helper. */
static void wt_sau_close_all(void)
{
    uint32_t rnr;

    for (rnr = WT_SAU_DYN_FIRST; rnr <= WT_SAU_DYN_LAST; ++rnr) {
        wt_armv8m_sau_program_region(rnr, 0u, 0u, false, false);
    }
    g_sau_dyn_next = WT_SAU_DYN_FIRST;
}

static void wt_sau_open_window(uintptr_t base, size_t size)
{
    if (g_sau_dyn_next <= WT_SAU_DYN_LAST) {
        wt_armv8m_sau_program_region(g_sau_dyn_next, (uint32_t)base,
                                     (uint32_t)(base + size - 1u), false, true);
        ++g_sau_dyn_next;
    }
}

static void wt_sau_commit(void)
{
    wt_dsb();
    wt_isb();
}

void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count)
{
    static const wt_fabric_windows_t fabric = {
        WT_RAM_NS_BASE,
        WT_RAM_NS_BASE + WT_PLATFORM_GUEST_STACK_WINDOW_SIZE,
        wt_sau_close_all,
        wt_sau_open_window,
        wt_sau_commit
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
    /* Drop the Secure stack limits first: the next boot starts wolfBoot on
     * its own stack below MSPLIM_S, and a core that carried the limit over
     * the reset would fault its first push. */
    __asm volatile("movs r0, #0\n msr msplim, r0\n msr psplim, r0" ::: "r0");
    wt_dsb();
    WT_SCB_AIRCR_S = WT_SCB_AIRCR_SYSRESETREQ;
    wt_dsb();
    for (;;) {
    }
}

#if defined(WT_REMEASURE_PROBE)
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
        int tamper;

        r1 = wt_runtime_verify_guest(0u);
        mpu_ctrl = WT_MPU_S_CTRL;
        WT_MPU_S_CTRL = 0u;
        wt_dsb();
        wt_isb();
        tamper = wt_hsm_flash_remeasure_tamper(WT_FLASH_TO_S_ALIAS(window->base));
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
