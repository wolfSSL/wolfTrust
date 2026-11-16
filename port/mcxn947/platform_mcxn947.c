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

/* MCXN947 (CPU0) port of the shared Armv8-M platform: the SAU and Secure MPU
 * tables and the hooks platform_port.h names. The per-dispatch guest RAM
 * windows are the shared SAU backend. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "mcxn947_regs.h"
#include "fabric_sau.h"
#include "platform_port.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/platform.h"

/* The SAU must agree with the IDAU or the more secure attribute wins. Guest
 * RAM is not a static region: each dispatch opens only the arriving guest's
 * window (dynamic regions below), so the peer's stays Secure while it runs. */
static const wt_armv8m_sau_region_t g_sau_regions[] = {
    { WT_GUEST0_FLASH_BASE,
      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u, false },
    { WT_NSC_BASE, WT_NSC_END, true },
    /* Only the console: the manifest accepts no other Non-secure device grant,
     * so a guest with its MPU off still faults on every other peripheral. */
    { WT_LPUART4_BASE_NS, WT_LPUART4_BASE_NS + 0x00000FFFu, false },
};

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

    /* Region 4: flash NS alias, XN. Writable because the ROM flash driver
     * programs a phrase by storing it through this alias for the FMU to
     * capture; outside a ROM program sequence a store cannot alter flash. */
    { WT_FLASH_NS_BASE, WT_FLASH_NS_BASE + WT_FLASH_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NOCACHE },

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

void wt_port_boot_init(void)
{
}

int wt_port_fabric_init(void)
{
    return 0;
}

/* The guest windows alias the first loader's RAM, dead after the jump; the
 * shared platform has cleared them by now. */
int wt_port_late_init(void)
{
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
    return &wt_fabric_sau_backend;
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* No peripheral drives the PAL line on this part: the request pends it. */
void wt_port_conf_irq_set(int on)
{
    if (on != 0) {
        wt_platform_conf_irq_pend();
    }
}
#endif
