/* platform_mimxrt700.c
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

/* MIMXRT700 (cpu0) port of the shared Armv8-M platform: the SAU and Secure
 * MPU tables, the RAM code band staging, the AHBSC fabric rules behind their
 * GLIKEY unlock, the XSPI guest fence read-back and the hooks platform_port.h
 * names. The per-dispatch guest RAM windows are the shared SAU backend. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "mimxrt798_regs.h"
#include "fabric_sau.h"
#include "platform_port.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/platform.h"

/* The IDAU already marks every bit-28-clear alias Non-secure; the SAU must
 * agree or the more secure attribute wins. The guest RAM extent is NOT a
 * static Non-secure region: per the RT700 reference manual the AHB secure
 * controller does not gate CPU0, so the SAU is the CPU's guest-isolation layer.
 * Each dispatch marks only the arriving guest's RAM window Non-secure through
 * the dynamic regions below, leaving the peer's window Secure by SAU default. */
static const wt_armv8m_sau_region_t g_sau_regions[] = {
    { WT_GUEST0_FLASH_BASE,
      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u, false },
    { WT_NSC_BASE, WT_NSC_END, true },
    /* Only the console: the manifest accepts no other Non-secure device grant,
     * so a guest with its MPU off still faults on every other peripheral. */
    { WT_LPUART0_BASE_NS, WT_LPUART0_BASE_NS + 0x00000FFFu, false },
};

/* Secure-side MPU whitelist, programmed with PRIVDEFENA off by the arch
 * layer and replayed after every Secure Partition domain. */
static const wt_armv8m_mpu_region_t g_mpu_s_whitelist[] = {
    /* Region 0: secure image RX (vectors, NSC stubs, .text, .rodata). */
    { WT_FLASH_S_BASE, WT_FLASH_S_BASE + WT_FLASH_S_SIZE - 1u,
      WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 1: XSPI0 update partition + wolfHSM NVM + conformance NVM,
     * plus the Secure alias of the guest images: read-only XN (the NOR is
     * only ever written through XSPI IP commands) and non-cacheable so a
     * verify after a program reads the NOR. */
    { WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE),
      WT_CONF_NVM_FLASH_BASE_S + WT_CONF_NVM_FLASH_SIZE - 1u,
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

    /* Region 4: XSPI0 NS alias, read-only XN for guest image metadata. */
    { WT_FLASH_NS_BASE, WT_FLASH_NS_BASE + 0x001FFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },

    /* Region 5: peripheral aperture, both aliases (AHBSC, XSPI, TRNG,
     * LPUART, clock and reset control). */
    { WT_PERIPH_NS_BASE, WT_PERIPH_S_BASE + WT_PERIPH_ALIAS_SIZE - 1u,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 6: Cortex-M33 private peripheral bus. */
    { 0xE0000000u, 0xE00FFFFFu,
      WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
      WT_MPU_RLAR_ATTRIDX_DEVICE },

    /* Region 7: RAM code band through the Secure Code alias (NSC gateway
     * and NOR program/erase code), privileged read-execute; the only
     * executable RAM in the Secure map. */
    { WT_RAMFUNC_BASE, WT_RAMFUNC_BASE + WT_RAMFUNC_SIZE - 1u,
      WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
      WT_MPU_RLAR_ATTRIDX_NORMAL },
};

extern uint32_t _siramfunc[];
extern uint32_t _sramfunc[];
extern uint32_t _eramfunc[];

/* wolfBoot arms the XSPI SFP fence each boot and locks it until the next hard
 * reset; this only trusts what the registers read back, never programs them. */
int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size)
{
    wt_frad_region_t regions[WT_XSPI_FRAD_COUNT];
    uint32_t mgc;
    uint32_t mdad;
    uint32_t word3;
    uint32_t lock;
    uint32_t i;
    int ret = WT_GUEST_VERIFY_OK;

    mgc = WT_XSPI0_MGC;
    mdad = WT_XSPI0_TG0MDAD;
    if ((mgc & (WT_XSPI_MGC_GVLD | WT_XSPI_MGC_GVLDFRAD |
                WT_XSPI_MGC_GVLDMDAD)) !=
            (WT_XSPI_MGC_GVLD | WT_XSPI_MGC_GVLDFRAD | WT_XSPI_MGC_GVLDMDAD) ||
            (mgc & WT_XSPI_MGC_GCLCK) == 0u ||
            (mdad & (WT_XSPI_TG0MDAD_VLD | WT_XSPI_TG0MDAD_LCK)) !=
            (WT_XSPI_TG0MDAD_VLD | WT_XSPI_TG0MDAD_LCK)) {
        ret = WT_GUEST_VERIFY_ERROR_WRP;
    }

    if (ret == WT_GUEST_VERIFY_OK) {
        for (i = 0u; i < WT_XSPI_FRAD_COUNT; i++) {
            word3 = WT_XSPI0_FRAD_WORD(i, 3u);
            lock = word3 & WT_XSPI_FRAD_WORD3_LOCK;
            regions[i].start = WT_XSPI0_FRAD_WORD(i, 0u) &
                               WT_XSPI_FRAD_ADDR_MASK;
            regions[i].end = (WT_XSPI0_FRAD_WORD(i, 1u) &
                              WT_XSPI_FRAD_ADDR_MASK) |
                             ~WT_XSPI_FRAD_ADDR_MASK;
            regions[i].write_acp = WT_XSPI0_FRAD_WORD(i, 2u) &
                                   WT_XSPI_FRAD_WORD2_ACP;
            regions[i].valid = word3 & WT_XSPI_FRAD_WORD3_VLD;
            regions[i].locked = ((lock == WT_XSPI_FRAD_LOCK_HARD ||
                                  lock == WT_XSPI_FRAD_LOCK_FULL) &&
                                 (word3 & WT_XSPI_FRAD_WORD3_EAL) == 0u) ?
                                1u : 0u;
        }
        ret = wt_guest_flash_frad_covers(regions, WT_XSPI_FRAD_COUNT,
                                         window_base, window_size);
    }

    return ret;
}

static int wt_glikey_write_enable(uintptr_t base, uint32_t index)
{
    static const uint32_t codewords[] = {
        WT_GLIKEY_CODEWORD_STEP1, WT_GLIKEY_CODEWORD_STEP2,
        WT_GLIKEY_CODEWORD_STEP3, WT_GLIKEY_CODEWORD_EN
    };
    uint32_t value;
    size_t i;
    int ret = 0;

    if (((WT_GLIKEY_CTRL_1(base) & WT_GLIKEY_CTRL_1_SFR_LOCK_MASK) >>
            WT_GLIKEY_CTRL_1_SFR_LOCK_SHIFT) != WT_GLIKEY_SFR_UNLOCKED) {
        ret = -1;
    }
    if (ret == 0) {
        WT_GLIKEY_CTRL_0(base) |= WT_GLIKEY_CTRL_0_SFT_RST;
        WT_GLIKEY_CTRL_0(base) = (index & WT_GLIKEY_CTRL_0_INDEX_MASK) |
                                 (1u << WT_GLIKEY_CTRL_WR_EN_SHIFT);
        WT_GLIKEY_CTRL_1(base) &= ~WT_GLIKEY_CTRL_WR_EN_MASK;
    }
    for (i = 0u; ret == 0 && i < sizeof(codewords) / sizeof(codewords[0]);
         ++i) {
        /* The top byte selects the control register the 2-bit step lands in. */
        if ((codewords[i] >> 24) == WT_GLIKEY_CODEWORD_SEL_CTRL_1) {
            value = ((codewords[i] >> 16) & 0x3u) << WT_GLIKEY_CTRL_WR_EN_SHIFT;
            WT_GLIKEY_CTRL_1(base) = (WT_GLIKEY_CTRL_1(base) &
                                      ~WT_GLIKEY_CTRL_WR_EN_MASK) | value;
        }
        else {
            value = (codewords[i] & 0x3u) << WT_GLIKEY_CTRL_WR_EN_SHIFT;
            WT_GLIKEY_CTRL_0(base) = (WT_GLIKEY_CTRL_0(base) &
                                      ~WT_GLIKEY_CTRL_WR_EN_MASK) | value;
        }
        if ((WT_GLIKEY_STATUS(base) & WT_GLIKEY_STATUS_ERROR_MASK) != 0u) {
            ret = -1;
        }
    }
    if (ret == 0 && (WT_GLIKEY_STATUS(base) >> WT_GLIKEY_STATUS_FSM_SHIFT) !=
            WT_GLIKEY_FSM_WR_EN) {
        ret = -1;
    }
    return ret;
}

/* Reset leaves AHBSC0 secure checking off, so no memory or peripheral rule is
 * enforced until MISC_CTRL (and its duplicate) turn it on behind GLIKEY0. */
static int wt_ahbsc_enable_checking(void)
{
    uint32_t misc;
    uint32_t misc_dp;
    int ret;

    WT_AHBSC0_AHB_PERIPHERAL0_SLAVE_RULE1 &= ~WT_AHBSC0_RULE_LP_FLEXCOMM0_MASK;
    ret = wt_glikey_write_enable(WT_GLIKEY0_BASE_S,
                                 WT_GLIKEY0_INDEX_MISC_CTRL);
    if (ret == 0) {
        WT_AHBSC_MISC_CTRL_REG(WT_AHBSC0_BASE_S) =
            (WT_AHBSC_MISC_CTRL_REG(WT_AHBSC0_BASE_S) &
             ~WT_AHBSC_MISC_CTRL_CHECK_MASK) | WT_AHBSC_MISC_CTRL_CHECK_ON;
        WT_AHBSC_MISC_CTRL_DP_REG(WT_AHBSC0_BASE_S) =
            (WT_AHBSC_MISC_CTRL_DP_REG(WT_AHBSC0_BASE_S) &
             ~WT_AHBSC_MISC_CTRL_CHECK_MASK) | WT_AHBSC_MISC_CTRL_CHECK_ON;
    }
    WT_GLIKEY_CTRL_0(WT_GLIKEY0_BASE_S) |= WT_GLIKEY_CTRL_0_SFT_RST;
    wt_dsb();
    wt_isb();
    misc = WT_AHBSC_MISC_CTRL_REG(WT_AHBSC0_BASE_S);
    misc_dp = WT_AHBSC_MISC_CTRL_DP_REG(WT_AHBSC0_BASE_S);
    if (ret == 0 &&
            ((misc & WT_AHBSC_MISC_CTRL_CHECK_MASK) !=
                 WT_AHBSC_MISC_CTRL_CHECK_ON ||
             (misc_dp & WT_AHBSC_MISC_CTRL_CHECK_MASK) !=
                 WT_AHBSC_MISC_CTRL_CHECK_ON)) {
        ret = -1;
    }
    return ret;
}

/* Mark the Secure runtime bank and the RAM code band Secure-only at the
 * fabric, as NXP's TrustZone setup does (not yet proven to stop other bus
 * masters), then stage the band through the Secure data alias of its
 * execution address before anything runs from it. */
void wt_port_boot_init(void)
{
    size_t i;
    uint32_t* src;
    uint32_t* dst;

    for (i = 0u; i < 4u; ++i) {
        WT_AHBSC0_SRAM11_RULE(i) = WT_AHBSC_RULE_ALL_SECURE;
    }
    WT_AHBSC0_SRAM12_RULE(0u) = WT_AHBSC_RULE_ALL_SECURE;
    src = _siramfunc;
    for (dst = _sramfunc; dst < _eramfunc; ++dst) {
        *(uint32_t*)((uintptr_t)dst + WT_SRAM_CODE_TO_DATA) = *src;
        ++src;
    }
    wt_dsb();
    wt_isb();
}

int wt_port_fabric_init(void)
{
    return 0;
}

/* Checking keeps the guests off the fabric's own rule registers. */
int wt_port_late_init(void)
{
    return wt_ahbsc_enable_checking();
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
