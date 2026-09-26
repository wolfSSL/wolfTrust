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
#include "mimxrt798_regs.h"

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
#include "wolfhsm/wh_error.h"

static volatile uint32_t g_secure_service_depth;
static volatile uint32_t g_hsm_wait_skip_count;

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

/* The XSPI0 NOR has no hardware write-protect claim wired yet, so a guest
 * window is never reported as protected. */
int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size)
{
    (void)window_base;
    (void)window_size;
    return WT_GUEST_VERIFY_ERROR_WRP;
}

volatile void* wt_platform_boot_handoff_region(size_t* size)
{
    *size = WT_RAM_S_BASE - WT_BOOT_HANDOFF_ADDRESS;
    return (volatile void*)WT_BOOT_HANDOFF_ADDRESS;
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

void wt_platform_init(void)
{
    size_t i;
    uint32_t* src;
    uint32_t* dst;

    /* Mark the Secure runtime bank (P11) and the RAM code band (first rule of
     * P12) Secure-only at the fabric, as NXP's TrustZone setup does; not yet
     * proven to stop other bus masters. The band is written through the
     * Secure data alias of its execution address. */
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
    wt_ffm_gateway_install();
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    wt_armv8m_sau_init(g_sau_regions,
                       sizeof(g_sau_regions) / sizeof(g_sau_regions[0]));
    wt_armv8m_mpu_s_init(g_mpu_s_whitelist,
                         sizeof(g_mpu_s_whitelist) /
                         sizeof(g_mpu_s_whitelist[0]));
    wt_arch_init();
    wt_arch_zero_guest_memory(WT_GUEST0_RAM_BASE, WT_GUEST_RAM_SIZE);
    wt_arch_zero_guest_memory(WT_GUEST1_RAM_BASE, WT_GUEST_RAM_SIZE);
    /* Checking keeps the guests off the fabric's own rule registers. */
    if (wt_ahbsc_enable_checking() != 0) {
        wt_platform_panic();
    }
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
/* PAL interrupt source: the unprivileged DRIVER partition asks for its line
 * to fire, so the privileged side pends it in the NVIC. */
void wt_conf_uart_irq_set(int on)
{
    if (on != 0) {
        WT_NVIC_ISPR0 = (1u << WT_CONF_IRQ);
    }
    else {
        wt_arch_secure_irq_disable(WT_CONF_IRQ);
    }
}

void WT_CONF_IRQ_HANDLER(void)
{
    wt_spm_conf_irq(WT_CONF_IRQ);
}

extern char _s_conf_server_data[];
extern char _e_conf_server_data[];
extern char _s_conf_driver_data[];
extern char _e_conf_driver_data[];

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

void wt_platform_system_reset(void)
{
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
