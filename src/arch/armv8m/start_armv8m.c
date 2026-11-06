/* start_armv8m.c
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


/* Armv8-M reset entry: initialize the image's data and bss (including the
 * conformance, per-partition, and vnet bands the linker script places in
 * their own MPU-granted windows), then enter the neutral boot sequence. */

#include "wolftrust/arch.h"
#include "wolftrust/boot.h"
#include "wolftrust/platform.h"
#include "wolftrust/arch/armv8m/core_regs.h"

#include <stddef.h>
#include <stdint.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _siconfdata;
extern uint32_t _sconfdata;
extern uint32_t _econfdata;
extern uint32_t _sconfbss;
extern uint32_t _econfbss;
extern uint32_t _si_vault;
extern uint32_t _s_vault;
extern uint32_t _e_vault_data;
extern uint32_t _s_vault_bss;
extern uint32_t _e_vault;
extern uint32_t _si_attest;
extern uint32_t _s_attest;
extern uint32_t _e_attest_data;
extern uint32_t _s_attest_bss;
extern uint32_t _e_attest;
extern uint32_t _si_hsm;
extern uint32_t _s_hsm;
extern uint32_t _e_hsm_data;
extern uint32_t _s_hsm_bss;
extern uint32_t _e_hsm;
#if defined(CONFIG_VNET)
extern uint32_t _si_vnet;
extern uint32_t _s_vnet;
extern uint32_t _e_vnet_data;
extern uint32_t _s_vnet_bss;
extern uint32_t _e_vnet;
#endif
#if defined(CONFIG_TPM)
extern uint32_t _si_tpm;
extern uint32_t _s_tpm;
extern uint32_t _e_tpm_data;
extern uint32_t _s_tpm_bss;
extern uint32_t _e_tpm;
#endif
#if defined(CONFIG_PKCS11)
extern uint32_t _si_pkcs11;
extern uint32_t _s_pkcs11;
extern uint32_t _e_pkcs11_data;
extern uint32_t _s_pkcs11_bss;
extern uint32_t _e_pkcs11;
#endif

extern uint32_t _wt_part_stacks_base;
extern uint32_t _wt_part_stacks_limit;
extern uint32_t _wt_sp_stacks_base;
extern uint32_t _wt_sp_stacks_limit;
#if defined(CONFIG_TPM)
extern uint32_t _wt_tpm_stack_base;
extern uint32_t _wt_tpm_stack_limit;
#endif
#if defined(CONFIG_PKCS11)
extern uint32_t _wt_pkcs11_stack_base;
extern uint32_t _wt_pkcs11_stack_limit;
#endif

/* Bytes of partition band and stack RAM zeroed at reset, read over SWD. */
volatile uint32_t g_wt_boot_zeroed_bytes;

extern uint32_t _wt_band_vault_base;
extern uint32_t _wt_band_vault_limit;
extern uint32_t _wt_band_attest_base;
extern uint32_t _wt_band_attest_limit;
extern uint32_t _wt_band_hsm_base;
extern uint32_t _wt_band_hsm_limit;
#if defined(CONFIG_VNET)
extern uint32_t _wt_band_vnet_base;
extern uint32_t _wt_band_vnet_limit;
#endif
#if defined(CONFIG_TPM)
extern uint32_t _wt_band_tpm_base;
extern uint32_t _wt_band_tpm_limit;
#endif
#if defined(CONFIG_PKCS11)
extern uint32_t _wt_band_pkcs11_base;
extern uint32_t _wt_band_pkcs11_limit;
#endif

/* One partition data band: where its .data loads from, where its .data and
 * .bss live, and the full MPU-granted extent around them. */
typedef struct wt_band_image {
    const uint32_t* load;
    uint32_t* data;
    uint32_t* data_end;
    uint32_t* bss;
    uint32_t* end;
    uint32_t* base;
    uint32_t* limit;
} wt_band_image_t;

static const wt_band_image_t g_wt_bands[] = {
    { &_si_vault, &_s_vault, &_e_vault_data, &_s_vault_bss, &_e_vault,
      &_wt_band_vault_base, &_wt_band_vault_limit },
    { &_si_attest, &_s_attest, &_e_attest_data, &_s_attest_bss, &_e_attest,
      &_wt_band_attest_base, &_wt_band_attest_limit },
    { &_si_hsm, &_s_hsm, &_e_hsm_data, &_s_hsm_bss, &_e_hsm,
      &_wt_band_hsm_base, &_wt_band_hsm_limit },
#if defined(CONFIG_VNET)
    { &_si_vnet, &_s_vnet, &_e_vnet_data, &_s_vnet_bss, &_e_vnet,
      &_wt_band_vnet_base, &_wt_band_vnet_limit },
#endif
#if defined(CONFIG_TPM)
    { &_si_tpm, &_s_tpm, &_e_tpm_data, &_s_tpm_bss, &_e_tpm,
      &_wt_band_tpm_base, &_wt_band_tpm_limit },
#endif
#if defined(CONFIG_PKCS11)
    { &_si_pkcs11, &_s_pkcs11, &_e_pkcs11_data, &_s_pkcs11_bss,
      &_e_pkcs11, &_wt_band_pkcs11_base, &_wt_band_pkcs11_limit },
#endif
};

static void wt_band_load(const wt_band_image_t* band)
{
    const uint32_t* src = band->load;
    uint32_t* dst;

    for (dst = band->data; dst < band->data_end; ++dst) {
        *dst = *src++;
    }
    for (dst = band->bss; dst < band->end; ++dst) {
        *dst = 0u;
    }
}

void wt_arch_sp_band_reset(uintptr_t base, size_t size)
{
    size_t i;

    wt_arch_zero_guest_memory(base, size);
    for (i = 0u; i < sizeof(g_wt_bands) / sizeof(g_wt_bands[0]); i++) {
        if ((uintptr_t)g_wt_bands[i].data == base) {
            wt_band_load(&g_wt_bands[i]);
        }
    }
}

static void wt_reset_main(void) __attribute__((noreturn, used));

/* Naked so nothing is pushed before MSP is moved below the two seal words
 * and they are written; MSP moves first so an exception cannot stack over
 * them, and MSPLIM_S is set only once MSP sits above it. */
__attribute__((naked, noreturn))
void Reset_Handler(void)
{
    __asm volatile(
        "ldr  r0, =_estack       \n"
        "movw r1, #0xEDA5        \n"   /* WT_ARMV8M_STACK_SEAL low half */
        "movt r1, #0xFEF5        \n"   /* WT_ARMV8M_STACK_SEAL high half */
        "subs r0, r0, #8         \n"
        "msr  msp, r0            \n"
        "str  r1, [r0, #0]       \n"
        "str  r1, [r0, #4]       \n"
        "ldr  r2, =_sstack       \n"
        "msr  msplim, r2         \n"
        "isb                     \n"
        "b    wt_reset_main      \n");
}

static void wt_reset_main(void)
{
    extern uint32_t _estack;
    extern uint32_t _sstack;
    const uint32_t* seal = (const uint32_t*)((uintptr_t)&_estack - 8u);
    uint32_t* src = &_sidata;
    uint32_t* dst = &_sdata;
    uint32_t msp;
    uint32_t msplim;
    uint32_t zeroed = 0u;
    size_t i;

    while (dst < &_edata) {
        *dst++ = *src++;
    }

    for (dst = &_sbss; dst < &_ebss; ++dst) {
        *dst = 0u;
    }

    /* Conformance SP .data/.bss live in their own MPU-granted window; the main
     * loops above skip it, so initialize it here. Empty in production builds. */
    src = &_siconfdata;
    for (dst = &_sconfdata; dst < &_econfdata; ++dst) {
        *dst = *src++;
    }
    for (dst = &_sconfbss; dst < &_econfbss; ++dst) {
        *dst = 0u;
    }

    /* The partition data bands live outside the general .data/.bss window, so
     * the loops above skip them. */
    for (i = 0u; i < sizeof(g_wt_bands) / sizeof(g_wt_bands[0]); i++) {
        for (dst = g_wt_bands[i].base; dst < g_wt_bands[i].limit; ++dst) {
            *dst = 0u;
        }
        wt_band_load(&g_wt_bands[i]);
        zeroed += (uint32_t)((uintptr_t)g_wt_bands[i].limit -
                             (uintptr_t)g_wt_bands[i].base);
    }

    /* Partition and coroutine stacks are NOLOAD outside .bss: zero them so no
     * partition starts on a previous boot's stack contents. */
    for (dst = &_wt_part_stacks_base; dst < &_wt_part_stacks_limit; ++dst) {
        *dst = 0u;
    }
    for (dst = &_wt_sp_stacks_base; dst < &_wt_sp_stacks_limit; ++dst) {
        *dst = 0u;
    }
#if defined(CONFIG_TPM)
    for (dst = &_wt_tpm_stack_base; dst < &_wt_tpm_stack_limit; ++dst) {
        *dst = 0u;
    }
#endif
#if defined(CONFIG_PKCS11)
    for (dst = &_wt_pkcs11_stack_base;
         dst < &_wt_pkcs11_stack_limit; ++dst) {
        *dst = 0u;
    }
#endif
    zeroed += (uint32_t)((uintptr_t)&_wt_part_stacks_limit -
                         (uintptr_t)&_wt_part_stacks_base);
    zeroed += (uint32_t)((uintptr_t)&_wt_sp_stacks_limit -
                         (uintptr_t)&_wt_sp_stacks_base);
#if defined(CONFIG_TPM)
    zeroed += (uint32_t)((uintptr_t)&_wt_tpm_stack_limit -
                         (uintptr_t)&_wt_tpm_stack_base);
#endif
#if defined(CONFIG_PKCS11)
    zeroed += (uint32_t)((uintptr_t)&_wt_pkcs11_stack_limit -
                         (uintptr_t)&_wt_pkcs11_stack_base);
#endif
    g_wt_boot_zeroed_bytes = zeroed;

#if defined(WT_SEAL_NEG_PROBE) && (WT_SEAL_NEG_PROBE == 3)
    /* sealbootneg: a damaged main-stack seal must stop the boot here. The
     * store is opaque so the compiler cannot fold the check and drop the
     * boot path behind it. */
    __asm__ volatile ("str %1, [%0]" : : "r"(seal), "r"(0u) : "memory");
#endif
    /* Refuse to boot unless the reset entry sealed the main stack top, moved
     * MSP below the seal words, and limited the main stack at _sstack. */
    __asm__ volatile ("mrs %0, msp" : "=r"(msp));
    __asm__ volatile ("mrs %0, msplim" : "=r"(msplim));
    if (seal[0] != WT_ARMV8M_STACK_SEAL || seal[1] != WT_ARMV8M_STACK_SEAL ||
        msp > (uint32_t)(uintptr_t)seal ||
        msplim != (uint32_t)(uintptr_t)&_sstack || msplim >= msp) {
        wt_platform_panic();
    }

#if defined(WT_MSP_OVF_PROBE) && (WT_MSP_OVF_PROBE == 1)
    /* mspovfneg: push on the main stack until MSPLIM_S raises STKOF. */
    __asm__ volatile ("1: push {r0-r7}\n b 1b");
#endif
    wt_boot_run();
}
