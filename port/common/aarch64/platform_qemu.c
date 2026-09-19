/* platform_qemu.c
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

/* wt_platform_* operations shared by the QEMU-hosted AArch64 ports (virt
 * and versal-virt): the board is already initialized by the EL3 monitor,
 * so the SPMC side only reports, resets, and describes its image. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/ffm_gateway.h"
#include "wolftrust/platform.h"
#include "memory_map.h"

#include <stddef.h>
#include <stdint.h>

extern uint8_t _e_secure_text[];
extern uint8_t __image_end[];

/* Install the NS memory checks the FF-M gateway consults for every
 * Normal-world vector (the port seam the Armv8-M port installs the same way). */
void wt_platform_init(void)
{
    wt_ffm_gateway_install();
}

/* No TrustZone address-space filter on these machines (WT-PORT-0008: the
 * port does not claim the capability, so nothing consults this). */
void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count)
{
    (void)windows;
    (void)count;
}

void wt_platform_log_fault(wt_guest_id_t guest_id, wt_fault_reason_t reason,
                           uintptr_t fault_address, uintptr_t pc)
{
    wt_el3_puts("[SPM] fault guest=");
    wt_el3_putdec(guest_id);
    wt_el3_puts(" reason=");
    wt_el3_putdec((uint64_t)reason);
    wt_el3_puts(" addr=0x");
    wt_el3_puthex(fault_address, 16u);
    wt_el3_puts(" pc=0x");
    wt_el3_puthex(pc, 16u);
    wt_el3_puts("\r\n");
}

int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size)
{
    (void)window_base;
    (void)window_size;
    return 0;
}

/* No Normal world to run: the SPMC waits for FF-A events instead. */
void wt_platform_all_guests_faulted(void)
{
    static uint32_t entered;

    /* The first call never returns, so a re-entry is a recovery escalation. */
    if (entered != 0u) {
        wt_el3_puts("[SPM] restart budget exhausted, failing closed\r\n");
        wt_platform_console_flush();
        (void)wt_mon_call(WT_MON_FID_PANIC, 0x7Du);
        for (;;) {
            __asm__ volatile("wfi");
        }
    }
    entered = 1u;
    wt_spm_init_partitions();
    wt_el3_puts("[SPM] partitions ready n=");
    wt_el3_putdec(wt_spm_sp_init_count());
    wt_el3_puts("\r\n[SPM] no runnable guest, waiting for FF-A events\r\n");
    wt_spm_idle();
}

void wt_platform_panic(void)
{
    wt_el3_puts("[SPM] panic from 0x");
    wt_el3_puthex((uint64_t)(uintptr_t)__builtin_return_address(0), 16u);
    wt_el3_puts("\r\n");
    wt_platform_console_flush();
    (void)wt_mon_call(WT_MON_FID_PANIC, 0xF2u);
    for (;;) {
        __asm__ volatile("wfi");
    }
}

void wt_platform_system_reset(void)
{
    wt_platform_console_flush();
    (void)wt_mon_call(WT_MON_FID_SYSTEM_RESET, 0u);
    for (;;) {
        __asm__ volatile("wfi");
    }
}

#ifdef WT_ENGINE_HSM
bool wt_platform_secure_service_active(void)
{
    return false;
}

void wt_platform_note_hsm_wait_skip(wt_guest_id_t guest_id)
{
    (void)guest_id;
}
#endif

/* The wolfBoot handoff record arrives through the FF-A boot information
 * blob; none is placed yet, so the region is empty and fails closed. */
volatile void* wt_platform_boot_handoff_region(size_t* size)
{
    if (size != NULL) {
        *size = (g_wt_spm_handoff_pa != 0u) ? g_wt_spm_handoff_size : 0u;
    }
    return (volatile void*)g_wt_spm_handoff_pa;
}

/* The code every partition executes: the SPMC image text (RX) and its
 * constant data (RO), shaped exactly like the SPMC's shareable fill entries
 * so the partition mapping replaces them (the manifest's executable
 * resource is policy only; the scheduler maps code from here). */
size_t wt_platform_sp_shared_regions(wt_memory_region_t* regions, size_t max)
{
    uintptr_t text_end = (uintptr_t)_e_secure_text;
    uintptr_t image_end = ((uintptr_t)__image_end + WT_TABLES_PAGE_SIZE - 1u) &
                          ~(uintptr_t)(WT_TABLES_PAGE_SIZE - 1u);

    if (regions == NULL || max < 2u) {
        return 0u;
    }
    regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    regions[0].size = text_end - (uintptr_t)WT_SPM_IMAGE_PA;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    regions[1].base = text_end;
    regions[1].size = image_end - text_end;
    regions[1].attributes = WT_MEM_ATTR_READ;
    return 2u;
}

#if (defined(WT_FFM_NEGATIVE_PROBE) && (WT_FFM_NEGATIVE_PROBE == 1)) || \
    (defined(WT_KEYSTORE_NEG_PROBE) && (WT_KEYSTORE_NEG_PROBE == 1))
uintptr_t wt_platform_probe_address(unsigned int target)
{
    switch (target) {
    case WT_PROBE_KEYSTORE_BAND:
        return (uintptr_t)WT_SPM_KEYSTORE_PA;
    default:
        return (uintptr_t)WT_SPM_RAM_PA;
    }
}
#endif
