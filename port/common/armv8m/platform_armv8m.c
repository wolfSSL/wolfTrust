/* platform_armv8m.c
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

/* The platform operations every Armv8-M port shares: boot in a fixed order
 * around the port's hooks (platform_port.h), fault logging, panic and reset,
 * the per-dispatch guest RAM windows, the conformance interrupt source, the
 * test-build probes and the service-activity counters. */

#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/monitor.h"
#include "wolftrust/arch/armv8m/context.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/core_regs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "platform_port.h"
#include "fabric_sau.h"
#include "flash_port.h"

#include "wolftrust/fabric_windows.h"
#include "wolftrust/ffm_gateway.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/ffm.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/boot_handoff.h"
#include "wolftrust/services/initial_attestation.h"
#include "wolftrust/arch/armv8m/cmse.h"
#include "wolftrust/sched/tasklet.h"

static volatile uint32_t g_secure_service_depth;
static volatile uint32_t g_hsm_wait_skip_count;

void wt_platform_init(void)
{
    const wt_armv8m_sau_region_t* sau;
    const wt_armv8m_mpu_region_t* mpu;
    size_t sau_count = 0u;
    size_t mpu_count = 0u;

    wt_port_boot_init();
    /* The Secure vector table begins at the image base, after any boot
     * header. */
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    if (wt_port_fabric_init() != 0) {
        wt_platform_panic();
    }
    sau = wt_port_sau_regions(&sau_count);
    mpu = wt_port_mpu_s_regions(&mpu_count);
    if (sau == NULL || mpu == NULL || sau_count == 0u || mpu_count == 0u ||
            sau_count > wt_armv8m_sau_region_count() ||
            (wt_port_fabric_windows() == &wt_fabric_sau_backend &&
             wt_fabric_sau_init(sau_count) != 0)) {
        wt_platform_panic();
    }
    wt_armv8m_sau_init(sau, sau_count);
    wt_armv8m_mpu_s_init(mpu, mpu_count);
    wt_arch_init();
    wt_arch_zero_guest_memory(WT_GUEST0_RAM_BASE, WT_GUEST0_RAM_SIZE);
    wt_arch_zero_guest_memory(WT_GUEST1_RAM_BASE, WT_GUEST1_RAM_SIZE);
    if (wt_port_late_init() != 0) {
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

void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count)
{
    wt_fabric_apply_windows(wt_port_fabric_windows(), windows, count);
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
void wt_platform_conf_irq_pend(void)
{
#if WT_CONF_IRQ >= 32u
    WT_NVIC_ISPR1 = (1u << (WT_CONF_IRQ - 32u));
#else
    WT_NVIC_ISPR0 = (1u << WT_CONF_IRQ);
#endif
}

/* PAL interrupt source: the unprivileged DRIVER partition asks for its line
 * to fire or rest, and the port raises it from its peripheral. */
void wt_conf_uart_irq_set(int on)
{
    wt_port_conf_irq_set(on);
    if (on == 0) {
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
    /* A program issued just before this reset (the conformance boot flag,
     * an anti-rollback arming store) must land before SYSRESETREQ; the port's
     * quiesce is bounded so a wedged controller still resets. */
    wt_port_flash_quiesce();
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

/* On-demand runtime re-measurement (WT-FFM-0052): an untampered re-measure
 * of guest 0 passes, a post-launch in-flash tamper is caught. The Secure
 * MPU maps flash privileged-RO, so it is dropped for the one program. */
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

/* Boot-and-update gate: on the pre-update image arm wolfBoot's update
 * trigger for the candidate pre-staged in the update partition and reboot;
 * the swapped-in image skips the arm, so the swap terminates. A failed arm
 * falls through to a normal boot so the miss is observable. */
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
