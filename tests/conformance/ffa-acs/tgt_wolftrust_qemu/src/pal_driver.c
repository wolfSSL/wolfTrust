/* pal_driver.c
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

/* FF-A ACS device layer for the wolfTrust QEMU machines: the test NVM is a
 * Secure RAM band owned by SP1; the machines model no SP805 watchdogs, no
 * reference-clock timer and no SMMU test engine. */

#include "pal_interfaces.h"
#include "pal_nvm.h"
#include "pal_spm_helpers.h"

uint32_t pal_nvm_write(uint32_t offset, void *buffer, size_t size)
{
    return driver_nvm_write(offset, buffer, size);
}

uint32_t pal_nvm_read(uint32_t offset, void *buffer, size_t size)
{
    return driver_nvm_read(offset, buffer, size);
}

/* Recovery aid only: the scenario runner's emulator timeout ends a hung run. */
uint32_t pal_watchdog_enable(void)
{
    return PAL_SUCCESS;
}

uint32_t pal_watchdog_disable(void)
{
    return PAL_SUCCESS;
}

uint32_t pal_ap_phy_refclk_en(uint32_t us)
{
    (void)us;
    return PAL_ERROR;
}

uint32_t pal_ap_phy_refclk_dis(bool int_mask)
{
    (void)int_mask;
    return PAL_ERROR;
}

uint32_t pal_ap_virt_refclk_en(uint32_t us)
{
    (void)us;
    return PAL_ERROR;
}

uint32_t pal_ap_virt_refclk_dis(bool int_mask)
{
    (void)int_mask;
    return PAL_ERROR;
}

/* The SPMC's test-timer service: a deadline against its scheduling tick that
 * makes the named interrupt pending on expiry. A partition reaches it by SVC,
 * the Normal-world dispatcher by SMC, through the same conduit helper. */
#define WT_ACS_SVC_TIMER_ARM  0xC3000102U
#define WT_ACS_SVC_TIMER_STOP 0xC3000103U

smc_ret_values asm_smc64(uint32_t fid, u_register_t arg1, u_register_t arg2,
                         u_register_t arg3, u_register_t arg4,
                         u_register_t arg5, u_register_t arg6,
                         u_register_t arg7);

static uint32_t wt_acs_timer_call(uint32_t fid, uint32_t intid, uint32_t ms)
{
    smc_args args = {
        .fid = fid,
        .arg1 = intid,
        .arg2 = ms
    };
#if defined(VM1_COMPILE)
    /* The dispatcher reaches the monitor by SMC; its hvc conduit is a real
     * hypervisor call this system has nothing to take. */
    smc_ret_values ret = asm_smc64(args.fid, args.arg1, args.arg2, args.arg3,
                                   args.arg4, args.arg5, args.arg6, args.arg7);
#else
    smc_ret_values ret = pal_hvc(&args);
#endif

    return (ret.ret0 == 0U) ? PAL_SUCCESS : PAL_ERROR;
}

uint32_t pal_twdog_enable(uint32_t ms)
{
    (void)spm_interrupt_enable(PLATFORM_TWDOG_INTID, true, INTERRUPT_TYPE_IRQ);
    return wt_acs_timer_call(WT_ACS_SVC_TIMER_ARM, PLATFORM_TWDOG_INTID, ms);
}

uint32_t pal_twdog_disable(void)
{
    return wt_acs_timer_call(WT_ACS_SVC_TIMER_STOP, 0U, 0U);
}

void pal_twdog_intr_enable(void)
{
    (void)spm_interrupt_enable(PLATFORM_TWDOG_INTID, true, INTERRUPT_TYPE_IRQ);
}

void pal_twdog_intr_disable(void)
{
    (void)spm_interrupt_enable(PLATFORM_TWDOG_INTID, false, INTERRUPT_TYPE_IRQ);
}

/* The reference driver loads this value straight into a watchdog counting
 * the system counter, so it is counter ticks; the SPMC's timer takes ms. */
void pal_ns_wdog_enable(uint32_t ms)
{
    uint64_t freq;

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (freq == 0U) {
        freq = 1U;
    }
    (void)wt_acs_timer_call(WT_ACS_SVC_TIMER_ARM, PLATFORM_NS_WD_INTR,
                            (uint32_t)(((uint64_t)ms * 1000U) / freq));
}

void pal_ns_wdog_disable(void)
{
    (void)wt_acs_timer_call(WT_ACS_SVC_TIMER_STOP, 0U, 0U);
}

void pal_ns_wdog_intr_enable(void)
{
}

void pal_ns_wdog_intr_disable(void)
{
}

void pal_secure_intr_enable(uint32_t int_id, enum interrupt_pin pin)
{
    (void)int_id;
    (void)pin;
}

void pal_secure_intr_disable(uint32_t int_id, enum interrupt_pin pin)
{
    (void)int_id;
    (void)pin;
}

uint64_t pal_sleep(uint32_t ms)
{
    return sp_sleep_elapsed_time(ms);
}

uint32_t pal_smmu_device_configure(uint32_t stream_id, uint64_t source,
                                   uint64_t dest, uint64_t size, bool secure)
{
    (void)stream_id;
    (void)source;
    (void)dest;
    (void)size;
    (void)secure;
    return PAL_ERROR;
}
