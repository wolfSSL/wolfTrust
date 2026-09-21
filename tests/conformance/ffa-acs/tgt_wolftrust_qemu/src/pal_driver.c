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

uint32_t pal_twdog_enable(uint32_t ms)
{
    (void)ms;
    return PAL_ERROR;
}

uint32_t pal_twdog_disable(void)
{
    return PAL_ERROR;
}

void pal_twdog_intr_enable(void)
{
}

void pal_twdog_intr_disable(void)
{
}

void pal_ns_wdog_enable(uint32_t ms)
{
    (void)ms;
}

void pal_ns_wdog_disable(void)
{
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
