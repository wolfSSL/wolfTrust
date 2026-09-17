/* pal_driver_intf.c
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

/* SPE PAL for the Arm psa-arch-tests DRIVER partition on wolfTrust (P3a).
 * NVMEM is a flash-backed store surviving an AIRCR reset (P5 K2): a RAM shadow
 * loaded from the reserved flash sector at first use and written through on
 * every write via wt_conf_nvm_sync (SVC to the privileged flash driver). The
 * watchdog and interrupt hooks are no-ops until P4/P6 provide the real
 * devices; prints are swallowed until the secure UART routing lands in P3b.
 * All state lives in the driver partition's own CONFDATA/.bss window. */

#include "conf_nvm.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uintptr_t addr_t;

#define WT_CONF_DRV_NVM_SIZE 0x100u
static uint8_t g_drv_nvm[WT_CONF_DRV_NVM_SIZE];
static uint8_t g_drv_nvm_ready;
static uint8_t g_drv_wd_enabled;

static int wt_conf_drv_nvm_init(void)
{
    if (g_drv_nvm_ready == 0u) {
        /* Reload the persisted contents; a blank sector reads back 0xFF, the
         * same power-on state the RAM store used to fabricate. */
        if (wt_conf_nvm_sync(g_drv_nvm, sizeof(g_drv_nvm), 0) != 0) {
            (void)memset(g_drv_nvm, 0xFF, sizeof(g_drv_nvm));
        }
        g_drv_nvm_ready = 1u;
    }
    return 0;
}

#if defined(WT_CONF_NVM_HOST_TEST)
/* Host-test seam: force the next access to reload from the flash simulator,
 * modelling what a post-reset boot does. Never compiled into the target. */
void wt_conf_drv_nvm_test_reset(void)
{
    g_drv_nvm_ready = 0u;
}
#endif

void pal_uart_init(uint32_t uart_base_addr)
{
    (void)uart_base_addr;
}

void pal_print_s(const char* str, int32_t data)
{
    (void)str;
    (void)data;
}

int pal_print(uint8_t c)
{
    (void)c;
    return 0;
}

int pal_nvmem_write(addr_t base, uint32_t offset, void* buffer, int size)
{
    (void)base;
    (void)wt_conf_drv_nvm_init();
    /* Wrap-safe: offset + size overflows size_t on a 32-bit target, so
     * compare each side against the array bound without adding them. */
    if (buffer == NULL || size < 0 ||
            (size_t)offset > sizeof(g_drv_nvm) ||
            (size_t)size > sizeof(g_drv_nvm) - (size_t)offset) {
        return 0;
    }
    (void)memcpy(&g_drv_nvm[offset], buffer, (size_t)size);
    /* Write through to flash so the value survives an AIRCR reset. */
    if (wt_conf_nvm_sync(g_drv_nvm, sizeof(g_drv_nvm), 1) != 0) {
        return 0;
    }
    return 1;
}

int pal_nvmem_read(addr_t base, uint32_t offset, void* buffer, int size)
{
    (void)base;
    (void)wt_conf_drv_nvm_init();
    /* Wrap-safe: offset + size overflows size_t on a 32-bit target, so
     * compare each side against the array bound without adding them. */
    if (buffer == NULL || size < 0 ||
            (size_t)offset > sizeof(g_drv_nvm) ||
            (size_t)size > sizeof(g_drv_nvm) - (size_t)offset) {
        return 0;
    }
    (void)memcpy(buffer, &g_drv_nvm[offset], (size_t)size);
    return 1;
}

int pal_wd_timer_init(addr_t base_addr, uint32_t time_us,
                      uint32_t timer_tick_us)
{
    (void)base_addr;
    (void)time_us;
    (void)timer_tick_us;
    return 0;
}

int pal_wd_timer_enable(addr_t base_addr)
{
    (void)base_addr;
    g_drv_wd_enabled = 1u;
    return 0;
}

int pal_wd_timer_disable(addr_t base_addr)
{
    (void)base_addr;
    g_drv_wd_enabled = 0u;
    return 0;
}

int pal_wd_timer_is_enabled(addr_t base_addr)
{
    (void)base_addr;
    return (int)g_drv_wd_enabled;
}

void pal_generate_interrupt(void)
{
    (void)wt_conf_irq_set(1);
}

void pal_disable_interrupt(void)
{
    (void)wt_conf_irq_set(0);
}
