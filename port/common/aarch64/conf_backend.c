/* conf_backend.c
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

/* Privileged backend for the AArch64 conformance image, called from the SVC
 * gate (spm_gate_core.c) on behalf of the unprivileged DRIVER partition. The
 * NVM store lives in a .noinit band so val's boot flag survives the EL3 warm
 * reset the panic tests trigger; on QEMU a warm reset re-enters the boot chain
 * without clearing RAM, and neither the EL3 image copy nor the SPMC bss clear
 * touches this band. The interrupt hook raises the DRIVER partition's Secure
 * SPI through the GIC. */

#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/platform.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/types.h"

#include "psa_manifest/pid.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern uint8_t _e_conf_data[];

#define WT_CONF_NVM_SIZE  0x200u
#define WT_CONF_NVM_MAGIC 0x774E564Du /* "wNVM" */
#define WT_CONF_UART_INTID 63u

/* .noinit: not in the image (NOLOAD) and outside the SPMC bss-clear range, so
 * its contents persist across a warm reset. */
static struct {
    uint32_t magic;
    uint8_t  store[WT_CONF_NVM_SIZE];
} g_conf_nvm __attribute__((section(".noinit")));

static void wt_conf_nvm_prime(void)
{
    /* First power-on (cold boot) leaves the band cleared; present the
     * flash-blank 0xFF state val expects until something is written. */
    if (g_conf_nvm.magic != WT_CONF_NVM_MAGIC) {
        (void)memset(g_conf_nvm.store, 0xFF, sizeof(g_conf_nvm.store));
        g_conf_nvm.magic = WT_CONF_NVM_MAGIC;
    }
}

int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store)
{
    if (buf == NULL || len == 0u || len > sizeof(g_conf_nvm.store)) {
        return -1;
    }
    wt_conf_nvm_prime();
    if (store == 0) {
        (void)memcpy(buf, g_conf_nvm.store, (size_t)len);
    }
    else {
        (void)memcpy(g_conf_nvm.store, buf, (size_t)len);
    }
    return 0;
}

void wt_conf_uart_irq_set(int on)
{
    if (on != 0) {
        wt_gic->set_pending(WT_CONF_UART_INTID);
    }
    else {
        wt_gic->disable(WT_CONF_UART_INTID);
    }
}

/* The Arm test partitions read their val/psa API tables from .data, which the
 * linker places in the shared conformance band; grant it so each reaches its
 * own data at S-EL0 while SPM RAM stays EL1-only. Only the three test
 * partitions get it; the production services never touch this band. Per-
 * partition hole carving for the L3 MMIO-isolation tests is a later slice. */
size_t wt_platform_conf_sp_grants(int32_t partition_id,
                                  wt_memory_region_t* regions,
                                  size_t count, size_t max)
{
    uintptr_t base = (uintptr_t)WT_SPM_CONFDATA_PA;
    /* The full band, not just the used .data/.bss: the per-partition
     * pseudo-MMIO holes the isolation tests probe live near its top and must be
     * reachable by their owner. Per-partition hole carving is a later slice. */
    uintptr_t end = (uintptr_t)WT_SPM_CONFDATA_PA + (uintptr_t)WT_SPM_CONFDATA_SIZE;

    (void)_e_conf_data;
    if (partition_id != SERVER_PARTITION_ID &&
            partition_id != DRIVER_PARTITION_ID &&
            partition_id != CLIENT_PARTITION_ID) {
        return count;
    }
    if (regions != NULL && count < max && end > base) {
        regions[count].base = base;
        regions[count].size = (uint32_t)(end - base);
        regions[count].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
        count++;
    }
    return count;
}
