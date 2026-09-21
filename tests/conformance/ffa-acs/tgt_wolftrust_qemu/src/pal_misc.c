/* pal_misc.c
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

#include "pal_interfaces.h"
#include "pal_misc_asm.h"

#define WT_ACS_PSCI_SYSTEM_OFF 0x84000008u
#define WT_ACS_BUFFER_COUNT    5

static uint32_t is_buffer_in_use[WT_ACS_BUFFER_COUNT];
__attribute__ ((aligned (PAGE_SIZE_4K)))
static uint8_t pal_buffer_4k[WT_ACS_BUFFER_COUNT][PAGE_SIZE_4K];

static memory_region_descriptor_t endpoint_device_regions[] = {
#if defined(SP1_COMPILE)
    {PLATFORM_NVM_BASE, PLATFORM_NVM_BASE, PLATFORM_NVM_SIZE, ATTR_DEVICE_RW_S},
#endif
#if defined(VM1_COMPILE)
    {PLATFORM_NS_UART_BASE, PLATFORM_NS_UART_BASE, PLATFORM_NS_UART_SIZE,
        ATTR_DEVICE_RW},
    {GICD_BASE, GICD_BASE, GICD_SIZE, ATTR_DEVICE_RW},
    {GICR_BASE, GICR_BASE, GICR_SIZE, ATTR_DEVICE_RW},
    {GICC_BASE, GICC_BASE, GICC_SIZE, ATTR_DEVICE_RW},
#endif
};

uint32_t pal_get_endpoint_device_map(void **region_list,
                                     size_t *no_of_mem_regions)
{
    *region_list = (void *)endpoint_device_regions;
    *no_of_mem_regions = sizeof(endpoint_device_regions) /
                         sizeof(endpoint_device_regions[0]);
    return PAL_SUCCESS;
}

/* The dispatcher ends the emulator run through PSCI; a partition only parks. */
uint32_t pal_terminate_simulation(void)
{
#if defined(VM1_COMPILE)
    (void)pal_syscall_for_psci(WT_ACS_PSCI_SYSTEM_OFF, 0, 0, 0);
#endif
    while (1) {
    }
    return PAL_SUCCESS;
}

void *pal_memory_alloc(uint64_t size)
{
    int span = 0;
    int i;

    if (size == PAGE_SIZE_4K) {
        span = 1;
    }
    else if (size == (PAGE_SIZE_4K * 2)) {
        span = 2;
    }
    for (i = 0; (span != 0) && ((i + span) <= WT_ACS_BUFFER_COUNT); i++) {
        if ((is_buffer_in_use[i] == 0u) &&
            ((span == 1) || (is_buffer_in_use[i + 1] == 0u))) {
            is_buffer_in_use[i] = 1u;
            if (span == 2) {
                is_buffer_in_use[i + 1] = 1u;
            }
            return &pal_buffer_4k[i][0];
        }
    }
    return NULL;
}

uint32_t pal_memory_free(void *address, uint64_t size)
{
    int span = (size == (PAGE_SIZE_4K * 2)) ? 2 : 1;
    int i;

    for (i = 0; (i + span) <= WT_ACS_BUFFER_COUNT; i++) {
        if (&pal_buffer_4k[i][0] == address) {
            is_buffer_in_use[i] = 0u;
            if (span == 2) {
                is_buffer_in_use[i + 1] = 0u;
            }
            return PAL_SUCCESS;
        }
    }
    return PAL_ERROR;
}

/* Every endpoint runs identity-mapped. */
void *pal_mem_virt_to_phys(void *va)
{
    return va;
}
