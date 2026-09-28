/* pal_interfaces.h
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

/* The slice of the Arm FF-A ACS platform interface pal_misc.c uses, so the
 * page pool builds on the host without the ACS tree. */

#ifndef WT_TEST_PAL_INTERFACES_H
#define WT_TEST_PAL_INTERFACES_H

#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE_4K 0x1000
#define PAL_SUCCESS  0
#define PAL_ERROR    1

#define PLATFORM_NVM_BASE 0x0E800000u
#define PLATFORM_NVM_SIZE 0x10000u
#define ATTR_DEVICE_RW_S  0x5u

typedef struct {
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t length;
    uint64_t attributes;
} memory_region_descriptor_t;

uint32_t pal_get_endpoint_device_map(void **region_list,
                                     size_t *no_of_mem_regions);
uint32_t pal_terminate_simulation(void);
void *pal_memory_alloc(uint64_t size);
uint32_t pal_memory_free(void *address, uint64_t size);
void *pal_mem_virt_to_phys(void *va);

#endif /* WT_TEST_PAL_INTERFACES_H */
