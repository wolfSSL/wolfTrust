/* cmse.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "wolftrust/arch/armv8m/cmse.h"
#include <arm_cmse.h>
#include "wolftrust/partition.h"

bool wt_cmse_check_ns_rw(const void *ptr, size_t size)
{
    /* 64 KB cap: no legitimate CMSE-transported request is larger;
     * capping prevents integer-wrap attacks on the range check. */
    if (ptr == NULL || size == 0 || size > 0x10000) {
        return false;
    }
    return cmse_check_address_range((void *)ptr, size,
                                    CMSE_NONSECURE | CMSE_MPU_READWRITE) != NULL;
}

/* Non-zero when [ptr, ptr + size) lies wholly in one of the guest's memory
 * windows that grants every attribute in need and none in deny. */
static bool wt_cmse_in_guest_window(wt_guest_id_t guest_id, const void *ptr,
                                    size_t size, uint32_t need, uint32_t deny)
{
    const wt_guest_config_t *configs;
    const wt_guest_config_t *cfg = NULL;
    const wt_memory_window_t *w;
    uintptr_t addr = (uintptr_t)ptr;
    size_t count;
    size_t i;
    bool found = false;

    if (ptr == NULL || size == 0 || size > 0x10000 ||
            addr > UINTPTR_MAX - size) {
        return false;
    }
    configs = wt_partitions_config_table(&count);
    for (i = 0; i < count && guest_id < (wt_guest_id_t)count; ++i) {
        if (configs[i].guest_id == guest_id) {
            cfg = &configs[i];
            break;
        }
    }
    for (i = 0; cfg != NULL && !found && i < cfg->memory_window_count; ++i) {
        w = &cfg->memory_windows[i];
        found = (w->attributes & need) == need &&
                (w->attributes & deny) == 0u &&
                w->base <= UINTPTR_MAX - w->size &&
                addr >= w->base && addr + size <= w->base + w->size;
    }
    return found;
}

bool wt_cmse_check_in_guest_ns_ram(wt_guest_id_t guest_id,
                                   const void *ptr,
                                   size_t size)
{
    return wt_cmse_in_guest_window(guest_id, ptr, size,
                                   WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE,
                                   WT_MEM_ATTR_EXEC | WT_MEM_ATTR_DEVICE);
}

bool wt_cmse_check_guest_buffer(wt_guest_id_t guest_id, const void *ptr,
                                size_t size, int write)
{
    /* The window check runs first: it bounds the range the intrinsic sees. */
    return wt_cmse_in_guest_window(guest_id, ptr, size,
               write ? (WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE) :
                       WT_MEM_ATTR_READ,
               write ? (WT_MEM_ATTR_EXEC | WT_MEM_ATTR_DEVICE) :
                       WT_MEM_ATTR_DEVICE) &&
           cmse_check_address_range((void *)ptr, size, CMSE_NONSECURE |
               (write ? CMSE_MPU_READWRITE : CMSE_MPU_READ)) != NULL;
}
