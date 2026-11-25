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
    if (ptr == NULL || size == 0 || size > UINTPTR_MAX - (uintptr_t)ptr) {
        return false;
    }
    return cmse_check_address_range((void *)ptr, size,
                                    CMSE_NONSECURE | CMSE_MPU_READWRITE) != NULL;
}

bool wt_cmse_check_ns_ro(const void *ptr, size_t size)
{
    if (ptr == NULL || size == 0 || size > UINTPTR_MAX - (uintptr_t)ptr) {
        return false;
    }
    return cmse_check_address_range((void *)ptr, size,
                                    CMSE_NONSECURE | CMSE_MPU_READ) != NULL;
}

bool wt_cmse_check_in_guest_ns_ram(wt_guest_id_t guest_id,
                                   const void *ptr,
                                   size_t size)
{
    const wt_guest_config_t *configs;
    size_t count;
    size_t i;
    const wt_guest_config_t *cfg = NULL;
    uintptr_t addr;
    uintptr_t end;
    uintptr_t win_end;

    if (ptr == NULL || size == 0) {
        return false;
    }

    configs = wt_partitions_config_table(&count);

    if (guest_id >= (wt_guest_id_t)count) {
        return false;
    }

    for (i = 0; i < count; ++i) {
        if (configs[i].guest_id == guest_id) {
            cfg = &configs[i];
            break;
        }
    }

    if (cfg == NULL) {
        return false;
    }

    addr = (uintptr_t)ptr;

    /* Detect wraparound before any window comparison. */
    if (addr > UINTPTR_MAX - size) {
        return false;
    }
    end = addr + size;

    for (i = 0; i < cfg->memory_window_count; ++i) {
        const wt_memory_window_t *w = &cfg->memory_windows[i];
        uint32_t attr = w->attributes;

        if (!(attr & WT_MEM_ATTR_READ)) {
            continue;
        }
        if (!(attr & WT_MEM_ATTR_WRITE)) {
            continue;
        }
        if (attr & WT_MEM_ATTR_EXEC) {
            continue;
        }
        if (attr & WT_MEM_ATTR_DEVICE) {
            continue;
        }

        if (w->base > UINTPTR_MAX - w->size) {
            continue;
        }
        win_end = w->base + w->size;

        if (addr >= w->base && end <= win_end) {
            return true;
        }
    }

    return false;
}

bool wt_cmse_check_in_guest_ns_addr(wt_guest_id_t guest_id,
                                    const void *ptr,
                                    size_t size)
{
    const wt_guest_config_t *configs;
    size_t count;
    size_t i;
    const wt_guest_config_t *cfg = NULL;
    uintptr_t addr;
    uintptr_t end;
    uintptr_t win_end;

    if (ptr == NULL || size == 0) {
        return false;
    }
    configs = wt_partitions_config_table(&count);
    if (guest_id >= (wt_guest_id_t)count) {
        return false;
    }
    for (i = 0; i < count; ++i) {
        if (configs[i].guest_id == guest_id) {
            cfg = &configs[i];
            break;
        }
    }
    if (cfg == NULL) return false;

    addr = (uintptr_t)ptr;
    if (addr > UINTPTR_MAX - size) return false;
    end = addr + size;

    for (i = 0; i < cfg->memory_window_count; ++i) {
        const wt_memory_window_t *w = &cfg->memory_windows[i];
        uint32_t attr = w->attributes;
        if (!(attr & WT_MEM_ATTR_READ)) continue;
        if (attr & WT_MEM_ATTR_DEVICE) continue;
        if (w->base > UINTPTR_MAX - w->size) continue;
        win_end = w->base + w->size;
        if (addr >= w->base && end <= win_end) return true;
    }
    return false;
}
