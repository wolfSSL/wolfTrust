/* spm_sp_mem.h
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

#ifndef WOLFTRUST_SPM_SP_MEM_H
#define WOLFTRUST_SPM_SP_MEM_H

#include <stdint.h>

#include "wolftrust/spm_core.h"
#include "wolftrust/types.h"

/* Generated, one row per Secure Partition in g_wt_spm_sps order: the
 * domain's memory resources, the private stack and RESTART_CLEAR band the
 * generator chose from them, and the domain's restart policy. */
typedef struct wt_spm_sp_mem {
    const wt_memory_region_t* regions;
    uintptr_t stack_base;
    uintptr_t band_base;
    uint32_t stack_size;
    uint32_t band_size;
    uint32_t restart_limit;
    uint32_t restart_window_ticks;
    uint8_t region_count;
    uint8_t restart_action;
} wt_spm_sp_mem_t;

extern WT_SPM_TABLE wt_spm_sp_mem_t g_wt_spm_sp_mems[];

#endif /* WOLFTRUST_SPM_SP_MEM_H */
