/* hsm_flash.h
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

#ifndef WOLFTRUST_STM32L562_HSM_FLASH_H
#define WOLFTRUST_STM32L562_HSM_FLASH_H

#include "wolftrust/port_nvm.h"  /* g_wt_hsm_flash_cb + context/config contract */

#include <stdbool.h>
#include <stdint.h>

typedef struct wt_hsm_flash_config {
    uintptr_t base;
    uint32_t size;
    uint32_t sector_size;
    uint32_t program_unit;
} wt_hsm_flash_config_t;

typedef struct wt_hsm_flash_context {
    uintptr_t base;
    uint32_t size;
    uint32_t sector_size;
    uint32_t program_unit;
    bool write_locked;
} wt_hsm_flash_context_t;

/* The vault's own flash bookkeeping (hsm_flash_ctx.c, in the vault's data
 * band). The driver's privileged state stays in hsm_flash.c, in SPM RAM. */
extern wt_hsm_flash_context_t g_hsm_flash_ctx;
extern volatile uint32_t g_wt_flash_gate_aborts;
extern volatile uint32_t g_wt_flash_gate_abort_info;

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Privileged survive-reset NVM sync for the conformance DRIVER partition
 * (P5 K2): store==0 loads the reserved flash sector into buf, store!=0 erases
 * that sector and programs buf back. len must be a multiple of the 8-byte
 * program unit. Returns 0 on success, -1 on failure. */
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store);
#endif

#if defined(WT_REMEASURE_PROBE)
/* Test-only: corrupt the first double-word of the Non-secure guest page at
 * ns_base through the Non-secure flash controller, so an on-demand
 * re-measurement of that window fails its pinned digest. */
int wt_hsm_flash_remeasure_tamper(uintptr_t ns_base);
#endif

#endif /* WOLFTRUST_STM32L562_HSM_FLASH_H */
