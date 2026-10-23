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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef WOLFTRUST_MCXN947_HSM_FLASH_H
#define WOLFTRUST_MCXN947_HSM_FLASH_H

#include <stdbool.h>
#include <stdint.h>
#include "wolftrust/port_nvm.h"

typedef struct wt_hsm_flash_config {
    uintptr_t base;
    uint32_t size;
    uint32_t sector_size;
    uint32_t program_unit;
} wt_hsm_flash_config_t;

typedef struct wt_hsm_flash_context {
    bool write_locked;
} wt_hsm_flash_context_t;

/* The vault's own flash bookkeeping (hsm_flash_ctx.c, in the vault's data
 * band). The driver's privileged state stays in hsm_flash.c, in SPM RAM. */
extern wt_hsm_flash_context_t g_hsm_flash_ctx;
extern volatile uint32_t g_wt_flash_gate_aborts;
extern volatile uint32_t g_wt_flash_gate_abort_info;

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store);
#endif

#if defined(WT_REMEASURE_PROBE)
int wt_hsm_flash_remeasure_tamper(uintptr_t secure_base);
#endif

#endif /* WOLFTRUST_MCXN947_HSM_FLASH_H */
