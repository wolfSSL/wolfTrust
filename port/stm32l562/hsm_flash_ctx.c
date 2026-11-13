/* hsm_flash_ctx.c
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

#include "hsm_flash.h"

wt_hsm_flash_context_t g_hsm_flash_ctx;

/* Gate-path forensics (SWD-readable), counted in the vault's own thread. */
volatile uint32_t g_wt_flash_gate_aborts __attribute__((used));
volatile uint32_t g_wt_flash_gate_abort_info __attribute__((used));
