/* spm_tables.h
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

#ifndef WOLFTRUST_SPM_TABLES_H
#define WOLFTRUST_SPM_TABLES_H

#include "wolftrust/manifest.h"
#include "wolftrust/spm_core.h"

#define WT_SPM_MAX_SERVICES 32U

/* Caller storage for the rows the generator emits: services holds
 * WT_SPM_MAX_SERVICES, sps WT_SPM_MAX_SPS and irqs irq_cap entries. */
typedef struct wt_spm_tables {
    wt_spm_service_t* services;
    wt_spm_sp_ipc_t* sps;
    wt_spm_irq_t* irqs;
    uint32_t irq_cap;
    uint32_t framework_version;
    uint8_t service_count;
    uint8_t sp_count;
    uint8_t irq_count;
} wt_spm_tables_t;

/* Derives the rows from a descriptive manifest with the generator's rules,
 * refusing any manifest the generator would refuse to activate. */
int wt_spm_tables_derive(const wt_system_manifest_t* manifest,
                         wt_spm_tables_t* out);

#endif /* WOLFTRUST_SPM_TABLES_H */
