/* spm.h
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

#ifndef WOLFTRUST_SPM_H
#define WOLFTRUST_SPM_H

#include <stdbool.h>
#include <stdint.h>

#include "wolftrust/manifest.h"

typedef enum wt_spm_state {
    WT_SPM_STATE_RESET = 0,
    WT_SPM_STATE_READY,
    WT_SPM_STATE_FAILED
} wt_spm_state_t;

typedef struct wt_spm {
    const wt_system_manifest_t* manifest;
    uint32_t supported_features;
    int validation_result;
    wt_spm_state_t state;
} wt_spm_t;

typedef enum wt_spm_result {
    WT_SPM_VALID = 0,
    WT_SPM_ERROR_ARGUMENT = -400,
    WT_SPM_ERROR_VALIDATION = -401
} wt_spm_result_t;

/* Validate a manifest before the SPM exposes a ready state. */
int wt_spm_init(wt_spm_t* spm,
                const wt_system_manifest_t* manifest,
                uint32_t supported_features,
                const wt_profile_capabilities_t* platform);

/* Bind the build's generated manifest without the runtime validator:
 * tools/manifest/generate.py already refused any manifest it would reject,
 * against this build's platform limits. Any other manifest needs
 * wt_spm_init(). */
int wt_spm_init_generated(wt_spm_t* spm, uint32_t supported_features);

bool wt_spm_ready(const wt_spm_t* spm);
const wt_system_manifest_t* wt_spm_manifest(const wt_spm_t* spm);
int wt_spm_validation_result(const wt_spm_t* spm);

#endif
