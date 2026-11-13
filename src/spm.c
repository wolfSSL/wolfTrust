/* spm.c
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

#include "wolftrust/spm.h"
#include "wolftrust_manifest_generated.h"

#include <stddef.h>

static int wt_spm_begin(wt_spm_t* spm, const wt_system_manifest_t* manifest,
                        uint32_t supported_features)
{
    if (spm == NULL) {
        return WT_SPM_ERROR_ARGUMENT;
    }

    spm->manifest = NULL;
    spm->supported_features = supported_features;
    spm->validation_result = WT_MANIFEST_ERROR_ARGUMENT;
    spm->state = WT_SPM_STATE_RESET;

    if (manifest == NULL) {
        spm->state = WT_SPM_STATE_FAILED;
        return WT_SPM_ERROR_ARGUMENT;
    }
    return WT_SPM_VALID;
}

static int wt_spm_finish(wt_spm_t* spm, const wt_system_manifest_t* manifest,
                         int result)
{
    spm->validation_result = result;
    if (result != WT_MANIFEST_VALID) {
        spm->state = WT_SPM_STATE_FAILED;
        return WT_SPM_ERROR_VALIDATION;
    }

    spm->manifest = manifest;
    spm->state = WT_SPM_STATE_READY;
    return WT_SPM_VALID;
}

int wt_spm_init(wt_spm_t* spm,
                const wt_system_manifest_t* manifest,
                uint32_t supported_features,
                const wt_profile_capabilities_t* platform)
{
    int ret;

    ret = wt_spm_begin(spm, manifest, supported_features);
    if (ret == WT_SPM_VALID) {
        ret = wt_spm_finish(spm, manifest, wt_manifest_validate(manifest,
                            supported_features, platform));
    }
    return ret;
}

int wt_spm_init_generated(wt_spm_t* spm, uint32_t supported_features)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    int ret;

    ret = wt_spm_begin(spm, manifest, supported_features);
    if (ret == WT_SPM_VALID) {
        ret = wt_spm_finish(spm, manifest, WT_MANIFEST_VALID);
    }
    return ret;
}

bool wt_spm_ready(const wt_spm_t* spm)
{
    return spm != NULL && spm->state == WT_SPM_STATE_READY &&
           spm->manifest != NULL;
}

const wt_system_manifest_t* wt_spm_manifest(const wt_spm_t* spm)
{
    if (!wt_spm_ready(spm)) {
        return NULL;
    }

    return spm->manifest;
}

int wt_spm_validation_result(const wt_spm_t* spm)
{
    if (spm == NULL) {
        return WT_MANIFEST_ERROR_ARGUMENT;
    }

    return spm->validation_result;
}
