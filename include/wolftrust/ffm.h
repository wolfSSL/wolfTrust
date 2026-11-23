/* ffm.h
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

#ifndef WOLFTRUST_FFM_H
#define WOLFTRUST_FFM_H

#include <stddef.h>
#include <stdint.h>

#include "psa/service.h"
#include "wolftrust/manifest.h"
#include "wolftrust/spm_core.h"
#include "wolftrust/types.h"

/* The SPM core state, passed opaquely through the service loops. */
typedef struct wt_spm_core wt_ffm_runtime_t;

typedef int (*wt_ffm_dispatch_fn)(void* context, wt_ffm_runtime_t* runtime,
                                  int32_t partition_id);

typedef enum wt_ffm_result {
    WT_FFM_SUCCESS = 0,
    WT_FFM_ERROR_ARGUMENT = -600,
    WT_FFM_ERROR_MANIFEST = -601,
    WT_FFM_ERROR_POLICY = -602,
    WT_FFM_ERROR_RESOURCE = -603,
    WT_FFM_ERROR_HANDLE = -604,
    WT_FFM_ERROR_STATE = -605,
    WT_FFM_ERROR_NOT_READY = -606,
    WT_FFM_ERROR_BUFFER = -607,
    WT_FFM_ERROR_ISOLATION = -608
} wt_ffm_result_t;

#endif /* WOLFTRUST_FFM_H */
