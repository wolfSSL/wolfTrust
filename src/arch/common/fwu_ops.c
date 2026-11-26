/* fwu_ops.c
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

#include "wolftrust/spm_ops.h"

#include "wolftrust/platform.h"
#include "wolftrust/services/fwu_service.h"
#include "wolftrust/services/hsm.h"

#include <stdint.h>

/* The port's flash staging backend (WT-FWU-0002). */
extern const wt_fwu_backend_t wt_fwu_flash_backend;

int wt_spm_fwu_op(const wt_secure_domain_t* domain, wt_spm_call_t* call)
{
    const wt_fwu_backend_t* be = &wt_fwu_flash_backend;
    uint32_t size = (uint32_t)call->num_bytes;
    uint32_t version = 0u;
    int sub = call->call_type;
    int ret = -1;

    if (sub == WT_SPM_FWU_BEGIN && be->begin != NULL) {
        ret = be->begin(NULL);
    }
    else if (sub == WT_SPM_FWU_WRITE && be->write != NULL &&
            wt_secure_domain_contains(domain, (uintptr_t)call->buffer,
                                      call->num_bytes, 0) != 0) {
        ret = be->write(NULL, call->vec_idx, (const uint8_t*)call->buffer,
                        size);
    }
    else if (sub == WT_SPM_FWU_ARM && be->arm != NULL) {
        ret = be->arm(NULL, size, call->version);
    }
    else if (sub == WT_SPM_FWU_DISARM && be->disarm != NULL) {
        ret = be->disarm(NULL);
    }
    else if (sub == WT_SPM_FWU_REBOOT) {
        /* psa_fwu_request_reboot: the granted reset does not return. */
        wt_platform_system_reset();
    }
    else if (sub == WT_SPM_FWU_FLOOR) {
        if (wt_hsm_rollback_image_floor(&version) == 0) {
            call->ret_version = version;
            ret = 0;
        }
    }
    else if (sub == WT_SPM_FWU_VERIFY && be->verify != NULL) {
        ret = be->verify(NULL, size, &version);
        if (ret == 0) {
            call->ret_version = version;
        }
    }
    else if (sub == WT_SPM_FWU_ACTIVE) {
        call->ret_version = wt_hsm_active_image_version();
        ret = 0;
    }
    return ret;
}
