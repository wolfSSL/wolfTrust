/* measure_ops.c
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

#include "wolftrust/guest_verify.h"

#include <stdint.h>
#include <string.h>

/* WT-FFM-0049/0062: the confined attest partition reads the launch-verified
 * guest measurements through the SPM, never the monitor's table directly. */
int wt_spm_measure_op(const wt_secure_domain_t* domain, wt_spm_call_t* call)
{
    const wt_guest_measurement_t* rec;
    int ret = 0;

    call->ret_size = wt_guest_measurement_count();
    if (call->buffer != NULL) {
        ret = -1;
        rec = wt_guest_measurement_get(call->vec_idx);
        if (rec != NULL && call->num_bytes == sizeof(*rec) &&
                wt_secure_domain_contains(domain, (uintptr_t)call->buffer,
                                          call->num_bytes, 1) != 0) {
            (void)memcpy(call->buffer, rec, sizeof(*rec));
            ret = 0;
        }
    }
    return ret;
}
