/* psa_ffa_transport.c
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

/* Operating-system-neutral PSA Firmware Framework client for a Normal-world
 * guest. It implements the register-only half of the PSA client API
 * (psa/client.h) on top of the architecture transport primitive wt_psa_ffa_op,
 * so a Zephyr, FreeRTOS, or bare-metal client links exactly the same client
 * and names no architecture detail. Data-carrying psa_call arrives with memory
 * sharing (B4). The FF-A sibling of psa_ffm_client.c (Armv8-M veneers). */

#include "psa/client.h"
#include "wolftrust/psa_ffa_transport.h"

uint32_t psa_framework_version(void)
{
    uint32_t result = 0u;

    if (wt_psa_ffa_op(WT_PSA_FFA_OP_FRAMEWORK_VERSION, 0u, 0u, &result) != 0) {
        return 0u;
    }
    return result;
}

uint32_t psa_version(uint32_t sid)
{
    uint32_t result = PSA_VERSION_NONE;

    if (wt_psa_ffa_op(WT_PSA_FFA_OP_SERVICE_VERSION, sid, 0u, &result) != 0) {
        return PSA_VERSION_NONE;
    }
    return result;
}

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    uint32_t result = 0u;

    if (wt_psa_ffa_op(WT_PSA_FFA_OP_CONNECT, sid, version, &result) != 0) {
        return (psa_handle_t)PSA_ERROR_COMMUNICATION_FAILURE;
    }
    return (psa_handle_t)(int32_t)result;
}

void psa_close(psa_handle_t handle)
{
    uint32_t result = 0u;

    (void)wt_psa_ffa_op(WT_PSA_FFA_OP_CLOSE, (uint64_t)(uint32_t)handle, 0u,
                        &result);
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    wt_psa_ffa_call_t desc;
    uint32_t result = 0u;

    desc.handle = (uint32_t)handle;
    desc.type = type;
    desc.in_len = (uint32_t)in_len;
    desc.out_len = (uint32_t)out_len;
    desc.in_vec = (uint64_t)(uintptr_t)in_vec;
    desc.out_vec = (uint64_t)(uintptr_t)out_vec;
    /* The SPMC reads the iovec arrays, copies the data both ways, and writes
     * each out_vec length back in place; the result comes back in the reply. */
    if (wt_psa_ffa_op(WT_PSA_FFA_OP_CALL, (uint64_t)(uintptr_t)&desc, 0u,
                      &result) != 0) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    return (psa_status_t)(int32_t)result;
}
