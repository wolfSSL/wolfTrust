/* psa_ffa_transport_arch.c
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

/* AArch64 binding of the PSA client transport. The WolfTrust_FFM_* entry
 * points the operating-system-neutral client (src/client/psa_ffm_client.c)
 * calls are the CMSE veneers on Armv8-M; here each one is carried as an FF-A
 * direct request to the PSA framework endpoint over the SMC conduit, hiding
 * the preemption resume loop (an FFA_INTERRUPT return is resumed with FFA_RUN
 * until the direct response arrives). */

#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/psa_ffa.h"
#include "wolftrust/ffm_veneer.h"
#include "wolftrust/arch/aarch64/psa_ffa_transport.h"

#include "psa/client.h"
#include "psa/error.h"

#if defined(__aarch64__)
static void transport_smc(wt_ffa_regs_t* r)
{
    wt_ffa_smc(r);
}
#else
static void transport_smc(wt_ffa_regs_t* r)
{
    wt_ffa_transport_smc(r);
}
#endif

int wt_psa_ffa_op(uint32_t op, uint64_t a0, uint64_t a1, uint32_t* result)
{
    wt_ffa_regs_t r;
    unsigned int i;
    unsigned int guard = 0u;

    for (i = 0u; i < 8u; i++) {
        r.x[i] = 0u;
    }
    r.x[0] = WT_FFA_MSG_SEND_DIRECT_REQ32;
    r.x[1] = ((uint64_t)WT_FFA_ID_NS_PRIMARY << 16) | WT_FFA_ID_PSA;
    r.x[3] = op;
    r.x[4] = a0;
    r.x[5] = a1;
    for (;;) {
        transport_smc(&r);
        if ((uint32_t)r.x[0] != WT_FFA_INTERRUPT) {
            break;
        }
        if (++guard > WT_PSA_FFA_MAX_RESUME) {
            return -1;
        }
        for (i = 0u; i < 8u; i++) {
            r.x[i] = 0u;
        }
        r.x[0] = WT_FFA_RUN;
        r.x[1] = (uint64_t)WT_FFA_ID_PSA << 16;
    }
    if ((uint32_t)r.x[0] != WT_FFA_MSG_SEND_DIRECT_RESP32) {
        return -1;
    }
    *result = (uint32_t)r.x[3];
    return 0;
}

uint32_t WolfTrust_FFM_FrameworkVersion(void)
{
    uint32_t result = 0u;

    if (wt_psa_ffa_op(WT_PSA_FFA_OP_FRAMEWORK_VERSION, 0u, 0u, &result) != 0) {
        return 0u;
    }
    return result;
}

uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid)
{
    uint32_t result = 0u;

    if (wt_psa_ffa_op(WT_PSA_FFA_OP_SERVICE_VERSION, sid, 0u, &result) != 0) {
        return PSA_VERSION_NONE;
    }
    return result;
}

int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version)
{
    uint32_t result = 0u;

    if (wt_psa_ffa_op(WT_PSA_FFA_OP_CONNECT, sid, version, &result) != 0) {
        return (int32_t)PSA_ERROR_COMMUNICATION_FAILURE;
    }
    return (int32_t)result;
}

int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                          wt_ffm_veneer_iovec_t* ns_iovec)
{
    uint32_t result = 0u;
    uint64_t a1 = ((uint64_t)(uint32_t)type << 32) | (uint64_t)(uint32_t)handle;

    if (wt_psa_ffa_op(WT_PSA_FFA_OP_CALL, (uint64_t)(uintptr_t)ns_iovec, a1,
                      &result) != 0) {
        return (int32_t)PSA_ERROR_COMMUNICATION_FAILURE;
    }
    return (int32_t)result;
}

void WolfTrust_FFM_Close(int32_t handle)
{
    uint32_t result = 0u;

    (void)wt_psa_ffa_op(WT_PSA_FFA_OP_CLOSE, (uint64_t)(uint32_t)handle, 0u,
                        &result);
}
