/* ffa_spmd.c
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

/* SPMD: FF-A calls arriving at the Secure physical instance (from the SPMC).
 * Every reply zeroes the unused result registers (11.2). */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa.h"

static unsigned int g_spmc_ready;

static void reply_error(wt_ffa_regs_t* r, int32_t code)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_ERROR;
    r->x[2] = (uint64_t)(uint32_t)code;
}

static void reply_success(wt_ffa_regs_t* r, uint64_t w2, uint64_t w3)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_SUCCESS32;
    r->x[2] = w2;
    r->x[3] = w3;
}

static int spmd_implements(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_ERROR:
        case WT_FFA_SUCCESS32:
        case WT_FFA_SUCCESS64:
        case WT_FFA_VERSION:
        case WT_FFA_FEATURES:
        case WT_FFA_ID_GET:
        case WT_FFA_SPM_ID_GET:
        case WT_FFA_MSG_WAIT:
        case WT_FFA_CONSOLE_LOG32:
        case WT_FFA_CONSOLE_LOG64:
            return 1;
        default:
            return 0;
    }
}

unsigned int wt_ffa_spmd_spmc_ready(void)
{
    return g_spmc_ready;
}

/* 13.12: w1 = count (bits 31:8 SBZ), characters tightly packed from w2/x2
 * upward; 1..24 characters over w2-w7, 1..128 over x2-x17. */
void wt_ffa_spmd_console_call(uint64_t* x, unsigned int is64)
{
    uint32_t count = (uint32_t)x[1];
    unsigned int per_reg = (is64 != 0u) ? 8u : 4u;
    unsigned int max = (is64 != 0u) ? 128u : 24u;
    unsigned int i;
    uint64_t reg;

    if (((count & 0xFFFFFF00u) != 0u) || (count < 1u) || (count > max)) {
        reply_error((wt_ffa_regs_t*)x, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    for (i = 0u; i < count; i++) {
        reg = x[2u + (i / per_reg)];
        wt_platform_console_putc((char)((reg >> (8u * (i % per_reg))) & 0xFFu));
    }
    reply_success((wt_ffa_regs_t*)x, 0u, 0u);
}

void wt_ffa_spmd_secure_call(wt_ffa_regs_t* r)
{
    uint32_t fid = (uint32_t)r->x[0];
    uint32_t w1 = (uint32_t)r->x[1];
    unsigned int i;

    switch (fid) {
        case WT_FFA_VERSION:
            for (i = 1u; i < 8u; i++) {
                r->x[i] = 0u;
            }
            r->x[0] = (uint64_t)(uint32_t)wt_ffa_version_reply(w1,
                                                               WT_FFA_VERSION_1_2);
            break;
        case WT_FFA_FEATURES:
            if (WT_FFA_FEATURES_IS_FID(w1) && spmd_implements(w1)) {
                reply_success(r, 0u, 0u);
            }
            else {
                reply_error(r, WT_FFA_NOT_SUPPORTED);
            }
            break;
        case WT_FFA_ID_GET:
            reply_success(r, WT_FFA_ID_SPMC, 0u);
            break;
        case WT_FFA_SPM_ID_GET:
            reply_success(r, WT_FFA_ID_SPMD, 0u);
            break;
        case WT_FFA_CONSOLE_LOG32:
            wt_ffa_spmd_console_call(r->x, 0u);
            break;
        case WT_FFA_MSG_WAIT:
            /* 5.5: the first MSG_WAIT from the SPMC ends its initialization. */
            if (g_spmc_ready == 0u) {
                g_spmc_ready = 1u;
                wt_el3_spmc_ready();
            }
            reply_error(r, WT_FFA_DENIED);
            break;
        default:
            reply_error(r, WT_FFA_NOT_SUPPORTED);
            break;
    }
}
