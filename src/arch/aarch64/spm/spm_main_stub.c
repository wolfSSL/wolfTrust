/* spm_main_stub.c
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

/* Placeholder Secure EL1 payload until the SPM runs here: prove the drop
 * from EL3 landed, negotiate the FF-A version with the SPMD, discover the
 * SPMC and SPMD ids, then leave through the monitor's test exit call. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"

#define WT_STUB_UNKNOWN_FID 0x840000F0u

void wt_spm_main(void);

static void stub_fail(const char* what, uint64_t value)
{
    wt_el3_puts("[SPM] FAIL ");
    wt_el3_puts(what);
    wt_el3_puts(" x0=0x");
    wt_el3_puthex(value, 8u);
    wt_el3_puts("\r\n");
    wt_platform_console_flush();
    (void)wt_mon_call(WT_MON_FID_PANIC, 0xF1u);
}

static void ffa_call(wt_ffa_regs_t* r, uint32_t fid, uint64_t x1)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = fid;
    r->x[1] = x1;
    wt_ffa_smc(r);
}

void wt_spm_main(void)
{
    wt_ffa_regs_t r;

    wt_el3_puts("[SPM] stub entered at S-EL1\r\n");

    ffa_call(&r, WT_FFA_VERSION, WT_FFA_VERSION_1_2);
    if ((uint32_t)r.x[0] != WT_FFA_VERSION_1_2) {
        stub_fail("ffa version", r.x[0]);
    }
    wt_el3_puts("[SPM] ffa version 1.2 negotiated\r\n");

    ffa_call(&r, WT_FFA_ID_GET, 0u);
    if (((uint32_t)r.x[0] != WT_FFA_SUCCESS32) || (r.x[2] != WT_FFA_ID_SPMC)) {
        stub_fail("ffa id_get", r.x[0]);
    }
    ffa_call(&r, WT_FFA_SPM_ID_GET, 0u);
    if (((uint32_t)r.x[0] != WT_FFA_SUCCESS32) || (r.x[2] != WT_FFA_ID_SPMD)) {
        stub_fail("ffa spm_id_get", r.x[0]);
    }
    ffa_call(&r, WT_FFA_FEATURES, WT_FFA_VERSION);
    if ((uint32_t)r.x[0] != WT_FFA_SUCCESS32) {
        stub_fail("ffa features(version)", r.x[0]);
    }
    ffa_call(&r, WT_STUB_UNKNOWN_FID, 0u);
    if (((uint32_t)r.x[0] != WT_FFA_ERROR) ||
        ((int32_t)(uint32_t)r.x[2] != WT_FFA_NOT_SUPPORTED)) {
        stub_fail("ffa unknown fid", r.x[0]);
    }
    wt_el3_puts("[SPM] ffa discovery ok id=0x8000 spmd=0x8001\r\n");

    wt_platform_console_flush();
    (void)wt_mon_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
}
