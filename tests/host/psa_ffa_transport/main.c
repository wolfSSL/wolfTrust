/* main.c
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

/* WT-FFA-0012: the register-only PSA client transport over the FF-A NS physical
 * instance. The client (src/client/psa_ffa_transport.c) marshals each PSA
 * framework operation into an FF-A direct request; the SPMC handler
 * (psa_service.c) answers it. The seam relays one straight into the other, so
 * both production sources are exercised end to end. */

#include "psa/client.h"

#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/psa_ffa.h"

#include <stdint.h>
#include <stdio.h>

static int checks;
static int failures;

void wt_ffa_transport_smc(wt_ffa_regs_t* r)
{
    if (((uint32_t)r->x[0] == WT_FFA_MSG_SEND_DIRECT_REQ32) &&
        (wt_ffa_direct_receiver(r->x[1]) == WT_FFA_ID_PSA)) {
        (void)wt_spm_psa_framework(r);
        return;
    }
    r->x[0] = WT_FFA_ERROR;
    r->x[2] = (uint64_t)(uint32_t)WT_FFA_NOT_SUPPORTED;
}

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

int main(void)
{
    psa_handle_t handle;
    psa_handle_t reused;
    psa_handle_t refused;
    psa_handle_t many[WT_PSA_FFA_MAX_CONN + 1u];
    unsigned int i;
    psa_handle_t hcall;
    psa_invec civ;
    psa_outvec cov;
    psa_status_t st;
    static const uint8_t ci[4] = { 1u, 2u, 3u, 4u };
    uint8_t co[4] = { 0u, 0u, 0u, 0u };
    static uint8_t area[512] __attribute__((aligned(16)));
    uint64_t lo;
    uint64_t hi;
    wt_psa_ffa_call_t* d;
    psa_invec* div;
    psa_outvec* dov;
    uint8_t* dib;
    uint8_t* dob;

    printf("WT-FFA-0012 (PSA client transport over FF-A)\n");

    check(psa_framework_version() == PSA_FRAMEWORK_VERSION,
          "psa_framework_version returns the framework version over the transport");
    check(psa_version(WT_PSA_FFA_SID_TEST) == WT_PSA_FFA_SID_TEST_VERSION,
          "psa_version returns the service version for a known service");
    check(psa_version(0x9999u) == PSA_VERSION_NONE,
          "psa_version returns PSA_VERSION_NONE for an unknown service");

    handle = psa_connect(WT_PSA_FFA_SID_TEST, WT_PSA_FFA_SID_TEST_VERSION);
    check(PSA_HANDLE_IS_VALID(handle),
          "psa_connect to a known service returns a valid handle");

    refused = psa_connect(0x9999u, 1u);
    check(!PSA_HANDLE_IS_VALID(refused) &&
              (psa_status_t)refused == PSA_ERROR_CONNECTION_REFUSED,
          "psa_connect to an unknown service is refused");
    check((psa_status_t)psa_connect(WT_PSA_FFA_SID_TEST,
                                    WT_PSA_FFA_SID_TEST_VERSION + 1u) ==
              PSA_ERROR_CONNECTION_REFUSED,
          "psa_connect with an incompatible version is refused");

    psa_close(handle);
    reused = psa_connect(WT_PSA_FFA_SID_TEST, 0u);
    check(PSA_HANDLE_IS_VALID(reused),
          "a closed slot is reusable and version 0 accepts any compatible version");
    psa_close(reused);

    for (i = 0u; i < WT_PSA_FFA_MAX_CONN; i++) {
        many[i] = psa_connect(WT_PSA_FFA_SID_TEST, WT_PSA_FFA_SID_TEST_VERSION);
    }
    check(PSA_HANDLE_IS_VALID(many[WT_PSA_FFA_MAX_CONN - 1u]),
          "the connection table holds WT_PSA_FFA_MAX_CONN live connections");
    many[WT_PSA_FFA_MAX_CONN] =
        psa_connect(WT_PSA_FFA_SID_TEST, WT_PSA_FFA_SID_TEST_VERSION);
    check((psa_status_t)many[WT_PSA_FFA_MAX_CONN] == PSA_ERROR_CONNECTION_BUSY,
          "a full connection table refuses further connects with CONNECTION_BUSY");
    for (i = 0u; i < WT_PSA_FFA_MAX_CONN; i++) {
        psa_close(many[i]);
    }

    /* Data-carrying psa_call: the whole path client -> seam -> SPMC copy, then
     * wt_psa_call_run directly for the validation rejections (WT-FFA-0009). */
    wt_spm_psa_init(0u, ~(uint64_t)0);
    hcall = psa_connect(WT_PSA_FFA_SID_TEST, WT_PSA_FFA_SID_TEST_VERSION);
    civ.base = ci;
    civ.len = sizeof(ci);
    cov.base = co;
    cov.len = sizeof(co);
    st = psa_call(hcall, 0, &civ, 1u, &cov, 1u);
    check(st == PSA_SUCCESS && cov.len == sizeof(ci) &&
              co[0] == (uint8_t)~ci[0] && co[3] == (uint8_t)~ci[3],
          "psa_call round-trips through the transport and the SPMC copy");

    lo = (uint64_t)(uintptr_t)area;
    hi = lo + (uint64_t)sizeof(area);
    d = (wt_psa_ffa_call_t*)(void*)&area[0];
    div = (psa_invec*)(void*)&area[64];
    dov = (psa_outvec*)(void*)&area[128];
    dib = &area[192];
    dob = &area[256];
    d->handle = (uint32_t)hcall;
    d->type = 0;
    d->in_len = 1u;
    d->out_len = 1u;
    d->in_vec = (uint64_t)(uintptr_t)div;
    d->out_vec = (uint64_t)(uintptr_t)dov;
    div[0].base = dib;
    div[0].len = 4u;
    dov[0].base = dob;
    dov[0].len = 4u;
    dib[0] = 0xAAu;
    dib[3] = 0x55u;
    check(wt_psa_call_run((uint64_t)(uintptr_t)d, lo, hi) == PSA_SUCCESS &&
              dob[0] == (uint8_t)~0xAAu && dov[0].len == 4u,
          "wt_psa_call_run copies and transforms buffers inside the window");

    div[0].base = (const void*)(uintptr_t)(lo - 16u);
    check((psa_status_t)wt_psa_call_run((uint64_t)(uintptr_t)d, lo, hi) ==
              PSA_ERROR_PROGRAMMER_ERROR,
          "an in-vec buffer outside the Non-secure window is refused");
    div[0].base = dib;

    d->in_len = PSA_MAX_IOVEC + 1u;
    check((psa_status_t)wt_psa_call_run((uint64_t)(uintptr_t)d, lo, hi) ==
              PSA_ERROR_PROGRAMMER_ERROR,
          "an iovec count over PSA_MAX_IOVEC is refused");
    d->in_len = 1u;

    d->handle = 0x777u;
    check((psa_status_t)wt_psa_call_run((uint64_t)(uintptr_t)d, lo, hi) ==
              PSA_ERROR_PROGRAMMER_ERROR,
          "a call on a dead handle is refused");
    d->handle = (uint32_t)hcall;

    check((psa_status_t)wt_psa_call_run(lo - 64u, lo, hi) ==
              PSA_ERROR_PROGRAMMER_ERROR,
          "a parameter block outside the Non-secure window is refused");
    psa_close(hcall);

    printf("psa_ffa_transport: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
