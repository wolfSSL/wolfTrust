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

/* WT-FFA-0001 / WT-FFA-0002: the FF-A function-id table, status codes, id
 * spaces, and the version negotiation rules of DEN0077A 13.2. */

#include "wolftrust/arch/aarch64/ffa_abi.h"

#include <stdint.h>
#include <stdio.h>

static int checks;
static int failures;

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

static const uint32_t g_fids[] = {
    WT_FFA_ERROR, WT_FFA_SUCCESS32, WT_FFA_SUCCESS64, WT_FFA_INTERRUPT,
    WT_FFA_VERSION, WT_FFA_FEATURES, WT_FFA_RX_RELEASE, WT_FFA_RXTX_MAP32,
    WT_FFA_RXTX_MAP64, WT_FFA_RXTX_UNMAP, WT_FFA_PARTITION_INFO_GET,
    WT_FFA_ID_GET, WT_FFA_MSG_WAIT, WT_FFA_YIELD, WT_FFA_RUN,
    WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_MSG_SEND_DIRECT_REQ64,
    WT_FFA_MSG_SEND_DIRECT_RESP32, WT_FFA_MSG_SEND_DIRECT_RESP64,
    WT_FFA_NORMAL_WORLD_RESUME, WT_FFA_NOTIFICATION_BITMAP_CREATE,
    WT_FFA_RX_ACQUIRE, WT_FFA_SPM_ID_GET, WT_FFA_MSG_SEND2,
    WT_FFA_CONSOLE_LOG32, WT_FFA_CONSOLE_LOG64,
    WT_FFA_PARTITION_INFO_GET_REGS, WT_FFA_MSG_SEND_DIRECT_REQ2,
    WT_FFA_MSG_SEND_DIRECT_RESP2
};

static const int32_t g_codes[] = {
    WT_FFA_NOT_SUPPORTED, WT_FFA_INVALID_PARAMETERS, WT_FFA_NO_MEMORY,
    WT_FFA_BUSY, WT_FFA_INTERRUPTED, WT_FFA_DENIED, WT_FFA_RETRY,
    WT_FFA_ABORTED, WT_FFA_NO_DATA, WT_FFA_NOT_READY
};

int main(void)
{
    size_t n = sizeof(g_fids) / sizeof(g_fids[0]);
    size_t i;
    size_t j;
    int ok;

    printf("WT-FFA-0001 / WT-FFA-0002 (function ids, status codes, version)\n");

    ok = 1;
    for (i = 0u; i < n; i++) {
        ok = ok && wt_ffa_fid_in_range(g_fids[i]);
        ok = ok && ((g_fids[i] & 0x80000000u) != 0u);
    }
    check(ok, "every function id sits in the reserved FF-A fast-call ranges");

    ok = 1;
    for (i = 0u; i < n; i++) {
        for (j = i + 1u; j < n; j++) {
            ok = ok && (g_fids[i] != g_fids[j]);
        }
    }
    check(ok, "function ids are unique");

    check((WT_FFA_SUCCESS64 & 0x40000000u) != 0u &&
          (WT_FFA_SUCCESS32 & 0x40000000u) == 0u &&
          (WT_FFA_SUCCESS64 & 0xFFFFu) == (WT_FFA_SUCCESS32 & 0xFFFFu),
          "SMC64 variants differ from SMC32 only in bit 30");
    check(!wt_ffa_fid_in_range(0x8400005Fu) && !wt_ffa_fid_in_range(0x84000100u) &&
          !wt_ffa_fid_in_range(0xC3800004u) && wt_ffa_fid_in_range(0x840000FFu) &&
          wt_ffa_fid_in_range(0xC4000060u),
          "range check excludes neighbours and the OEM test calls");

    ok = 1;
    for (i = 0u; i < sizeof(g_codes) / sizeof(g_codes[0]); i++) {
        ok = ok && (g_codes[i] == -(int32_t)(i + 1u));
    }
    check(ok, "status codes are -1..-10 in specification order");

    check(WT_FFA_VERSION_1_2 == WT_FFA_VERSION_MAKE(1u, 2u) &&
          WT_FFA_VERSION_MAJOR_OF(WT_FFA_VERSION_1_2) == 1u &&
          WT_FFA_VERSION_MINOR_OF(WT_FFA_VERSION_1_2) == 2u,
          "version 1.2 encodes as major 1 minor 2");
    check(wt_ffa_version_reply(WT_FFA_VERSION_1_2, WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "a 1.2 caller is told 1.2");
    check(wt_ffa_version_reply(WT_FFA_VERSION_MAKE(1u, 0u), WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "a 1.0 caller is told the callee version 1.2");
    check(wt_ffa_version_reply(WT_FFA_VERSION_MAKE(2u, 0u), WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "an incompatible 2.0 caller is told 1.2 rather than refused");
    check(wt_ffa_version_reply(0x80010002u, WT_FFA_VERSION_1_2) ==
              WT_FFA_NOT_SUPPORTED,
          "bit 31 set in the input version is NOT_SUPPORTED");
    check(wt_ffa_version_compatible(WT_FFA_VERSION_MAKE(1u, 0u), WT_FFA_VERSION_1_2) &&
          wt_ffa_version_compatible(WT_FFA_VERSION_1_2, WT_FFA_VERSION_1_2),
          "same major and caller minor <= callee minor is compatible");
    check(!wt_ffa_version_compatible(WT_FFA_VERSION_MAKE(1u, 3u), WT_FFA_VERSION_1_2) &&
          !wt_ffa_version_compatible(WT_FFA_VERSION_MAKE(2u, 0u), WT_FFA_VERSION_1_2),
          "greater minor or different major is incompatible");

    check((WT_FFA_ID_SPMC & 0x8000u) != 0u && (WT_FFA_ID_SPMD & 0x8000u) != 0u &&
          (WT_FFA_ID_SP_FIRST & 0x8000u) != 0u && WT_FFA_ID_SPMC != WT_FFA_ID_SPMD &&
          WT_FFA_ID_SP_FIRST > WT_FFA_ID_SPMD && WT_FFA_ID_NS_PRIMARY == 0u,
          "SPM-allocated ids carry bit 15, the primary NS endpoint is id 0");
    check(WT_FFA_FEATURES_IS_FID(WT_FFA_VERSION) && !WT_FFA_FEATURES_IS_FID(0x3u),
          "FFA_FEATURES tells function ids from feature ids by bit 31");

    printf("ffa_abi: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
