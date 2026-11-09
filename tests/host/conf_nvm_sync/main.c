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

/* The STM32H563 conformance NVM seam reports success only when the SVC
 * transport delivered the request and the privileged flash op succeeded. */

#include "conf_nvm.h"
#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"

#include <stdio.h>
#include <string.h>

static int g_transport_ret;
static int g_op_ret;
static int g_failures;

int wt_spm_sp_call(struct wt_spm_call* call)
{
    if (g_transport_ret != WT_FFM_SUCCESS) {
        return g_transport_ret;
    }
    call->ret_int = g_op_ret;
    return WT_FFM_SUCCESS;
}

static void check(int cond, const char* name)
{
    if (cond) {
        printf("PASS: %s\n", name);
    }
    else {
        printf("FAIL: %s\n", name);
        g_failures++;
    }
}

int main(void)
{
    uint8_t buf[16];

    (void)memset(buf, 0, sizeof(buf));
    g_transport_ret = WT_FFM_SUCCESS;
    g_op_ret = 0;
    check(wt_conf_nvm_sync(buf, sizeof(buf), 1) == 0,
          "delivered sync reports the flash result");
    g_op_ret = -1;
    check(wt_conf_nvm_sync(buf, sizeof(buf), 1) != 0,
          "delivered sync reports a flash failure");
    g_op_ret = 0;
    g_transport_ret = WT_FFM_ERROR_ARGUMENT;
    check(wt_conf_nvm_sync(buf, sizeof(buf), 1) != 0,
          "rejected transport never reports a sync that did not run");
    check(wt_conf_nvm_sync(buf, sizeof(buf), 0) != 0,
          "rejected transport never reports a reload that did not run");

    if (g_failures == 0) {
        printf("PASS: conf_nvm_sync transport status\n");
        return 0;
    }
    printf("FAIL: conf_nvm_sync (%d failures)\n", g_failures);
    return 1;
}
