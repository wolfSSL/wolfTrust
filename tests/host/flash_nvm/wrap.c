/* wrap.c
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

/* The conformance DRIVER partition's trap wrappers (conf_nvm_sync.c) against
 * a gate stand-in: a trap the gate refuses must never read as success. */

#include "conf_nvm.h"

#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"

#include <stdint.h>
#include <stdio.h>

static int g_gate_status;
static int g_gate_ret;
static int g_failures;

int wt_spm_sp_call(struct wt_spm_call* call)
{
    if (g_gate_status == WT_FFM_SUCCESS) {
        call->ret_int = g_gate_ret;
    }
    return g_gate_status;
}

static void check(int cond, const char *name)
{
    printf("%s: %s\n", (cond != 0) ? "PASS" : "FAIL", name);
    if (cond == 0) {
        g_failures++;
    }
}

int main(void)
{
    uint8_t buf[4] = { 0 };

    g_gate_status = WT_FFM_SUCCESS;
    g_gate_ret = 0;
    check(wt_conf_nvm_sync(buf, sizeof(buf), 1) == 0,
          "an NVM sync the gate runs returns its result");
    check(wt_conf_irq_set(1) == 0,
          "an interrupt poke the gate runs returns its result");
    g_gate_ret = -1;
    check(wt_conf_nvm_sync(buf, sizeof(buf), 0) == -1,
          "a failed NVM sync reads as a failure");
    g_gate_status = WT_FFM_ERROR_ARGUMENT;
    g_gate_ret = 0;
    check(wt_conf_nvm_sync(buf, sizeof(buf), 1) != 0,
          "an NVM store the gate refuses is not a success");
    check(wt_conf_nvm_sync(buf, sizeof(buf), 0) != 0,
          "an NVM load the gate refuses is not a success");
    check(wt_conf_irq_set(1) != 0,
          "an interrupt raise the gate refuses is not a success");
    check(wt_conf_irq_set(0) != 0,
          "an interrupt quiesce the gate refuses is not a success");

    if (g_failures == 0) {
        printf("PASS: conformance trap wrappers\n");
        return 0;
    }
    printf("FAIL: conformance trap wrappers (%d failures)\n", g_failures);
    return 1;
}
