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

/* The FWU partition's registered restart hook, driven against a RAM flash
 * backend: a restart cancels any swap the previous instance armed, and a
 * backend that cannot disarm fails the restart closed. */

#include <stdio.h>
#include <string.h>

/* The partition table and its scheduler seams are production; the scheduler
 * itself is simulated. */
#include "../../../src/spm_partitions.c"

static wt_spm_sp_restore_fn g_restore;
static int32_t g_restore_id;
static int g_added;
static int g_armed;
static int g_disarm_calls;
static int g_fail_disarm;
static int g_failures;

static int test_flash_disarm(void* ctx)
{
    (void)ctx;
    g_disarm_calls++;
    if (g_fail_disarm != 0) {
        return -1;
    }
    g_armed = 0;
    return 0;
}

const wt_fwu_backend_t wt_fwu_flash_backend = {
    .disarm = test_flash_disarm,
    .capacity = 4096u,
    .align = 16u,
};

int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg)
{
    (void)runtime;
    (void)partition_id;
    (void)entry;
    (void)arg;
    g_added++;
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_set_restore(int32_t partition_id,
                             wt_spm_sp_restore_fn restore)
{
    g_restore_id = partition_id;
    g_restore = restore;
    return WT_FFM_SUCCESS;
}

int wt_spm_svc_transport(wt_ffm_runtime_t* runtime, struct wt_spm_call* call)
{
    (void)runtime;
    (void)call;
    return WT_FFM_ERROR_STATE;
}

static void check(int ok, const char* what)
{
    (void)printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

int main(void)
{
    check(wt_spm_fwu_start(NULL, PARTITION_FWU_ID) == WT_FFM_SUCCESS &&
          g_added == 1 && g_restore != NULL &&
          g_restore_id == PARTITION_FWU_ID,
          "WT-FWU-0003 FWU partition registers a restart hook");

    g_armed = 1;
    check(g_restore != NULL && g_restore(PARTITION_FWU_ID) == WT_FFM_SUCCESS &&
          g_disarm_calls == 1 && g_armed == 0,
          "WT-FWU-0003 restart hook cancels an armed swap");

    g_armed = 1;
    g_fail_disarm = 1;
    check(g_restore != NULL &&
          g_restore(PARTITION_FWU_ID) == WT_FFM_ERROR_STATE && g_armed == 1,
          "WT-FWU-0003 a restart that cannot disarm fails closed");

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: FWU partition restart hook\n");
    return 0;
}
