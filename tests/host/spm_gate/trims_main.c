/* trims_main.c
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

/* Built with every WT_FFM_SP_* trim at 0: the gate refuses each trimmed
 * call instead of serving it. */

#include "spm_host.h"
#include "wolftrust/spm_gate.h"

#include <stdio.h>
#include <string.h>

#if !defined(WT_FFM_SP_DOORBELL) || (WT_FFM_SP_DOORBELL != 0) || \
    !defined(WT_FFM_SP_RHANDLE) || (WT_FFM_SP_RHANDLE != 0) || \
    !defined(WT_FFM_SP_SKIP) || (WT_FFM_SP_SKIP != 0)
#error "trims_main.c runs with every WT_FFM_SP_* trim at 0"
#endif

#define TEST_PARTITION_ID 1

static const wt_service_descriptor_t g_services[] = {
    {
        "test_service", 0x1000U, 1U, WT_SERVICE_VERSION_RELAXED, 0x10U,
        0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "test_partition", TEST_PARTITION_ID, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "host-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

int main(void)
{
    static const int ops[] = {
        WT_SPM_OP_NOTIFY, WT_SPM_OP_CLEAR, WT_SPM_OP_SET_RHANDLE,
        WT_SPM_OP_SKIP
    };
    wt_spm_call_t call;
    size_t i;
    int failures = 0;

    if (wt_spm_host_init(&g_manifest, NULL, NULL) != WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "host SPM did not initialize\n");
        return 1;
    }
    for (i = 0U; i < sizeof(ops) / sizeof(ops[0]); i++) {
        (void)memset(&call, 0, sizeof(call));
        call.op = ops[i];
        call.partition_id = TEST_PARTITION_ID;
        call.notify_partition = TEST_PARTITION_ID;
        if (wt_spm_gate(&g_wt_spm, NULL, &call) != WT_FFM_ERROR_ARGUMENT) {
            (void)fprintf(stderr, "trimmed op %d was served\n", ops[i]);
            failures++;
        }
    }
    if (failures != 0) {
        return 1;
    }
    (void)printf("PASS: spm_gate trims refuse psa_notify, psa_clear, "
                 "psa_set_rhandle and psa_skip\n");
    return 0;
}
