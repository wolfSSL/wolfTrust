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

#include "wolftrust/spm.h"
#include "wolftrust/partition.h"
#include "wolftrust/ffm.h"
#include "wolftrust_manifest_generated.h"

#include <stdio.h>

static int ports_check_read(void* context, psa_client_id_t caller,
                            const void* address, size_t size)
{
    (void)context;
    (void)caller;
    (void)address;
    (void)size;
    return 0;
}

static int ports_check_write(void* context, psa_client_id_t caller,
                             void* address, size_t size)
{
    (void)context;
    (void)caller;
    (void)address;
    (void)size;
    return 0;
}

static int ports_dispatch(void* context, wt_ffm_runtime_t* runtime,
                          int32_t partition_id)
{
    (void)context;
    (void)runtime;
    (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

static void ports_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
}

static const wt_ffm_port_ops_t g_ports_ffm_ops = {
    ports_check_read,
    ports_check_write,
    ports_dispatch,
    ports_panic
};

static wt_ffm_runtime_t g_ports_ffm_runtime;

static int ports_fail(const char* what, int result)
{
    (void)fprintf(stderr, "FAIL: %s %s (%d)\n", WT_TEST_MANIFEST, what,
                  result);
    return 1;
}

int main(void)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    const wt_profile_capabilities_t* platform =
        wt_partitions_profile_capabilities();
    const wt_guest_config_t* configs;
    const wt_domain_descriptor_t* domain;
    wt_spm_t spm;
    size_t count;
    size_t i;
    size_t j;
    int result;

    result = wt_manifest_validate(manifest, WT_MANIFEST_FEATURE_IPC,
                                  platform);
    if (result != WT_MANIFEST_VALID)
        return ports_fail("rejected by wt_manifest_validate", result);

    result = wt_spm_init(&spm, manifest, WT_MANIFEST_FEATURE_IPC, platform);
    if (result != WT_SPM_VALID || wt_spm_manifest(&spm) != manifest)
        return ports_fail("rejected by wt_spm_init", result);

    result = wt_partitions_bind_manifest(manifest);
    if (result != 0)
        return ports_fail("rejected by wt_partitions_bind_manifest", result);

    configs = wt_partitions_config_table(&count);
    if (configs == NULL || count == 0U)
        return ports_fail("has no guest configuration", 0);
    for (i = 0U; i < count; i++) {
        domain = NULL;
        for (j = 0U; j < manifest->domain_count; j++) {
            if (manifest->domains[j].id ==
                    (wt_domain_id_t)configs[i].guest_id + 1U) {
                domain = &manifest->domains[j];
            }
        }
        if (domain == NULL)
            return ports_fail("has no domain for a guest", (int)i);
        result = wt_partition_validate_port_binding(&configs[i], domain);
        if (result != WT_PORT_VALID)
            return ports_fail("rejected by the port binding", result);
        result = wt_partition_validate_profile(platform,
            configs[i].port.provided_capabilities);
        if (result != WT_PORT_VALID)
            return ports_fail("rejected by the port profile", result);
    }

    result = wt_ffm_init(&g_ports_ffm_runtime, manifest, &g_ports_ffm_ops,
                         NULL);
    if (result != WT_FFM_SUCCESS)
        return ports_fail("rejected by wt_ffm_init", result);

    (void)printf("PASS: %s validated with the port's capabilities: "
                 "domains=%u partitions=%u\n", WT_TEST_MANIFEST,
                 (unsigned int)manifest->domain_count,
                 (unsigned int)manifest->partition_count);
    return 0;
}
