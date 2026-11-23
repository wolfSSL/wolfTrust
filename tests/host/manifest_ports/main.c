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
#include "wolftrust/spm_tables.h"
#include "wolftrust_manifest_generated.h"

#include <stdio.h>
#include <string.h>

static wt_spm_service_t g_ports_services[WT_SPM_MAX_SERVICES];
static wt_spm_sp_ipc_t g_ports_sps[WT_SPM_MAX_SPS];
static wt_spm_irq_t g_ports_irqs[WT_SPM_MAX_SERVICES];

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
    wt_spm_tables_t tables;
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

    (void)memset(&tables, 0, sizeof(tables));
    tables.services = g_ports_services;
    tables.sps = g_ports_sps;
    tables.irqs = g_ports_irqs;
    tables.irq_cap = WT_SPM_MAX_SERVICES;
    result = wt_spm_tables_derive(manifest, &tables);
    if (result != WT_SPM_OK)
        return ports_fail("rejected by wt_spm_tables_derive", result);

    (void)printf("PASS: %s validated with the port's capabilities: "
                 "domains=%u partitions=%u\n", WT_TEST_MANIFEST,
                 (unsigned int)manifest->domain_count,
                 (unsigned int)manifest->partition_count);
    return 0;
}
