/* production_main.c
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

#include "wolftrust/spm_core.h"
#include "wolftrust/spm.h"
#include "wolftrust/partition.h"
#include "wolftrust/ffm.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust_manifest_generated.h"
#include "psa_manifest/sid.h"
#include "psa_manifest/pid.h"
#include "memory_map.h"

#include <stdio.h>
#include <string.h>

int wt_spm_caller_can_write(psa_client_id_t caller, void* base, size_t len)
{
    (void)caller;
    (void)base;
    (void)len;
    return 0;
}

int main(void)
{
    wt_spm_t spm;
    wt_system_manifest_t invalid_manifest;
    wt_domain_descriptor_t invalid_domains[WT_MANIFEST_MAX_PARTITIONS];
    wt_memory_resource_t invalid_res[WT_MAX_MEMORY_REGIONS];
    wt_profile_capabilities_t limited_platform;
    wt_guest_config_t invalid_config;
    const wt_guest_config_t* configs;
    const wt_domain_descriptor_t* guest_domain;
    wt_secure_domain_t crypto_domain;
    wt_secure_domain_t tables[WT_MANIFEST_MAX_PARTITIONS];
    size_t table_count;
    size_t config_count;
    size_t domain_count;
    size_t i;
    size_t j;
    int result;

    result = wt_spm_init(&spm, wt_generated_manifest_get(),
                         WT_MANIFEST_FEATURE_IPC,
                         wt_partitions_profile_capabilities());
    if (result != WT_SPM_VALID || !wt_spm_ready(&spm)) {
        (void)fprintf(stderr, "production manifest rejected: %d\n", result);
        return 1;
    }

    limited_platform = *wt_partitions_profile_capabilities();
    limited_platform.capabilities &= ~WT_CAPABILITY_MEMORY_PROTECTION;
    result = wt_spm_init(&spm, wt_generated_manifest_get(),
                         WT_MANIFEST_FEATURE_IPC, &limited_platform);
    if (result != WT_SPM_ERROR_VALIDATION ||
            wt_spm_validation_result(&spm) != WT_MANIFEST_ERROR_DOMAIN ||
            wt_spm_ready(&spm)) {
        (void)fprintf(stderr,
                      "missing immutable platform capability was accepted\n");
        return 1;
    }

    result = wt_spm_init(&spm, wt_generated_manifest_get(),
                         WT_MANIFEST_FEATURE_IPC,
                         wt_partitions_profile_capabilities());
    if (result != WT_SPM_VALID || !wt_spm_ready(&spm)) {
        (void)fprintf(stderr, "production manifest restore rejected: %d\n",
                      result);
        return 1;
    }

    if (wt_partitions_check_manifest(wt_spm_manifest(&spm)) != 0) {
        (void)fprintf(stderr, "production partition rows rejected\n");
        return 1;
    }

    configs = wt_partitions_config_table(&config_count);
    if (config_count == 0U || spm.manifest->domain_count < 2U) {
        return 1;
    }
    guest_domain = &spm.manifest->domains[1];
    if (wt_partition_validate_port_binding(&configs[0], guest_domain) !=
            WT_PORT_VALID) {
        (void)fprintf(stderr, "production port binding rejected\n");
        return 1;
    }

    invalid_config = configs[0];
    invalid_config.port.provided_capabilities &=
        ~WT_PORT_CAPABILITY_VECTOR_READ_ALIAS;
    if (wt_partition_validate_port_binding(&invalid_config, guest_domain) !=
            WT_PORT_ERROR_CAPABILITY) {
        (void)fprintf(stderr, "missing port capability was accepted\n");
        return 1;
    }

    invalid_config = configs[0];
    invalid_config.port.vector_read_address = invalid_config.vector_table;
    if (wt_partition_validate_port_binding(&invalid_config, guest_domain) !=
            WT_PORT_ERROR_VECTOR_ALIAS) {
        (void)fprintf(stderr, "direct vector address was accepted as alias\n");
        return 1;
    }

    wt_spm_core_init();
    if (wt_spm_service_version(-1, SERVICE_ATTEST_SID) !=
            SERVICE_ATTEST_VERSION) {
        (void)fprintf(stderr, "SERVICE_ATTEST not registered by SID\n");
        return 1;
    }
    if (wt_spm_service_version(-1, SERVICE_HSM_SID) !=
            SERVICE_HSM_VERSION) {
        (void)fprintf(stderr, "SERVICE_HSM not registered by SID\n");
        return 1;
    }

    /* WT-FFM-0011 Phase B: the crypto Secure Partition now resolves to its own
     * secure private RAM, not the Non-secure guest memory it was conflated
     * with before. */
    if (wt_ffm_resolve_secure_domain(wt_spm_manifest(&spm), PARTITION_HSM_ID,
                                     &crypto_domain) != WT_SECURE_DOMAIN_OK) {
        (void)fprintf(stderr, "crypto Secure Partition domain not resolved\n");
        return 1;
    }
    if (!wt_secure_domain_contains(&crypto_domain, WT_SP_CRYPTO_STACK_BASE,
                                   4U, 1)) {
        (void)fprintf(stderr, "crypto SP does not own its secure stack\n");
        return 1;
    }
    if (wt_secure_domain_contains(&crypto_domain, WT_GUEST0_RAM_BASE, 4U, 0)) {
        (void)fprintf(stderr, "crypto SP still reaches Non-secure guest RAM\n");
        return 1;
    }

    domain_count = wt_spm_manifest(&spm)->domain_count;
    if (domain_count > sizeof(invalid_domains) / sizeof(invalid_domains[0])) {
        return 1;
    }

    /* WT-FFM-0011: the production partitions' tables are isolated from each
     * other and from SPM RAM, and none reaches the conformance window. */
    table_count = 0U;
    for (i = 0U; i < domain_count; i++) {
        const wt_domain_descriptor_t* domain =
            &wt_spm_manifest(&spm)->domains[i];

        if (domain->domain_class != WT_DOMAIN_CLASS_SECURE_PARTITION) {
            continue;
        }
        if (table_count >= sizeof(tables) / sizeof(tables[0]) ||
                wt_ffm_resolve_secure_domain(wt_spm_manifest(&spm),
                    domain->id, &tables[table_count]) !=
                    WT_SECURE_DOMAIN_OK) {
            (void)fprintf(stderr, "partition table not resolved\n");
            return 1;
        }
        table_count++;
    }
    if (table_count < 3U) {
        (void)fprintf(stderr, "production partitions missing\n");
        return 1;
    }
    for (i = 0U; i < table_count; i++) {
        if (!wt_secure_domain_excludes(&tables[i], WT_RAM_S_BASE,
                WT_L3_BANDS_BASE - WT_RAM_S_BASE)) {
            (void)fprintf(stderr, "partition %u reaches SPM RAM\n",
                          (unsigned int)tables[i].domain_id);
            return 1;
        }
#if WT_CONF_SP_DATA_SIZE != 0U
        if (!wt_secure_domain_excludes(&tables[i], WT_CONF_SP_DATA_BASE,
                                       WT_CONF_SP_DATA_SIZE)) {
            (void)fprintf(stderr,
                          "partition %u reaches the conformance window\n",
                          (unsigned int)tables[i].domain_id);
            return 1;
        }
#endif
        for (j = i + 1U; j < table_count; j++) {
            if (!wt_secure_domains_isolated(&tables[i], &tables[j], NULL,
                                            0U)) {
                (void)fprintf(stderr, "partitions %u and %u overlap\n",
                              (unsigned int)tables[i].domain_id,
                              (unsigned int)tables[j].domain_id);
                return 1;
            }
        }
    }
    /* The three bands belong to exactly their partitions. */
    if (wt_ffm_resolve_secure_domain(wt_spm_manifest(&spm),
            PARTITION_VAULT_ID, &crypto_domain) != WT_SECURE_DOMAIN_OK ||
            !wt_secure_domain_contains(&crypto_domain, WT_SP_VAULT_DATA_BASE,
                                       WT_SP_VAULT_DATA_SIZE, 1) ||
            !wt_secure_domain_excludes(&crypto_domain, WT_SP_ATTEST_DATA_BASE,
                                       WT_SP_ATTEST_DATA_SIZE) ||
            !wt_secure_domain_excludes(&crypto_domain, WT_SP_HSM_DATA_BASE,
                                       WT_SP_HSM_DATA_SIZE)) {
        (void)fprintf(stderr, "vault does not own exactly its band\n");
        return 1;
    }
    if (wt_ffm_resolve_secure_domain(wt_spm_manifest(&spm),
            PARTITION_ATTEST_ID, &crypto_domain) != WT_SECURE_DOMAIN_OK ||
            !wt_secure_domain_contains(&crypto_domain,
                                       WT_SP_ATTEST_DATA_BASE,
                                       WT_SP_ATTEST_DATA_SIZE, 1) ||
            !wt_secure_domain_excludes(&crypto_domain, WT_SP_VAULT_DATA_BASE,
                                       WT_SP_VAULT_DATA_SIZE) ||
            !wt_secure_domain_excludes(&crypto_domain, WT_SP_HSM_DATA_BASE,
                                       WT_SP_HSM_DATA_SIZE)) {
        (void)fprintf(stderr, "attestation does not own exactly its band\n");
        return 1;
    }
    if (wt_ffm_resolve_secure_domain(wt_spm_manifest(&spm),
            PARTITION_HSM_ID, &crypto_domain) != WT_SECURE_DOMAIN_OK ||
            !wt_secure_domain_contains(&crypto_domain, WT_SP_HSM_DATA_BASE,
                                       WT_SP_HSM_DATA_SIZE, 1) ||
            !wt_secure_domain_excludes(&crypto_domain, WT_SP_VAULT_DATA_BASE,
                                       WT_SP_VAULT_DATA_SIZE) ||
            !wt_secure_domain_excludes(&crypto_domain,
                                       WT_SP_ATTEST_DATA_BASE,
                                       WT_SP_ATTEST_DATA_SIZE)) {
        (void)fprintf(stderr, "crypto SP does not own exactly its band\n");
        return 1;
    }

    /* The guest rows are fixed from the manifest at build time: a manifest
     * whose guest policy differs from the rows is refused. */
    (void)memcpy(invalid_domains, wt_spm_manifest(&spm)->domains,
                 domain_count * sizeof(invalid_domains[0]));
    invalid_manifest = *wt_spm_manifest(&spm);
    invalid_manifest.domains = invalid_domains;
    invalid_domains[1].restart_policy.restart_limit = 7U;
    if (wt_partitions_check_manifest(&invalid_manifest) == 0) {
        (void)fprintf(stderr, "a different restart limit was accepted\n");
        return 1;
    }

    invalid_domains[1].restart_policy.restart_limit =
        wt_spm_manifest(&spm)->domains[1].restart_policy.restart_limit;
    invalid_domains[1].initial_lifecycle = WT_DOMAIN_LIFECYCLE_STOPPED;
    if (wt_partitions_check_manifest(&invalid_manifest) == 0) {
        (void)fprintf(stderr, "a different lifecycle was accepted\n");
        return 1;
    }

    /* An unsupported restart action still fails closed. */
    invalid_domains[1].initial_lifecycle =
        wt_spm_manifest(&spm)->domains[1].initial_lifecycle;
    invalid_domains[1].restart_policy.action = WT_RESTART_ACTION_NEVER;
    if (wt_partitions_check_manifest(&invalid_manifest) == 0) {
        (void)fprintf(stderr, "unsupported restart action was accepted\n");
        return 1;
    }

    /* A guest declared unprivileged misstates how it launches: refused. */
    invalid_domains[1].restart_policy.action = WT_RESTART_ACTION_DOMAIN;
    invalid_domains[1].privilege_state = WT_PRIVILEGE_STATE_UNPRIVILEGED;
    if (wt_partitions_check_manifest(&invalid_manifest) == 0) {
        (void)fprintf(stderr, "unprivileged guest declaration was accepted\n");
        return 1;
    }

    /* A guest window that differs from the row's constant window: refused. */
    invalid_domains[1].privilege_state = WT_PRIVILEGE_STATE_PRIVILEGED;
    if (invalid_domains[1].memory_resource_count == 0U ||
            invalid_domains[1].memory_resource_count > WT_MAX_MEMORY_REGIONS) {
        (void)fprintf(stderr, "the guest domain has no resources to vary\n");
        return 1;
    }
    (void)memcpy(invalid_res, invalid_domains[1].memory_resources,
                 invalid_domains[1].memory_resource_count *
                 sizeof(invalid_res[0]));
    invalid_res[0].size += 32U;
    invalid_domains[1].memory_resources = invalid_res;
    if (wt_partitions_check_manifest(&invalid_manifest) == 0) {
        (void)fprintf(stderr, "a different guest window was accepted\n");
        return 1;
    }

    /* The real manifest matches the rows; its guests declare READY. */
    if (wt_partitions_check_manifest(wt_spm_manifest(&spm)) != 0) {
        (void)fprintf(stderr, "the real manifest was refused\n");
        return 1;
    }
    configs = wt_partitions_config_table(&config_count);
    if (configs[0].initial_state != WT_GUEST_READY) {
        (void)fprintf(stderr, "restored guest lifecycle not READY\n");
        return 1;
    }

    (void)printf("production manifest and port capabilities accepted: "
                 "profile=%u domains=%zu\n",
                 (unsigned int)spm.manifest->isolation_profile,
                 spm.manifest->domain_count);
    return 0;
}
