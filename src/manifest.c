/* manifest.c
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

#include "wolftrust/manifest.h"

static int wt_manifest_name_valid(const char* name)
{
    size_t i;

    if (name == NULL)
        return 0;

    for (i = 0U; i <= WT_MANIFEST_NAME_MAX; i++) {
        unsigned char value = (unsigned char)name[i];

        if (value == '\0')
            return i != 0U;

        if (i == 0U) {
            if (!((value >= (unsigned char)'A' &&
                    value <= (unsigned char)'Z') ||
                    value == (unsigned char)'_')) {
                return 0;
            }
        }
        else if (!((value >= (unsigned char)'A' &&
                value <= (unsigned char)'Z') ||
                (value >= (unsigned char)'0' &&
                 value <= (unsigned char)'9') ||
                value == (unsigned char)'_')) {
            return 0;
        }
    }

    return 0;
}

static int wt_manifest_string_equal(const char* first, const char* second)
{
    size_t i;

    for (i = 0U; i <= WT_MANIFEST_NAME_MAX; i++) {
        if (first[i] != second[i])
            return 0;
        if (first[i] == '\0')
            return 1;
    }

    return 0;
}

static size_t wt_manifest_name_length(const char* name)
{
    size_t length = 0U;

    while (name[length] != '\0')
        length++;

    return length;
}

static int wt_manifest_name_equals_generated(const char* name,
                                             const char* base,
                                             const char* suffix)
{
    size_t name_length = wt_manifest_name_length(name);
    size_t base_length = wt_manifest_name_length(base);
    size_t suffix_length = wt_manifest_name_length(suffix);
    size_t i;

    if (name_length != base_length + suffix_length)
        return 0;

    for (i = 0U; i < base_length; i++) {
        if (name[i] != base[i])
            return 0;
    }

    for (i = 0U; i < suffix_length; i++) {
        if (name[base_length + i] != suffix[i])
            return 0;
    }

    return 1;
}

static char wt_manifest_generated_char(const char* base, size_t base_length,
                                       const char* suffix, size_t index)
{
    if (index < base_length)
        return base[index];

    return suffix[index - base_length];
}

static int wt_manifest_generated_names_equal(const char* first_base,
                                             const char* first_suffix,
                                             const char* second_base,
                                             const char* second_suffix)
{
    size_t first_base_length = wt_manifest_name_length(first_base);
    size_t first_suffix_length = wt_manifest_name_length(first_suffix);
    size_t second_base_length = wt_manifest_name_length(second_base);
    size_t second_suffix_length = wt_manifest_name_length(second_suffix);
    size_t total_length = first_base_length + first_suffix_length;
    size_t i;

    if (total_length != second_base_length + second_suffix_length)
        return 0;

    for (i = 0U; i < total_length; i++) {
        if (wt_manifest_generated_char(first_base, first_base_length,
                first_suffix, i) !=
                wt_manifest_generated_char(second_base, second_base_length,
                    second_suffix, i)) {
            return 0;
        }
    }

    return 1;
}

static int wt_manifest_partition_symbol_collision(
    const char* name, const wt_partition_manifest_t* partition)
{
    if (partition->framework_version != WT_FFM_VERSION_1_1)
        return 0;

    return wt_manifest_name_equals_generated(name, partition->name,
               "_MODEL_IPC") ||
           wt_manifest_name_equals_generated(name, partition->name,
               "_MODEL_SFN");
}

static int wt_manifest_service_symbol_collision(
    const char* name, const wt_partition_manifest_t* partition,
    const wt_service_descriptor_t* service)
{
    if (wt_manifest_name_equals_generated(name, service->name, "_SID") ||
            wt_manifest_name_equals_generated(name, service->name,
                                               "_VERSION")) {
        return 1;
    }

    if (partition->model == WT_PARTITION_MODEL_IPC &&
            wt_manifest_name_equals_generated(name, service->name,
                                               "_SIGNAL")) {
        return 1;
    }

    if (service->connection_based == 0U &&
            wt_manifest_name_equals_generated(name, service->name,
                                               "_HANDLE")) {
        return 1;
    }

    return 0;
}

static int wt_manifest_service_model_symbol_collision(
    const wt_partition_manifest_t* model_partition,
    const wt_partition_manifest_t* service_partition,
    const wt_service_descriptor_t* service)
{
    if (model_partition->framework_version != WT_FFM_VERSION_1_1)
        return 0;

    if (wt_manifest_generated_names_equal(model_partition->name,
            "_MODEL_IPC", service->name, "_SID") ||
            wt_manifest_generated_names_equal(model_partition->name,
                "_MODEL_IPC", service->name, "_VERSION") ||
            wt_manifest_generated_names_equal(model_partition->name,
                "_MODEL_SFN", service->name, "_SID") ||
            wt_manifest_generated_names_equal(model_partition->name,
                "_MODEL_SFN", service->name, "_VERSION")) {
        return 1;
    }

    if (service_partition->model == WT_PARTITION_MODEL_IPC &&
            (wt_manifest_generated_names_equal(model_partition->name,
                "_MODEL_IPC", service->name, "_SIGNAL") ||
             wt_manifest_generated_names_equal(model_partition->name,
                "_MODEL_SFN", service->name, "_SIGNAL"))) {
        return 1;
    }

    if (service->connection_based == 0U &&
            (wt_manifest_generated_names_equal(model_partition->name,
                "_MODEL_IPC", service->name, "_HANDLE") ||
             wt_manifest_generated_names_equal(model_partition->name,
                "_MODEL_SFN", service->name, "_HANDLE"))) {
        return 1;
    }

    return 0;
}

static int wt_manifest_signal_valid(uint32_t signal)
{
    if (signal == 0U || (signal & WT_MANIFEST_RESERVED_SIGNALS) != 0U)
        return 0;

    return (signal & (signal - 1U)) == 0U;
}

static int wt_manifest_digest_valid(const uint8_t* digest, size_t size)
{
    uint8_t aggregate = 0U;
    size_t i;

    if (digest == NULL || size != WT_MANIFEST_DIGEST_SIZE)
        return 0;

    for (i = 0U; i < size; i++)
        aggregate |= digest[i];

    return aggregate != 0U;
}

static const wt_domain_descriptor_t* wt_manifest_find_domain(
    const wt_system_manifest_t* manifest, wt_domain_id_t id)
{
    size_t i;

    for (i = 0U; i < manifest->domain_count; i++) {
        if (manifest->domains[i].id == id)
            return &manifest->domains[i];
    }

    return NULL;
}

static int wt_manifest_validate_ffm_resources(
    const wt_system_manifest_t* manifest)
{
    size_t i;
    size_t j;

    for (i = 0U; i < manifest->domain_count; i++) {
        const wt_domain_descriptor_t* domain = &manifest->domains[i];

        /* The dispatcher unmasks a guest's peripheral lines before its NS
         * bank is reinstated, so an IRQ-driven Non-secure application is
         * refused until that unmask is deferred out of the dispatch window. */
        if (domain->domain_class == WT_DOMAIN_CLASS_NONSECURE_APPLICATION &&
                domain->interrupt_resource_count != 0U) {
            return WT_MANIFEST_ERROR_INTERRUPT;
        }

        if (domain->domain_class != WT_DOMAIN_CLASS_SECURE_PARTITION)
            continue;

        for (j = 0U; j < domain->memory_resource_count; j++) {
            const wt_memory_resource_t* resource =
                &domain->memory_resources[j];

            if ((resource->attributes & WT_MEMORY_ATTR_DEVICE) != 0U &&
                    (resource->attributes & WT_MEMORY_ATTR_SHARED) != 0U) {
                return WT_MANIFEST_ERROR_RESOURCE_OWNERSHIP;
            }
        }

        for (j = 0U; j < domain->interrupt_resource_count; j++) {
            if ((domain->interrupt_resources[j].attributes &
                    WT_INTERRUPT_ATTR_SHARED) != 0U) {
                return WT_MANIFEST_ERROR_RESOURCE_OWNERSHIP;
            }
        }
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_header(const wt_system_manifest_t* manifest,
                                       uint32_t supported_features,
                                       const wt_profile_capabilities_t* platform)
{
    int ret;

    if (manifest->format_version != WT_MANIFEST_FORMAT_VERSION)
        return WT_MANIFEST_ERROR_FORMAT;

    if (!wt_manifest_name_valid(manifest->generator_version))
        return WT_MANIFEST_ERROR_GENERATOR;

    if (!wt_manifest_digest_valid(manifest->input_digest,
                                  manifest->input_digest_size)) {
        return WT_MANIFEST_ERROR_DIGEST;
    }

    if ((supported_features & ~WT_MANIFEST_FEATURE_MASK) != 0U ||
            (supported_features & WT_MANIFEST_FEATURE_IPC) == 0U ||
            (manifest->features & ~supported_features) != 0U ||
            (manifest->features & WT_MANIFEST_FEATURE_IPC) == 0U) {
        return WT_MANIFEST_ERROR_FEATURE;
    }

    if (manifest->limits.max_partitions == 0U ||
            manifest->limits.max_partitions > WT_MANIFEST_MAX_PARTITIONS ||
            manifest->limits.max_services_per_partition == 0U ||
            manifest->limits.max_services_per_partition >
                WT_MANIFEST_MAX_SERVICES ||
            manifest->limits.max_dependencies_per_partition == 0U ||
            manifest->limits.max_dependencies_per_partition >
                WT_MANIFEST_MAX_DEPENDENCIES ||
            manifest->limits.max_stateless_handles < 32U) {
        return WT_MANIFEST_ERROR_LIMIT;
    }

    if (manifest->partition_count == 0U ||
            manifest->partition_count > manifest->limits.max_partitions ||
            manifest->partitions == NULL) {
        return WT_MANIFEST_ERROR_LIMIT;
    }

    if (manifest->profile_capabilities == NULL || manifest->domains == NULL ||
            platform == NULL)
        return WT_MANIFEST_ERROR_ARGUMENT;

    if ((manifest->profile_capabilities->capabilities &
            ~platform->capabilities) != 0U ||
            manifest->profile_capabilities->max_domains >
                platform->max_domains ||
            manifest->profile_capabilities->max_memory_resources_per_domain >
                platform->max_memory_resources_per_domain ||
            manifest->profile_capabilities->max_interrupts_per_domain >
                platform->max_interrupts_per_domain) {
        return WT_MANIFEST_ERROR_DOMAIN;
    }

    if (wt_domain_validate_set(manifest->domains, manifest->domain_count,
            manifest->isolation_profile, platform) != WT_DOMAIN_VALID) {
        return WT_MANIFEST_ERROR_DOMAIN;
    }

    ret = wt_manifest_validate_ffm_resources(manifest);
    if (ret != WT_MANIFEST_VALID)
        return ret;

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_partition_header(
    const wt_system_manifest_t* manifest,
    const wt_partition_manifest_t* partition)
{
    const wt_domain_descriptor_t* domain;
    size_t signal_count;

    if (!wt_manifest_name_valid(partition->name))
        return WT_MANIFEST_ERROR_NAME;

    domain = wt_manifest_find_domain(manifest, partition->domain_id);
    if (domain == NULL || partition->domain_id == 0U ||
            partition->domain_id > (wt_domain_id_t)INT32_MAX ||
            domain->domain_class != WT_DOMAIN_CLASS_SECURE_PARTITION) {
        return WT_MANIFEST_ERROR_PARTITION_ID;
    }

    if (partition->framework_version != WT_FFM_VERSION_1_0 &&
            partition->framework_version != WT_FFM_VERSION_1_1) {
        return WT_MANIFEST_ERROR_FRAMEWORK_VERSION;
    }

    if ((unsigned int)partition->model >
            (unsigned int)WT_PARTITION_MODEL_SFN) {
        return WT_MANIFEST_ERROR_MODEL;
    }

    if (partition->framework_version == WT_FFM_VERSION_1_0 &&
            partition->model != WT_PARTITION_MODEL_IPC) {
        return WT_MANIFEST_ERROR_MODEL;
    }

    if ((partition->model == WT_PARTITION_MODEL_IPC &&
            (manifest->features & WT_MANIFEST_FEATURE_IPC) == 0U) ||
            (partition->model == WT_PARTITION_MODEL_SFN &&
             (manifest->features & WT_MANIFEST_FEATURE_SFN) == 0U)) {
        return WT_MANIFEST_ERROR_FEATURE;
    }

    if ((unsigned int)partition->priority >
            (unsigned int)WT_PARTITION_PRIORITY_HIGH) {
        return WT_MANIFEST_ERROR_PRIORITY;
    }

    if (partition->service_count == 0U && partition->interrupt_count == 0U)
        return WT_MANIFEST_ERROR_SERVICE;

    if (partition->service_count >
            manifest->limits.max_services_per_partition ||
            (partition->service_count != 0U && partition->services == NULL)) {
        return WT_MANIFEST_ERROR_SERVICE;
    }

    if (partition->dependency_count >
            manifest->limits.max_dependencies_per_partition ||
            (partition->dependency_count != 0U &&
             partition->dependencies == NULL)) {
        return WT_MANIFEST_ERROR_DEPENDENCY;
    }

    if (partition->interrupt_count != domain->interrupt_resource_count ||
            (partition->interrupt_count != 0U &&
             partition->interrupts == NULL)) {
        return WT_MANIFEST_ERROR_INTERRUPT;
    }

    signal_count = partition->interrupt_count;
    if (partition->model == WT_PARTITION_MODEL_IPC)
        signal_count += partition->service_count;

    if (signal_count > WT_MANIFEST_MAX_SIGNALS) {
        return WT_MANIFEST_ERROR_SIGNAL;
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_service(
    const wt_system_manifest_t* manifest,
    const wt_partition_manifest_t* partition,
    const wt_service_descriptor_t* service)
{
    if (!wt_manifest_name_valid(service->name))
        return WT_MANIFEST_ERROR_NAME;

    if (service->sid == 0U)
        return WT_MANIFEST_ERROR_SERVICE_ID;

    if (service->version == 0U ||
            (unsigned int)service->version_policy >
                (unsigned int)WT_SERVICE_VERSION_RELAXED) {
        return WT_MANIFEST_ERROR_SERVICE_VERSION;
    }

    if (service->nonsecure_clients > 1U || service->connection_based > 1U)
        return WT_MANIFEST_ERROR_SERVICE;

    if (partition->framework_version == WT_FFM_VERSION_1_0 &&
            service->connection_based == 0U) {
        return WT_MANIFEST_ERROR_SERVICE;
    }

    if (service->connection_based != 0U) {
        if (service->stateless_handle_index != 0U)
            return WT_MANIFEST_ERROR_STATELESS_HANDLE;
    }
    else {
        if ((manifest->features & WT_MANIFEST_FEATURE_STATELESS) == 0U)
            return WT_MANIFEST_ERROR_FEATURE;
        if (service->stateless_handle_index == 0U ||
                service->stateless_handle_index >
                    manifest->limits.max_stateless_handles) {
            return WT_MANIFEST_ERROR_STATELESS_HANDLE;
        }
    }

    if (partition->model == WT_PARTITION_MODEL_IPC) {
        if (!wt_manifest_signal_valid(service->signal))
            return WT_MANIFEST_ERROR_SIGNAL;
    }
    else if (service->signal != 0U) {
        return WT_MANIFEST_ERROR_SIGNAL;
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_signal_used(const wt_partition_manifest_t* partition,
                                   size_t service_limit,
                                   size_t interrupt_limit,
                                   uint32_t signal)
{
    size_t i;

    for (i = 0U; i < service_limit; i++) {
        if (partition->services[i].signal == signal)
            return 1;
    }

    for (i = 0U; i < interrupt_limit; i++) {
        if (partition->interrupts[i].signal == signal)
            return 1;
    }

    return 0;
}

static int wt_manifest_validate_interrupt(
    const wt_domain_descriptor_t* domain,
    const wt_partition_manifest_t* partition, size_t index)
{
    const wt_manifest_interrupt_t* interrupt = &partition->interrupts[index];
    size_t i;
    int found = 0;

    if (!wt_manifest_name_valid(interrupt->signal_name) ||
            !wt_manifest_signal_valid(interrupt->signal)) {
        return WT_MANIFEST_ERROR_SIGNAL;
    }

    for (i = 0U; i < domain->interrupt_resource_count; i++) {
        if (domain->interrupt_resources[i].interrupt == interrupt->interrupt) {
            found = 1;
            break;
        }
    }

    if (found == 0)
        return WT_MANIFEST_ERROR_INTERRUPT;

    for (i = 0U; i < index; i++) {
        if (partition->interrupts[i].interrupt == interrupt->interrupt)
            return WT_MANIFEST_ERROR_INTERRUPT;
        if (wt_manifest_string_equal(partition->interrupts[i].signal_name,
                                     interrupt->signal_name)) {
            return WT_MANIFEST_ERROR_SIGNAL;
        }
    }

    if (wt_manifest_signal_used(partition, partition->service_count, index,
            interrupt->signal)) {
        return WT_MANIFEST_ERROR_SIGNAL;
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_partition(
    const wt_system_manifest_t* manifest,
    const wt_partition_manifest_t* partition)
{
    const wt_domain_descriptor_t* domain;
    size_t i;
    size_t j;
    int ret;

    ret = wt_manifest_validate_partition_header(manifest, partition);
    if (ret != WT_MANIFEST_VALID)
        return ret;

    domain = wt_manifest_find_domain(manifest, partition->domain_id);

    for (i = 0U; i < partition->service_count; i++) {
        ret = wt_manifest_validate_service(manifest, partition,
                                           &partition->services[i]);
        if (ret != WT_MANIFEST_VALID)
            return ret;

        if (partition->services[i].signal != 0U &&
                wt_manifest_signal_used(partition, i, 0U,
                    partition->services[i].signal)) {
            return WT_MANIFEST_ERROR_SIGNAL;
        }
    }

    for (i = 0U; i < partition->interrupt_count; i++) {
        ret = wt_manifest_validate_interrupt(domain, partition, i);
        if (ret != WT_MANIFEST_VALID)
            return ret;
    }

    for (i = 0U; i < partition->dependency_count; i++) {
        if (partition->dependencies[i] == 0U)
            return WT_MANIFEST_ERROR_DEPENDENCY;
        for (j = 0U; j < i; j++) {
            if (partition->dependencies[i] == partition->dependencies[j])
                return WT_MANIFEST_ERROR_DEPENDENCY;
        }
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_find_service(const wt_system_manifest_t* manifest,
                                    uint32_t sid, size_t* partition_index)
{
    size_t i;
    size_t j;

    for (i = 0U; i < manifest->partition_count; i++) {
        for (j = 0U; j < manifest->partitions[i].service_count; j++) {
            if (manifest->partitions[i].services[j].sid == sid) {
                if (partition_index != NULL)
                    *partition_index = i;
                return 1;
            }
        }
    }

    return 0;
}

static int wt_manifest_validate_partition_uniqueness(
    const wt_system_manifest_t* manifest)
{
    size_t i;
    size_t j;

    for (i = 0U; i < manifest->partition_count; i++) {
        for (j = 0U; j < i; j++) {
            if (wt_manifest_string_equal(manifest->partitions[i].name,
                                         manifest->partitions[j].name) ||
                    manifest->partitions[i].domain_id ==
                        manifest->partitions[j].domain_id) {
                return WT_MANIFEST_ERROR_PARTITION_ID;
            }
        }
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_domain_coverage(
    const wt_system_manifest_t* manifest)
{
    size_t i;
    size_t j;
    int found;

    for (i = 0U; i < manifest->domain_count; i++) {
        if (manifest->domains[i].domain_class !=
                WT_DOMAIN_CLASS_SECURE_PARTITION) {
            continue;
        }

        found = 0;
        for (j = 0U; j < manifest->partition_count; j++) {
            if (manifest->partitions[j].domain_id == manifest->domains[i].id) {
                found = 1;
                break;
            }
        }

        if (found == 0)
            return WT_MANIFEST_ERROR_PARTITION_ID;
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_service_uniqueness(
    const wt_system_manifest_t* manifest)
{
    size_t i;
    size_t j;
    size_t service_i;
    size_t service_j;

    for (i = 0U; i < manifest->partition_count; i++) {
        for (service_i = 0U;
                service_i < manifest->partitions[i].service_count;
                service_i++) {
            const wt_service_descriptor_t* first =
                &manifest->partitions[i].services[service_i];

            for (j = 0U; j <= i; j++) {
                size_t limit = manifest->partitions[j].service_count;

                if (j == i)
                    limit = service_i;

                for (service_j = 0U; service_j < limit; service_j++) {
                    const wt_service_descriptor_t* second =
                        &manifest->partitions[j].services[service_j];

                    if (first->sid == second->sid ||
                            wt_manifest_string_equal(first->name,
                                                     second->name)) {
                        return WT_MANIFEST_ERROR_SERVICE_ID;
                    }

                    if (first->stateless_handle_index != 0U &&
                            first->stateless_handle_index ==
                                second->stateless_handle_index) {
                        return WT_MANIFEST_ERROR_STATELESS_HANDLE;
                    }
                }
            }
        }
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_symbol_uniqueness(
    const wt_system_manifest_t* manifest)
{
    size_t i;
    size_t j;
    size_t k;
    size_t prior_partition;
    size_t prior_interrupt;

    for (i = 0U; i < manifest->partition_count; i++) {
        const wt_partition_manifest_t* partition = &manifest->partitions[i];

        for (j = 0U; j < manifest->partition_count; j++) {
            const wt_partition_manifest_t* other = &manifest->partitions[j];

            if (wt_manifest_partition_symbol_collision(partition->name,
                    other)) {
                return WT_MANIFEST_ERROR_SYMBOL;
            }

            for (k = 0U; k < other->service_count; k++) {
                if (wt_manifest_service_symbol_collision(partition->name,
                        other, &other->services[k]) ||
                        wt_manifest_service_model_symbol_collision(partition,
                            other, &other->services[k])) {
                    return WT_MANIFEST_ERROR_SYMBOL;
                }
            }

            for (k = 0U; k < other->interrupt_count; k++) {
                if (wt_manifest_string_equal(partition->name,
                        other->interrupts[k].signal_name)) {
                    return WT_MANIFEST_ERROR_SYMBOL;
                }
            }
        }

        for (j = 0U; j < partition->interrupt_count; j++) {
            const char* name = partition->interrupts[j].signal_name;

            for (k = 0U; k < manifest->partition_count; k++) {
                const wt_partition_manifest_t* other =
                    &manifest->partitions[k];
                size_t service;

                if (wt_manifest_partition_symbol_collision(name, other))
                    return WT_MANIFEST_ERROR_SYMBOL;

                for (service = 0U; service < other->service_count; service++) {
                    if (wt_manifest_service_symbol_collision(name, other,
                            &other->services[service])) {
                        return WT_MANIFEST_ERROR_SYMBOL;
                    }
                }
            }

            for (prior_partition = 0U; prior_partition <= i;
                    prior_partition++) {
                size_t limit = manifest->partitions[prior_partition]
                    .interrupt_count;

                if (prior_partition == i)
                    limit = j;

                for (prior_interrupt = 0U; prior_interrupt < limit;
                        prior_interrupt++) {
                    if (wt_manifest_string_equal(name,
                            manifest->partitions[prior_partition]
                                .interrupts[prior_interrupt].signal_name)) {
                        return WT_MANIFEST_ERROR_SYMBOL;
                    }
                }
            }
        }
    }

    return WT_MANIFEST_VALID;
}

static int wt_manifest_validate_dependencies(
    const wt_system_manifest_t* manifest)
{
    uint8_t edges[WT_MANIFEST_MAX_PARTITIONS][WT_MANIFEST_MAX_PARTITIONS] = {
        { 0U }
    };
    uint8_t removed[WT_MANIFEST_MAX_PARTITIONS] = { 0U };
    size_t i;
    size_t j;
    size_t k;
    size_t target;
    size_t removed_count = 0U;
    int progress;

    for (i = 0U; i < manifest->partition_count; i++) {
        for (j = 0U; j < manifest->partitions[i].dependency_count; j++) {
            if (!wt_manifest_find_service(manifest,
                    manifest->partitions[i].dependencies[j], &target) ||
                    target == i) {
                return WT_MANIFEST_ERROR_DEPENDENCY;
            }
            edges[i][target] = 1U;
        }
    }

    do {
        progress = 0;
        for (i = 0U; i < manifest->partition_count; i++) {
            int has_edge = 0;

            if (removed[i] != 0U)
                continue;

            for (j = 0U; j < manifest->partition_count; j++) {
                if (removed[j] == 0U && edges[i][j] != 0U) {
                    has_edge = 1;
                    break;
                }
            }

            if (has_edge == 0) {
                removed[i] = 1U;
                removed_count++;
                progress = 1;
                for (k = 0U; k < manifest->partition_count; k++)
                    edges[k][i] = 0U;
            }
        }
    } while (progress != 0);

    if (removed_count != manifest->partition_count)
        return WT_MANIFEST_ERROR_DEPENDENCY_CYCLE;

    return WT_MANIFEST_VALID;
}

int wt_manifest_validate(const wt_system_manifest_t* manifest,
                         uint32_t supported_features,
                         const wt_profile_capabilities_t* platform)
{
    size_t i;
    int ret;

    if (manifest == NULL)
        return WT_MANIFEST_ERROR_ARGUMENT;

    ret = wt_manifest_validate_header(manifest, supported_features, platform);
    if (ret != WT_MANIFEST_VALID)
        return ret;

    for (i = 0U; i < manifest->partition_count; i++) {
        ret = wt_manifest_validate_partition_header(manifest,
            &manifest->partitions[i]);
        if (ret != WT_MANIFEST_VALID)
            return ret;
    }

    ret = wt_manifest_validate_partition_uniqueness(manifest);
    if (ret != WT_MANIFEST_VALID)
        return ret;

    ret = wt_manifest_validate_domain_coverage(manifest);
    if (ret != WT_MANIFEST_VALID)
        return ret;

    for (i = 0U; i < manifest->partition_count; i++) {
        ret = wt_manifest_validate_partition(manifest,
                                             &manifest->partitions[i]);
        if (ret != WT_MANIFEST_VALID)
            return ret;
    }

    ret = wt_manifest_validate_service_uniqueness(manifest);
    if (ret != WT_MANIFEST_VALID)
        return ret;

    ret = wt_manifest_validate_symbol_uniqueness(manifest);
    if (ret != WT_MANIFEST_VALID)
        return ret;

    return wt_manifest_validate_dependencies(manifest);
}
