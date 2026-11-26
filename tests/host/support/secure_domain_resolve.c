/* secure_domain_resolve.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "secure_domain_resolve.h"

static const wt_domain_descriptor_t* wt_ffm_domain_by_id(
    const wt_system_manifest_t* manifest, wt_domain_id_t domain_id)
{
    size_t i;

    for (i = 0U; i < manifest->domain_count; i++) {
        if (manifest->domains[i].id == domain_id) {
            return &manifest->domains[i];
        }
    }
    return NULL;
}

int wt_ffm_resolve_secure_domain(const wt_system_manifest_t* manifest,
                                 wt_domain_id_t domain_id,
                                 wt_secure_domain_t* out_domain)
{
    const wt_domain_descriptor_t* domain;
    size_t i;

    if (manifest == NULL || out_domain == NULL) {
        return WT_SECURE_DOMAIN_ERROR_ARGUMENT;
    }

    out_domain->domain_id = WT_DOMAIN_ID_INVALID;
    out_domain->region_count = 0U;

    domain = wt_ffm_domain_by_id(manifest, domain_id);
    if (domain == NULL) {
        return WT_SECURE_DOMAIN_ERROR_NOT_FOUND;
    }
    if (domain->domain_class != WT_DOMAIN_CLASS_SECURE_PARTITION ||
            domain->security_state != WT_SECURITY_STATE_SECURE) {
        return WT_SECURE_DOMAIN_ERROR_CLASS;
    }
    if (domain->memory_resource_count > WT_MAX_MEMORY_REGIONS ||
            (domain->memory_resource_count != 0U &&
             domain->memory_resources == NULL)) {
        return WT_SECURE_DOMAIN_ERROR_CAPACITY;
    }

    for (i = 0U; i < domain->memory_resource_count; i++) {
        const wt_memory_resource_t* resource = &domain->memory_resources[i];

        out_domain->regions[i].base = resource->base;
        out_domain->regions[i].size = resource->size;
        /* SHARED must survive resolution (the scheduler uses it to keep a
         * shared band from being picked as a partition stack), and so must
         * RESTART_CLEAR (the fault scrub records the declared band from it). */
        out_domain->regions[i].attributes = resource->attributes &
            (WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_EXEC |
             WT_MEM_ATTR_DEVICE | WT_MEMORY_ATTR_SHARED |
             WT_MEMORY_ATTR_RESTART_CLEAR);
    }
    out_domain->region_count = domain->memory_resource_count;
    out_domain->domain_id = domain_id;
    return WT_SECURE_DOMAIN_OK;
}

int wt_ffm_compose_secure_partition_table(const wt_secure_domain_t* domain,
                                          const wt_memory_region_t* shared,
                                          size_t shared_count,
                                          wt_secure_domain_t* out_table)
{
    size_t i;
    size_t total;

    if (domain == NULL || out_table == NULL ||
            (shared == NULL && shared_count != 0U)) {
        return WT_SECURE_DOMAIN_ERROR_ARGUMENT;
    }

    out_table->domain_id = WT_DOMAIN_ID_INVALID;
    out_table->region_count = 0U;

    total = shared_count + domain->region_count;
    if (shared_count > WT_MAX_MEMORY_REGIONS || total > WT_MAX_MEMORY_REGIONS) {
        return WT_SECURE_DOMAIN_ERROR_CAPACITY;
    }

    for (i = 0U; i < shared_count; i++) {
        out_table->regions[i] = shared[i];
    }
    for (i = 0U; i < domain->region_count; i++) {
        out_table->regions[shared_count + i] = domain->regions[i];
    }
    out_table->region_count = total;
    out_table->domain_id = domain->domain_id;
    return WT_SECURE_DOMAIN_OK;
}
