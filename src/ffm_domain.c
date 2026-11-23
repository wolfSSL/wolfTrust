/* ffm_domain.c
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

#include "wolftrust/ffm_domain.h"

#include <stdint.h>

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
    out_domain->stack_base = 0U;
    out_domain->stack_size = 0U;

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
    out_domain->stack_base = domain->stack_base;
    out_domain->stack_size = domain->stack_size;
    out_domain->domain_id = domain_id;
    return WT_SECURE_DOMAIN_OK;
}

int wt_secure_domain_contains(const wt_secure_domain_t* domain,
                              uintptr_t addr, size_t len, int need_write)
{
    uintptr_t end;
    size_t i;

    if (domain == NULL || domain->region_count > WT_MAX_MEMORY_REGIONS ||
            len == 0U) {
        return 0;
    }
    if (addr > (UINTPTR_MAX - len)) {
        return 0;
    }
    end = addr + len;

    for (i = 0U; i < domain->region_count; i++) {
        const wt_memory_region_t* region = &domain->regions[i];
        uintptr_t region_end;

        if (region->size == 0U ||
                region->base > (UINTPTR_MAX - region->size)) {
            continue;
        }
        if ((region->attributes & WT_MEM_ATTR_READ) == 0U) {
            continue;
        }
        if (need_write != 0 &&
                (region->attributes & WT_MEM_ATTR_WRITE) == 0U) {
            continue;
        }
        region_end = region->base + region->size;
        if (addr >= region->base && end <= region_end) {
            return 1;
        }
    }
    return 0;
}

/* [base, base + size) as an end-exclusive range; zero for a range that is
 * empty or wraps, which therefore overlaps nothing and contains nothing. */
static int wt_secure_range(uintptr_t base, size_t size, uintptr_t* end)
{
    if (size == 0U || base > (UINTPTR_MAX - size)) {
        return 0;
    }
    *end = base + size;
    return 1;
}

static int wt_secure_regions_overlap(const wt_memory_region_t* first,
                                     const wt_memory_region_t* second)
{
    uintptr_t first_end;
    uintptr_t second_end;

    if (!wt_secure_range(first->base, first->size, &first_end) ||
            !wt_secure_range(second->base, second->size, &second_end)) {
        return 0;
    }
    return first->base < second_end && second->base < first_end;
}

static int wt_secure_region_within(const wt_memory_region_t* region,
                                   const wt_memory_region_t* window)
{
    uintptr_t region_end;
    uintptr_t window_end;

    if (!wt_secure_range(region->base, region->size, &region_end) ||
            !wt_secure_range(window->base, window->size, &window_end)) {
        return 0;
    }
    return region->base >= window->base && region_end <= window_end;
}

int wt_secure_domain_excludes(const wt_secure_domain_t* domain,
                              uintptr_t base, size_t size)
{
    wt_memory_region_t range;
    size_t i;

    if (domain == NULL || domain->region_count > WT_MAX_MEMORY_REGIONS) {
        return 0;
    }
    range.base = base;
    range.size = size;
    range.attributes = 0U;
    for (i = 0U; i < domain->region_count; i++) {
        /* A region that wraps the address space reaches everything. */
        if (domain->regions[i].size != 0U &&
                domain->regions[i].base >
                    (UINTPTR_MAX - domain->regions[i].size)) {
            return 0;
        }
        if (wt_secure_regions_overlap(&domain->regions[i], &range)) {
            return 0;
        }
    }
    return 1;
}

int wt_secure_domains_isolated(const wt_secure_domain_t* first,
                               const wt_secure_domain_t* second,
                               const wt_memory_region_t* shared,
                               size_t shared_count)
{
    size_t i;
    size_t j;
    size_t k;

    if (first == NULL || second == NULL ||
            first->region_count > WT_MAX_MEMORY_REGIONS ||
            second->region_count > WT_MAX_MEMORY_REGIONS ||
            (shared == NULL && shared_count != 0U)) {
        return 0;
    }
    for (i = 0U; i < first->region_count; i++) {
        for (j = 0U; j < second->region_count; j++) {
            const wt_memory_region_t* a = &first->regions[i];
            const wt_memory_region_t* b = &second->regions[j];

            if (((a->attributes | b->attributes) & WT_MEM_ATTR_WRITE) == 0U) {
                continue;
            }
            if (!wt_secure_regions_overlap(a, b)) {
                continue;
            }
            for (k = 0U; k < shared_count; k++) {
                if (wt_secure_region_within(a, &shared[k]) &&
                        wt_secure_region_within(b, &shared[k])) {
                    break;
                }
            }
            if (k == shared_count) {
                return 0;
            }
        }
    }
    return 1;
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
