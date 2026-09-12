/* partitions.c
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

/* Non-secure endpoint tables for the QEMU-hosted AArch64 ports. The guest
 * domains come from the generated manifest; nothing launches them until the
 * NS gateway lands, and launch verification fails closed meanwhile. */

#include "wolftrust/arch/aarch64/context.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/partition.h"
#include "memory_map.h"

#include <string.h>

#ifndef WT_TIMESLICE_MS
#define WT_TIMESLICE_MS 2U
#endif

static wt_guest_config_t g_partition_configs[WT_MAX_GUESTS];
static wt_guest_runtime_t g_partition_runtime[WT_MAX_GUESTS];
static wt_guest_context_t g_partition_contexts[WT_MAX_GUESTS];
static uintptr_t g_bound_exec_bases[WT_MAX_GUESTS];
static size_t g_bound_exec_sizes[WT_MAX_GUESTS];

static const wt_profile_capabilities_t g_profile_capabilities = {
    .capabilities = WT_CAPABILITY_SECURITY_STATE |
                    WT_CAPABILITY_PRIVILEGE_STATE |
                    WT_CAPABILITY_ROT_ISOLATION |
                    WT_CAPABILITY_DOMAIN_ISOLATION |
                    WT_CAPABILITY_MEMORY_PROTECTION |
                    WT_CAPABILITY_INTERRUPT_ISOLATION |
                    WT_CAPABILITY_RESTART,
    .max_domains = 11U,
    .max_memory_resources_per_domain = 3U,
    .max_interrupts_per_domain = 1U,
};

const wt_guest_measurement_t* wt_platform_guest_measurements(size_t* count)
{
    if (count != NULL) {
        *count = 0u;
    }
    return NULL;
}

static void wt_partitions_wire(void)
{
    size_t i;

    for (i = 0u; i < WT_MAX_GUESTS; ++i) {
        g_partition_configs[i].guest_id = (wt_guest_id_t)i;
        g_partition_configs[i].name[0] = 'g';
        g_partition_configs[i].name[1] = (char)('0' + i);
        g_partition_configs[i].name[2] = '\0';
        g_partition_configs[i].timeslice_ms = WT_TIMESLICE_MS;
        g_partition_configs[i].initial_state = WT_GUEST_STOPPED;
        g_partition_runtime[i].context = &g_partition_contexts[i];
    }
}

const wt_guest_config_t* wt_partitions_config_table(size_t* count)
{
    wt_partitions_wire();
    if (count != NULL) {
        *count = WT_MAX_GUESTS;
    }
    return g_partition_configs;
}

wt_guest_runtime_t* wt_partitions_runtime_table(size_t* count)
{
    wt_partitions_wire();
    if (count != NULL) {
        *count = WT_MAX_GUESTS;
    }
    return g_partition_runtime;
}

const wt_profile_capabilities_t* wt_partitions_profile_capabilities(void)
{
    return &g_profile_capabilities;
}

static const wt_domain_descriptor_t* wt_partition_manifest_domain(
    const wt_system_manifest_t* manifest, wt_domain_id_t id)
{
    size_t i;

    for (i = 0U; i < manifest->domain_count; ++i) {
        if (manifest->domains[i].id == id) {
            return &manifest->domains[i];
        }
    }
    return NULL;
}

int wt_partitions_bind_manifest(const wt_system_manifest_t* manifest)
{
    size_t i;
    size_t resource;
    size_t window_count;
    size_t region_count;

    if (manifest == NULL || manifest->domains == NULL) {
        return -1;
    }
    wt_partitions_wire();

    for (i = 0U; i < WT_MAX_GUESTS; ++i) {
        wt_guest_config_t* config = &g_partition_configs[i];
        const wt_domain_descriptor_t* domain;

        /* Domain zero is the SPM; guest n is domain n + 1. */
        domain = wt_partition_manifest_domain(manifest,
                                              (wt_domain_id_t)config->guest_id + 1U);
        if (domain == NULL ||
                domain->domain_class != WT_DOMAIN_CLASS_NONSECURE_APPLICATION ||
                domain->security_state != WT_SECURITY_STATE_NONSECURE ||
                domain->privilege_state != WT_PRIVILEGE_STATE_UNPRIVILEGED ||
                domain->restart_policy.action != WT_RESTART_ACTION_DOMAIN ||
                domain->entry_point == 0U ||
                domain->memory_resource_count > WT_MAX_MEMORY_REGIONS) {
            return -1;
        }
        if (wt_partition_validate_port_binding(config, domain) !=
                WT_PORT_VALID) {
            return -1;
        }

        config->restart_policy.restart_limit =
            domain->restart_policy.restart_limit;
        config->restart_policy.restart_window_ticks =
            domain->restart_policy.restart_window_ticks;
        config->restart_policy.initial_delay_ticks =
            domain->restart_policy.initial_delay_ticks;
        config->initial_state = (wt_guest_state_t)domain->initial_lifecycle;
        config->launch_required = domain->launch_required;
        config->launch_min_version = domain->launch_min_version;
        config->vector_table = domain->entry_point;

        window_count = 0U;
        region_count = 0U;
        g_bound_exec_bases[i] = 0U;
        g_bound_exec_sizes[i] = 0U;
        for (resource = 0U; resource < domain->memory_resource_count;
                ++resource) {
            const wt_memory_resource_t* r = &domain->memory_resources[resource];

            if ((r->attributes & WT_MEM_ATTR_DEVICE) == 0U) {
                if (window_count >= WT_MAX_MEMORY_WINDOWS) {
                    return -1;
                }
                config->memory_windows[window_count] = *r;
                window_count++;
            }
            config->memory_regions[region_count].base = r->base;
            config->memory_regions[region_count].size = r->size;
            config->memory_regions[region_count].attributes = r->attributes &
                (WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_EXEC |
                 WT_MEM_ATTR_DEVICE);
            region_count++;
            if ((r->attributes & WT_MEM_ATTR_EXEC) != 0U &&
                    g_bound_exec_sizes[i] == 0U) {
                g_bound_exec_bases[i] = r->base;
                g_bound_exec_sizes[i] = r->size;
            }
        }
        if (g_bound_exec_sizes[i] == 0U) {
            return -1;
        }
        config->memory_window_count = window_count;
        config->memory_region_count = region_count;
        (void)memset(&config->irq_mask, 0, sizeof(config->irq_mask));
        if (domain->stack_base > (uintptr_t)-1 - domain->stack_size) {
            return -1;
        }
        config->initial_msp_ns = domain->stack_base + domain->stack_size;
    }
    return 0;
}

void wt_partition_reset_runtime(const wt_guest_config_t* config,
                                wt_guest_runtime_t* runtime)
{
    uint32_t restart_count;
    uint32_t first_restart_tick;

    if (config == NULL || runtime == NULL) {
        return;
    }
    restart_count = runtime->restart_count;
    first_restart_tick = runtime->first_restart_tick;
    (void)memset(runtime, 0, sizeof(*runtime));
    runtime->context =
        &g_partition_contexts[(size_t)(runtime - g_partition_runtime)];
    (void)memset(runtime->context, 0, sizeof(*runtime->context));
    runtime->restart_count = restart_count;
    runtime->first_restart_tick = first_restart_tick;
    runtime->state = config->initial_state;
    runtime->context->sp_el0 = config->initial_msp_ns;
    runtime->context->pc = config->vector_table;
    if (config->guest_id >= WT_MAX_GUESTS ||
            g_bound_exec_sizes[config->guest_id] == 0U ||
            runtime->context->pc < g_bound_exec_bases[config->guest_id] ||
            runtime->context->pc >= g_bound_exec_bases[config->guest_id] +
                g_bound_exec_sizes[config->guest_id]) {
        runtime->context->pc = 0U;
        return;
    }
    runtime->context->elr = runtime->context->pc;
    runtime->context->frame_stacked = false;
}
