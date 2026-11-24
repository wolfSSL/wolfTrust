/* partition.h
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

#ifndef WOLFTRUST_PARTITION_H
#define WOLFTRUST_PARTITION_H

#include "wolftrust/manifest.h"
#include "wolftrust/types.h"

/* Enforcement a port declares it provides; the core refuses a guest binding
 * or a manifest profile that needs more than the port claims. */
#define WT_PORT_CAPABILITY_VECTOR_READ_ALIAS     (1U << 0)
#define WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING (1U << 1)
#define WT_PORT_CAPABILITY_TZ_FILTER             (1U << 2)
#define WT_PORT_CAPABILITY_ALL \
    (WT_PORT_CAPABILITY_VECTOR_READ_ALIAS | \
     WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING | \
     WT_PORT_CAPABILITY_TZ_FILTER)

typedef struct wt_guest_port_binding {
    uint32_t required_capabilities;
    uint32_t provided_capabilities;
    uintptr_t vector_read_address;
} wt_guest_port_binding_t;

typedef struct wt_guest_config {
    wt_guest_id_t guest_id;
    char name[WT_MAX_NAME_LEN];
    uintptr_t vector_table;
    uintptr_t initial_psp_ns;
    uintptr_t initial_msp_ns;
    wt_irq_mask_t irq_mask;
    wt_memory_window_t memory_windows[WT_MAX_MEMORY_WINDOWS];
    size_t memory_window_count;
    wt_memory_region_t memory_regions[WT_MAX_MEMORY_REGIONS];
    size_t memory_region_count;
    wt_restart_policy_t restart_policy;
    uint32_t timeslice_ms;
    wt_guest_port_binding_t port;
    wt_guest_state_t initial_state;
    uint32_t launch_required;
    uint32_t launch_min_version;
} wt_guest_config_t;

/* Per-guest scheduler runtime. The execution context is an architecture-port
 * type held by POINTER: the port owns the concrete storage and wires it in
 * wt_partition_reset_runtime / the runtime table, so the core never needs the
 * arch layout. */
typedef struct wt_guest_runtime {
    struct wt_guest_context* context;
    wt_guest_state_t state;
    uint32_t remaining_delay_ticks;
    uint32_t restart_count;
    uint32_t first_restart_tick;
    wt_fault_reason_t last_fault;
} wt_guest_runtime_t;

typedef enum wt_port_validation_result {
    WT_PORT_VALID = 0,
    WT_PORT_ERROR_ARGUMENT = -500,
    WT_PORT_ERROR_CAPABILITY = -501,
    WT_PORT_ERROR_VECTOR_ALIAS = -502,
    WT_PORT_ERROR_PROFILE = -503
} wt_port_validation_result_t;

const wt_guest_config_t* wt_partitions_config_table(size_t* count);
wt_guest_runtime_t* wt_partitions_runtime_table(size_t* count);
const wt_profile_capabilities_t* wt_partitions_profile_capabilities(void);
/* 0 when every constant guest row matches what the manifest declares. */
int wt_partitions_check_manifest(const wt_system_manifest_t* manifest);
int wt_partition_validate_port_binding(
    const wt_guest_config_t* config,
    const wt_domain_descriptor_t* domain);
/* Refuse a manifest profile whose isolation claims exceed what the port
 * provides: memory protection needs Non-secure domain programming or a
 * TrustZone filter, domain isolation needs the filter. */
int wt_partition_validate_profile(const wt_profile_capabilities_t* profile,
                                  uint32_t provided_capabilities);
void wt_partition_reset_runtime(const wt_guest_config_t* config,
                                wt_guest_runtime_t* runtime);

#endif
