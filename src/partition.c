/* partition.c
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

#include "wolftrust/partition.h"

#include <stddef.h>

int wt_partition_validate_port_binding(
    const wt_guest_config_t* config,
    const wt_domain_descriptor_t* domain)
{
    const wt_guest_port_binding_t* port;
    size_t i;

    if (config == NULL || domain == NULL ||
            (domain->memory_resource_count != 0U &&
             domain->memory_resources == NULL) ||
            config->memory_window_count > WT_MAX_MEMORY_WINDOWS ||
            config->memory_region_count > WT_MAX_MEMORY_REGIONS) {
        return WT_PORT_ERROR_ARGUMENT;
    }

    port = &config->port;
    if (((port->required_capabilities | port->provided_capabilities) &
            ~WT_PORT_CAPABILITY_ALL) != 0U ||
            (port->required_capabilities &
             port->provided_capabilities) !=
                port->required_capabilities) {
        return WT_PORT_ERROR_CAPABILITY;
    }

    if ((port->required_capabilities &
            WT_PORT_CAPABILITY_VECTOR_READ_ALIAS) != 0U &&
            (port->vector_read_address == 0U ||
             (port->vector_read_address & (sizeof(uint32_t) - 1U)) != 0U ||
             port->vector_read_address == config->vector_table)) {
        return WT_PORT_ERROR_VECTOR_ALIAS;
    }

    if (config->memory_region_count != 0U &&
            (port->provided_capabilities &
             WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING) == 0U) {
        return WT_PORT_ERROR_CAPABILITY;
    }

    /* A writable Non-secure window needs the fabric filter to isolate it. */
    for (i = 0U; i < domain->memory_resource_count; ++i) {
        if ((domain->memory_resources[i].attributes &
                WT_MEMORY_ATTR_WRITE) != 0U &&
                (port->provided_capabilities &
                 WT_PORT_CAPABILITY_TZ_FILTER) == 0U) {
            return WT_PORT_ERROR_CAPABILITY;
        }
    }

    return WT_PORT_VALID;
}

int wt_partition_validate_profile(const wt_profile_capabilities_t* profile,
                                  uint32_t provided_capabilities)
{
    if (profile == NULL) {
        return WT_PORT_ERROR_ARGUMENT;
    }
    if ((provided_capabilities & ~WT_PORT_CAPABILITY_ALL) != 0U) {
        return WT_PORT_ERROR_CAPABILITY;
    }
    if ((profile->capabilities & WT_CAPABILITY_MEMORY_PROTECTION) != 0U &&
            (provided_capabilities &
             (WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING |
              WT_PORT_CAPABILITY_TZ_FILTER)) == 0U) {
        return WT_PORT_ERROR_PROFILE;
    }
    if ((profile->capabilities & WT_CAPABILITY_DOMAIN_ISOLATION) != 0U &&
            (provided_capabilities & WT_PORT_CAPABILITY_TZ_FILTER) == 0U) {
        return WT_PORT_ERROR_PROFILE;
    }
    return WT_PORT_VALID;
}
