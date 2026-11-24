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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* WT-PORT-0009: a guest binding or a manifest profile that needs enforcement
 * the port does not declare is refused before anything is scheduled. */

#include "wolftrust/partition.h"

#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

/* Manifest-derived resources bound to the domain; validation checks these,
 * not the compiled template windows. */
static wt_memory_resource_t g_res[2];
static wt_memory_window_t g_windows[2];

static void fixture(wt_guest_config_t* config, wt_domain_descriptor_t* domain)
{
    memset(config, 0, sizeof(*config));
    memset(domain, 0, sizeof(*domain));
    memset(g_res, 0, sizeof(g_res));
    config->vector_table = 0x08020000u;
    g_windows[0].base = 0x20000000u;
    g_windows[0].size = 0x00010000u;
    g_windows[0].attributes = WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE;
    g_windows[1].base = 0x08020000u;
    g_windows[1].size = 0x00020000u;
    g_windows[1].attributes = WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_EXECUTE;
    config->memory_windows = g_windows;
    config->memory_window_count = 2u;
    config->memory_region_count = 3u;
    config->port.required_capabilities = WT_PORT_CAPABILITY_ALL;
    config->port.provided_capabilities = WT_PORT_CAPABILITY_ALL;
    config->port.vector_read_address = 0x0C020000u;
    g_res[0].base = 0x20000000u;
    g_res[0].size = 0x00010000u;
    g_res[0].attributes = WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE;
    g_res[1].base = 0x08020000u;
    g_res[1].size = 0x00020000u;
    g_res[1].attributes = WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_EXECUTE;
    domain->memory_resources = g_res;
    domain->memory_resource_count = 2u;
}

static int bind(const wt_guest_config_t* config,
                const wt_domain_descriptor_t* domain)
{
    return wt_partition_validate_port_binding(config, domain);
}

int main(void)
{
    wt_guest_config_t config;
    wt_domain_descriptor_t domain;
    wt_profile_capabilities_t profile;
    uint32_t caps;

    fixture(&config, &domain);
    check(bind(&config, &domain) == WT_PORT_VALID,
          "full port capabilities accept regions and a writable window");
    check(bind(NULL, &domain) == WT_PORT_ERROR_ARGUMENT,
          "null config is an argument error");
    check(bind(&config, NULL) == WT_PORT_ERROR_ARGUMENT,
          "null domain is an argument error");

    fixture(&config, &domain);
    config.memory_window_count = WT_MAX_MEMORY_WINDOWS + 1u;
    check(bind(&config, &domain) == WT_PORT_ERROR_ARGUMENT,
          "window count above the contract maximum is refused");

    fixture(&config, &domain);
    config.memory_region_count = WT_MAX_MEMORY_REGIONS + 1u;
    check(bind(&config, &domain) == WT_PORT_ERROR_ARGUMENT,
          "region count above the contract maximum is refused");

    fixture(&config, &domain);
    config.port.provided_capabilities |= (WT_PORT_CAPABILITY_ALL + 1u);
    check(bind(&config, &domain) == WT_PORT_ERROR_CAPABILITY,
          "an unknown capability bit is refused");

    fixture(&config, &domain);
    config.port.provided_capabilities &= ~WT_PORT_CAPABILITY_VECTOR_READ_ALIAS;
    check(bind(&config, &domain) == WT_PORT_ERROR_CAPABILITY,
          "a required capability the port lacks is refused");

    fixture(&config, &domain);
    config.port.vector_read_address = config.vector_table;
    check(bind(&config, &domain) == WT_PORT_ERROR_VECTOR_ALIAS,
          "the vector read alias must differ from the vector table");

    fixture(&config, &domain);
    caps = WT_PORT_CAPABILITY_VECTOR_READ_ALIAS | WT_PORT_CAPABILITY_TZ_FILTER;
    config.port.required_capabilities = caps;
    config.port.provided_capabilities = caps;
    check(bind(&config, &domain) == WT_PORT_ERROR_CAPABILITY,
          "guest memory regions need Non-secure domain programming");

    fixture(&config, &domain);
    caps = WT_PORT_CAPABILITY_VECTOR_READ_ALIAS |
           WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING;
    config.port.required_capabilities = caps;
    config.port.provided_capabilities = caps;
    check(bind(&config, &domain) == WT_PORT_ERROR_CAPABILITY,
          "a writable manifest resource needs the TrustZone filter");

    g_res[0].attributes = WT_MEMORY_ATTR_READ;
    check(bind(&config, &domain) == WT_PORT_VALID,
          "read-only manifest resources need no TrustZone filter");

    /* The manifest, not the compiled template, decides the filter need: a
     * read-only template window with a writable manifest resource must still
     * be refused on a filter-less port. */
    g_res[0].attributes = WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE;
    g_windows[0].attributes = WT_MEMORY_ATTR_READ;
    check(bind(&config, &domain) == WT_PORT_ERROR_CAPABILITY,
          "a writable manifest resource is refused even when the template is read-only");

    fixture(&config, &domain);
    caps = WT_PORT_CAPABILITY_VECTOR_READ_ALIAS;
    config.port.required_capabilities = caps;
    config.port.provided_capabilities = caps;
    config.memory_region_count = 0u;
    g_res[0].attributes = WT_MEMORY_ATTR_READ;
    check(bind(&config, &domain) == WT_PORT_VALID,
          "no regions and read-only manifest resources bind to a filter-less port");

    memset(&profile, 0, sizeof(profile));
    profile.capabilities = WT_CAPABILITY_MEMORY_PROTECTION |
                           WT_CAPABILITY_DOMAIN_ISOLATION;
    check(wt_partition_validate_profile(&profile, WT_PORT_CAPABILITY_ALL) ==
              WT_PORT_VALID,
          "an isolating profile is accepted by a fully enforcing port");
    check(wt_partition_validate_profile(&profile,
              WT_PORT_CAPABILITY_VECTOR_READ_ALIAS |
              WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING) ==
              WT_PORT_ERROR_PROFILE,
          "domain isolation without a TrustZone filter is refused");
    check(wt_partition_validate_profile(&profile,
              WT_PORT_CAPABILITY_VECTOR_READ_ALIAS) == WT_PORT_ERROR_PROFILE,
          "memory protection without any enforcement is refused");

    profile.capabilities = WT_CAPABILITY_MEMORY_PROTECTION;
    check(wt_partition_validate_profile(&profile,
              WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING) == WT_PORT_VALID,
          "memory protection is satisfied by Non-secure domain programming");

    profile.capabilities = 0u;
    check(wt_partition_validate_profile(&profile, 0u) == WT_PORT_VALID,
          "a profile claiming no isolation binds to any port");
    check(wt_partition_validate_profile(&profile, WT_PORT_CAPABILITY_ALL + 1u)
              == WT_PORT_ERROR_CAPABILITY,
          "an unknown provided bit is refused by the profile check");
    check(wt_partition_validate_profile(NULL, WT_PORT_CAPABILITY_ALL) ==
              WT_PORT_ERROR_ARGUMENT,
          "null profile is an argument error");

    printf("WT-PORT-0009 port capability binding: %d checks, %d failures\n",
           checks, failures);
    if (failures == 0) {
        printf("PASS: port_binding\n");
        return 0;
    }
    printf("FAIL: port_binding\n");
    return 1;
}
