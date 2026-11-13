/* manifest.h
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

#ifndef WOLFTRUST_MANIFEST_H
#define WOLFTRUST_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "wolftrust/domain.h"

/* 1 re-validates the generated manifest at boot; the build already did. */
#ifndef WT_MANIFEST_RUNTIME_CHECK
#define WT_MANIFEST_RUNTIME_CHECK 0
#endif

#define WT_MANIFEST_FORMAT_VERSION 1U
#define WT_MANIFEST_DIGEST_SIZE 32U
#define WT_MANIFEST_NAME_MAX 63U
#define WT_MANIFEST_MAX_PARTITIONS 32U
#define WT_MANIFEST_MAX_SERVICES 28U
#define WT_MANIFEST_MAX_DEPENDENCIES 32U
#define WT_MANIFEST_MAX_SIGNALS 28U
#define WT_MANIFEST_RESERVED_SIGNALS 0x0000000FU

#define WT_FFM_VERSION_1_0 0x0100U
#define WT_FFM_VERSION_1_1 0x0101U

#define WT_MANIFEST_FEATURE_IPC       (1U << 0)
#define WT_MANIFEST_FEATURE_SFN       (1U << 1)
#define WT_MANIFEST_FEATURE_STATELESS (1U << 2)
#define WT_MANIFEST_FEATURE_MM_IOVEC  (1U << 3)

typedef enum wt_partition_model {
    WT_PARTITION_MODEL_IPC = 0,
    WT_PARTITION_MODEL_SFN
} wt_partition_model_t;

typedef enum wt_partition_priority {
    WT_PARTITION_PRIORITY_LOW = 0,
    WT_PARTITION_PRIORITY_NORMAL,
    WT_PARTITION_PRIORITY_HIGH
} wt_partition_priority_t;

typedef enum wt_service_version_policy {
    WT_SERVICE_VERSION_STRICT = 0,
    WT_SERVICE_VERSION_RELAXED,
    WT_SERVICE_VERSION_UNSPECIFIED
} wt_service_version_policy_t;

typedef struct wt_service_descriptor {
    const char* name;
    uint32_t sid;
    uint32_t version;
    wt_service_version_policy_t version_policy;
    uint32_t signal;
    uint32_t stateless_handle_index;
    uint8_t nonsecure_clients;
    uint8_t connection_based;
} wt_service_descriptor_t;

typedef struct wt_manifest_interrupt {
    const char* signal_name;
    uint32_t interrupt;
    uint32_t signal;
} wt_manifest_interrupt_t;

typedef struct wt_partition_manifest {
    const char* name;
    wt_domain_id_t domain_id;
    uint32_t framework_version;
    wt_partition_model_t model;
    wt_partition_priority_t priority;
    const wt_service_descriptor_t* services;
    size_t service_count;
    const uint32_t* dependencies;
    size_t dependency_count;
    const wt_manifest_interrupt_t* interrupts;
    size_t interrupt_count;
} wt_partition_manifest_t;

typedef struct wt_manifest_limits {
    size_t max_partitions;
    size_t max_services_per_partition;
    size_t max_dependencies_per_partition;
    size_t max_stateless_handles;
} wt_manifest_limits_t;

typedef struct wt_system_manifest {
    uint32_t format_version;
    const char* generator_version;
    const uint8_t* input_digest;
    size_t input_digest_size;
    uint32_t features;
    wt_isolation_profile_t isolation_profile;
    const wt_profile_capabilities_t* profile_capabilities;
    const wt_domain_descriptor_t* domains;
    size_t domain_count;
    const wt_partition_manifest_t* partitions;
    size_t partition_count;
    wt_manifest_limits_t limits;
} wt_system_manifest_t;

typedef enum wt_manifest_validation_result {
    WT_MANIFEST_VALID = 0,
    WT_MANIFEST_ERROR_ARGUMENT = -100,
    WT_MANIFEST_ERROR_FORMAT = -101,
    WT_MANIFEST_ERROR_GENERATOR = -102,
    WT_MANIFEST_ERROR_DIGEST = -103,
    WT_MANIFEST_ERROR_FEATURE = -104,
    WT_MANIFEST_ERROR_LIMIT = -105,
    WT_MANIFEST_ERROR_DOMAIN = -106,
    WT_MANIFEST_ERROR_NAME = -107,
    WT_MANIFEST_ERROR_PARTITION_ID = -108,
    WT_MANIFEST_ERROR_FRAMEWORK_VERSION = -109,
    WT_MANIFEST_ERROR_MODEL = -110,
    WT_MANIFEST_ERROR_PRIORITY = -111,
    WT_MANIFEST_ERROR_SERVICE = -112,
    WT_MANIFEST_ERROR_SERVICE_ID = -113,
    WT_MANIFEST_ERROR_SERVICE_VERSION = -114,
    WT_MANIFEST_ERROR_SIGNAL = -115,
    WT_MANIFEST_ERROR_STATELESS_HANDLE = -116,
    WT_MANIFEST_ERROR_DEPENDENCY = -117,
    WT_MANIFEST_ERROR_DEPENDENCY_CYCLE = -118,
    WT_MANIFEST_ERROR_INTERRUPT = -119,
    WT_MANIFEST_ERROR_RESOURCE_OWNERSHIP = -120,
    WT_MANIFEST_ERROR_SYMBOL = -121
} wt_manifest_validation_result_t;

/* supported_features must come from immutable build capabilities. */
int wt_manifest_validate(const wt_system_manifest_t* manifest,
                         uint32_t supported_features,
                         const wt_profile_capabilities_t* platform);

#endif
