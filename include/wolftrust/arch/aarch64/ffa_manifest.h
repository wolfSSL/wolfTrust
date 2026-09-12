/* ffa_manifest.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_MANIFEST_H
#define WOLFTRUST_ARCH_AARCH64_FFA_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

/* FF-A partition properties (DEN0077A 1.2 Table 5.1) the manifest tool
 * emits from the optional "ffa" section, one entry per Secure Partition
 * domain; the wolfTrust domain and partition tables stay as they are. */

#define WT_FFA_MANIFEST_MAX_UUIDS       4u

#define WT_FFA_RUNTIME_EL_SEL0          0u
#define WT_FFA_RUNTIME_EL_SEL1          1u
#define WT_FFA_MESSAGING_DIRECT         1u
#define WT_FFA_MESSAGING_INDIRECT       2u
#define WT_FFA_NS_INTERRUPT_SIGNALED    0u
#define WT_FFA_NS_INTERRUPT_QUEUED      1u

/* Bytes in the textual order of the canonical UUID string. */
typedef struct wt_ffa_uuid {
    uint8_t bytes[16];
} wt_ffa_uuid_t;

typedef struct wt_ffa_partition_manifest {
    const wt_ffa_uuid_t* uuids;
    uint32_t domain_id;
    uint32_t uuid_count;
    uint32_t execution_contexts;
    uint32_t runtime_el;
    uint32_t messaging;
    uint32_t ns_interrupt_action;
    uint32_t boot_info_register;
} wt_ffa_partition_manifest_t;

const wt_ffa_partition_manifest_t* wt_generated_ffa_partitions_get(size_t* count);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_MANIFEST_H */
