/* ffm_domain.h
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

#ifndef WOLFTRUST_FFM_DOMAIN_H
#define WOLFTRUST_FFM_DOMAIN_H

#include "wolftrust/domain.h"
#include "wolftrust/manifest.h"
#include "wolftrust/types.h"

/* A Secure Partition's Level 3 protection domain resolved into the private
 * MPU region set the port programs before entering that partition. This is
 * the architecture-neutral policy the enforcement layer consumes; it holds
 * no Armv8-M or MPU register detail. WT-FFM-0011. */
typedef struct wt_secure_domain {
    wt_domain_id_t domain_id;
    wt_memory_region_t regions[WT_MAX_MEMORY_REGIONS];
    size_t region_count;
} wt_secure_domain_t;

typedef enum wt_secure_domain_result {
    WT_SECURE_DOMAIN_OK = 0,
    WT_SECURE_DOMAIN_ERROR_ARGUMENT = -600,
    WT_SECURE_DOMAIN_ERROR_NOT_FOUND = -601,
    WT_SECURE_DOMAIN_ERROR_CLASS = -602,
    WT_SECURE_DOMAIN_ERROR_CAPACITY = -603
} wt_secure_domain_result_t;

/* Resolve the Level 3 Secure protection domain for domain_id from a validated
 * manifest. Fails closed: a missing domain, a domain that is not a Secure
 * Partition, or a region set larger than the MPU can hold returns an error and
 * leaves out_domain empty, so the caller programs no partition regions rather
 * than an over-broad set. */
int wt_ffm_resolve_secure_domain(const wt_system_manifest_t* manifest,
                                 wt_domain_id_t domain_id,
                                 wt_secure_domain_t* out_domain);

/* Non-zero only when [addr, addr + len) lies wholly within one region of
 * domain that grants the requested access (need_write also requires read).
 * Zero length, an address range that overflows, or a region that wraps is
 * rejected. Proves cross-domain exclusion and validates a partition's own
 * memory references. */
int wt_secure_domain_contains(const wt_secure_domain_t* domain,
                              uintptr_t addr, size_t len, int need_write);

/* Non-zero only when no region of domain, whatever access it grants,
 * overlaps [base, base + size): the range is out of the partition's reach. */
int wt_secure_domain_excludes(const wt_secure_domain_t* domain,
                              uintptr_t base, size_t size);

/* Non-zero only when the two composed tables are isolated from each other:
 * no region one of them can write overlaps any region of the other. Regions
 * both only read (code, constants) may overlap, and so may regions that lie
 * wholly inside one of the shared windows the caller names. */
int wt_secure_domains_isolated(const wt_secure_domain_t* first,
                               const wt_secure_domain_t* second,
                               const wt_memory_region_t* shared,
                               size_t shared_count);

/* Compose the full secure MPU table for a Secure Partition: the shared
 * regions every partition needs to execute (secure code) followed by the
 * partition's own private regions. The Level 3 profile copies IOVEC
 * transfers (WT-FFM-0041), so the SPM, not the partition, touches client
 * memory — a partition's table therefore needs only code plus its private
 * regions, leaving other partitions, the SPM, and the private peripheral bus
 * unmapped and faulting. Fails closed when the combined set exceeds the MPU,
 * leaving out_table empty. */
int wt_ffm_compose_secure_partition_table(const wt_secure_domain_t* domain,
                                          const wt_memory_region_t* shared,
                                          size_t shared_count,
                                          wt_secure_domain_t* out_table);

#endif
