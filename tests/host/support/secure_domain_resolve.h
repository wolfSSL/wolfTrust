/* secure_domain_resolve.h
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

/* Host reference: a Secure Partition's domain read from the descriptive
 * manifest, for checking the generated memory rows the SPM programs. */

#ifndef WOLFTRUST_TESTS_SECURE_DOMAIN_RESOLVE_H
#define WOLFTRUST_TESTS_SECURE_DOMAIN_RESOLVE_H

#include "wolftrust/ffm_domain.h"

/* Resolve the Level 3 Secure protection domain for domain_id from a validated
 * manifest. Fails closed: a missing domain, a domain that is not a Secure
 * Partition, or a region set larger than the MPU can hold returns an error and
 * leaves out_domain empty, so the caller programs no partition regions rather
 * than an over-broad set. */
int wt_ffm_resolve_secure_domain(const wt_system_manifest_t* manifest,
                                 wt_domain_id_t domain_id,
                                 wt_secure_domain_t* out_domain);

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

#endif /* WOLFTRUST_TESTS_SECURE_DOMAIN_RESOLVE_H */
