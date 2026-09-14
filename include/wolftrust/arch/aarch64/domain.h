/* domain.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_DOMAIN_H
#define WOLFTRUST_ARCH_AARCH64_DOMAIN_H

#include "wolftrust/types.h"
#include "wolftrust/arch/aarch64/tables.h"

#include <stddef.h>
#include <stdint.h>

/* Partition domains at S-EL1: one prebuilt stage-1 table per region set,
 * keyed by the stable regions pointer the core hands to the wt_arch_*
 * domain operations; ASID 0 is the SPM-only table, partitions get 1.. */

#define WT_DOMAIN_MAX_TABLES 8u
/* Fill entries a partition table keeps EL1-only unless the partition's own
 * regions cover one flagged WT_DOMAIN_FILL_SHARED entirely, in which case
 * the partition's mapping (EL0 + EL1) replaces it. Partial cover still
 * fails. A shareable range is mapped non-global in every table (it is the
 * builder's WT_TABLES_ATTR_NG hint) so no ASID inherits another's entry. */
#define WT_DOMAIN_MAX_FILL   24u
#define WT_DOMAIN_FILL_SHARED WT_TABLES_ATTR_NG

#define WT_DOMAIN_FAIL_INIT   1
#define WT_DOMAIN_FAIL_BUILD  2
#define WT_DOMAIN_FAIL_SLOTS  3

/* Builds the SPM-only table over the pool; returns its TTBR0 or 0. The
 * fill list is kept and mapped EL1-only into every partition table. */
uint64_t wt_domain_init(const wt_memory_region_t* fill, size_t fill_count,
                        uint8_t* pool, uint64_t pool_pa, size_t pool_size);

uint64_t wt_domain_current_ttbr0(void);
size_t wt_domain_tables_built(void);
size_t wt_domain_pool_pages_used(void);

/* Fail-closed hook: the SPMC image panics, the host suite records it. */
void wt_domain_fail(int code);

#endif /* WOLFTRUST_ARCH_AARCH64_DOMAIN_H */
