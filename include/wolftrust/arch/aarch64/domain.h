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

/* Every partition plus each boot self-test domain, and the extra table a
 * memory-sharing borrower rebuilds while it holds a retrieved region. */
#define WT_DOMAIN_MAX_TABLES 16u
/* Fill entries a partition table keeps EL1-only unless the partition's own
 * regions cover one flagged WT_DOMAIN_FILL_SHARED entirely, in which case
 * the partition's mapping (EL0 + EL1) replaces it. Partial cover still
 * fails. A shareable range is mapped non-global in every table (it is the
 * builder's WT_TABLES_ATTR_NG hint) so no ASID inherits another's entry. */
#define WT_DOMAIN_MAX_FILL   32u
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

/* FFA_MEM_PERM_SET/GET on an already-built domain, over pages the caller has
 * found to be the partition's own (wt_tables_set_el0_attributes: its EL0
 * pages, Normal or Device); the range starts on a page; WT_TABLES_* result
 * codes. A Device page keeps its memory type and is never made executable. GET
 * reports no WT_MEM_ATTR_READ for a page the partition cannot reach at EL0
 * (one a transaction holds or it made no-access). */
int wt_domain_set_permissions(const wt_memory_region_t* regions, size_t count,
                              uintptr_t va, size_t pages, uint32_t attributes);
int wt_domain_get_permissions(const wt_memory_region_t* regions, size_t count,
                              uintptr_t va, uint32_t* attributes);

/* The EL0 access the domain's table gives va as Normal write-back memory
 * (whatever its region list says; a Device page is none): memory the partition
 * reaches so at EL0 is memory it may itself send. */
#define WT_DOMAIN_ACCESS_NONE 0
#define WT_DOMAIN_ACCESS_RO   1
#define WT_DOMAIN_ACCESS_RW   2
int wt_domain_page_access(const wt_memory_region_t* regions, size_t count,
                          uintptr_t va);
/* Non-zero when the domain's table holds va as the partition's in any form:
 * reachable at EL0, made no-access by the partition, or held while a
 * transaction it sent covers it; never an SPMC EL1-only entry. */
int wt_domain_page_claimed(const wt_memory_region_t* regions, size_t count,
                           uintptr_t va);
/* Non-zero when the domain's table gives va to the partition at EL0, or keeps
 * it as a page the partition made no-access, and no transaction holds it. */
int wt_domain_page_owned(const wt_memory_region_t* regions, size_t count,
                         uintptr_t va);
/* Non-zero when the domain's table maps va as Non-secure memory. */
int wt_domain_page_ns(const wt_memory_region_t* regions, size_t count,
                      uintptr_t va);

/* Lend a built domain a window onto memory outside its own regions, and take
 * it back (memory sharing); WT_TABLES_* result codes. */
int wt_domain_grant(const wt_memory_region_t* regions, size_t count,
                    uintptr_t va, size_t pages, uint32_t attributes,
                    int* was_mapped);
int wt_domain_revoke(const wt_memory_region_t* regions, size_t count,
                     uintptr_t va, size_t pages, int was_mapped);

/* An owner's own pages while a transaction holds them, and back exactly as
 * they were (wt_tables_hold_el0/release_el0); WT_TABLES_* result codes. */
int wt_domain_owner_hold(const wt_memory_region_t* regions, size_t count,
                         uintptr_t va, size_t pages, int keep_read);
int wt_domain_owner_release(const wt_memory_region_t* regions, size_t count,
                            uintptr_t va, size_t pages);

/* Fail-closed hook: the SPMC image panics, the host suite records it. */
void wt_domain_fail(int code);

#endif /* WOLFTRUST_ARCH_AARCH64_DOMAIN_H */
