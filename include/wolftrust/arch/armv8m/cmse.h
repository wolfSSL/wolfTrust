/* cmse.h
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

#ifndef WOLFTRUST_ARCH_ARMV8M_CMSE_H
#define WOLFTRUST_ARCH_ARMV8M_CMSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "wolftrust/types.h"

/* Validate a non-secure read+write buffer of exactly `size` bytes at `ptr`.
 * Returns true iff every byte is RW-accessible from non-secure code as
 * determined by ARMv8-M CMSE (uses cmse_check_address_range under the hood).
 * Returns false if ptr is NULL, size is 0, ptr + size would wrap, or
 * the range is not entirely non-secure RW. */
bool wt_cmse_check_ns_rw(const void *ptr, size_t size);

/* Same but for read-only access (non-secure code only needs to read it). */
bool wt_cmse_check_ns_ro(const void *ptr, size_t size);

/* Additional defense-in-depth check: the [ptr, ptr+size) range must lie
 * entirely within the NS-RAM window declared for guest `guest_id`.
 * This guards against SAU misconfiguration making cross-guest memory
 * appear non-secure. Returns false on any out-of-bounds or unknown guest. */
bool wt_cmse_check_in_guest_ns_ram(wt_guest_id_t guest_id,
                                   const void *ptr,
                                   size_t size);

/* Same as wt_cmse_check_in_guest_ns_ram but also accepts read-only/exec
 * windows (the guest's flash). Use for veneer inputs the guest may
 * legitimately pass from .rodata. The window must still belong to the
 * caller guest — cross-guest reads remain forbidden. */
bool wt_cmse_check_in_guest_ns_addr(wt_guest_id_t guest_id,
                                    const void *ptr,
                                    size_t size);

/* Convenience macro for an NSC veneer. Generates a naked function in the
 * .gnu.sgstubs section that emits a Secure Gateway (sg) instruction then
 * branches to the implementation symbol. */
#define WT_NSC_VENEER(name, impl_sym)                                \
    __attribute__((naked, section(".gnu.sgstubs")))                  \
    void name(void)                                                  \
    {                                                                \
        __asm volatile("sg\n\t" "b.w " #impl_sym "\n\t");            \
    }

#endif
