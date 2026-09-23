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

/* WT-FFM-0011 Phase A: the secure per-partition stack carve. These compile-time
 * guards are the overlap check — if the layout ever moves so partitions overlap
 * each other, escape the secure RAM window, or lose MPU alignment, the build
 * fails here (and the matching ASSERT in secure.ld fails at link). */

#include "memory_map.h"
#include "wolftrust/static_assert.h"

#include <stdio.h>

/* Every Armv8-M MPU region base is 32-byte aligned. */
WT_STATIC_ASSERT((WT_SP_CRYPTO_STACK_BASE & 0x1FU) == 0U,
               "crypto SP stack not 32-byte aligned");
WT_STATIC_ASSERT((WT_SP_ATTEST_STACK_BASE & 0x1FU) == 0U,
               "attest SP stack not 32-byte aligned");
WT_STATIC_ASSERT((WT_SP_SECURE_STACK_SIZE & 0x1FU) == 0U,
               "SP stack size not a 32-byte multiple");

/* The carve stays inside the secure RAM window and above the guest region. */
WT_STATIC_ASSERT(WT_SP_SECURE_RAM_BASE >= WT_RAM_S_BASE,
               "SP secure RAM below the secure RAM window");
WT_STATIC_ASSERT(WT_SP_SECURE_RAM_END <= (WT_RAM_S_BASE + WT_RAM_S_SIZE),
               "SP secure RAM overflows the secure RAM window");

/* Partitions are contiguous and non-overlapping, filling the reserved region. */
WT_STATIC_ASSERT(WT_SP_SECURE_RAM_SIZE ==
                   WT_SP_SECURE_STACK_SIZE * WT_SP_SECURE_STACK_COUNT,
               "SP secure RAM size does not match stack count");
WT_STATIC_ASSERT(WT_SP_CRYPTO_STACK_BASE + WT_SP_SECURE_STACK_SIZE ==
                   WT_SP_ATTEST_STACK_BASE,
               "crypto and attest SP stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_ATTEST_STACK_BASE + WT_SP_SECURE_STACK_SIZE ==
                   WT_SP_FF_SERVER_STACK_BASE,
               "attest and FF server SP stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_FF_SERVER_STACK_BASE + WT_SP_SECURE_STACK_SIZE ==
                   WT_SP_FF_DRIVER_STACK_BASE,
               "FF server and driver SP stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_FF_DRIVER_STACK_BASE + WT_SP_SECURE_STACK_SIZE ==
                   WT_SP_FF_CLIENT_STACK_BASE,
               "FF driver and client SP stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_FF_CLIENT_STACK_BASE + WT_SP_SECURE_STACK_SIZE ==
                   WT_SP_SECURE_RAM_END,
               "SP stacks do not fill the reserved region");

int main(void)
{
    (void)printf("WT-FFM-0011 PASS SP secure RAM [0x%08lX,0x%08lX) size 0x%lX\n",
                 (unsigned long)WT_SP_SECURE_RAM_BASE,
                 (unsigned long)WT_SP_SECURE_RAM_END,
                 (unsigned long)WT_SP_SECURE_RAM_SIZE);
    (void)printf("WT-FFM-0011 PASS crypto stack 0x%08lX, attest stack 0x%08lX\n",
                 (unsigned long)WT_SP_CRYPTO_STACK_BASE,
                 (unsigned long)WT_SP_ATTEST_STACK_BASE);
    (void)printf("PASS: sp_layout\n");
    return 0;
}
