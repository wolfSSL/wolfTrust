/* pal_misc_asm.h
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

/* pal_misc.c includes the assembly helpers' header. */

#ifndef WT_TEST_PAL_MISC_ASM_H
#define WT_TEST_PAL_MISC_ASM_H

#include <stdint.h>

/* Only the dispatcher's build calls it; the device-map rows compile it. */
uint64_t pal_syscall_for_psci(uint64_t fid, uint64_t x1, uint64_t x2,
                              uint64_t x3);

#endif /* WT_TEST_PAL_MISC_ASM_H */
