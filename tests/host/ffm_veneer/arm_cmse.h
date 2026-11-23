/* arm_cmse.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
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

#ifndef WT_TEST_ARM_CMSE_H
#define WT_TEST_ARM_CMSE_H

#include <stddef.h>

/* Flags from the Arm C Language Extensions for CMSE. */
#define CMSE_MPU_READWRITE 1
#define CMSE_MPU_READ 8
#define CMSE_NONSECURE 18

void* cmse_check_address_range(void* address, size_t size, int flags);

#endif
