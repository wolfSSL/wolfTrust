/* fabric_sau.h
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

/* The per-dispatch guest RAM backend over the SAU's dynamic regions: the
 * regions above the port's static table. close_all drops them all (guest
 * RAM falls to the SAU default, Secure); open_window marks one window
 * Non-secure. A window that is misaligned, overflows, overlaps an open one,
 * exceeds the SAU's capacity or does not read back is refused by a panic,
 * never left silently Secure or silently shared. */

#ifndef WOLFTRUST_PORT_ARMV8M_FABRIC_SAU_H
#define WOLFTRUST_PORT_ARMV8M_FABRIC_SAU_H

#include <stddef.h>

#include "wolftrust/fabric_windows.h"

/* Reserve the dynamic regions above static_count; nonzero when the SAU
 * implements no region for a dynamic window. */
int wt_fabric_sau_init(size_t static_count);
extern const wt_fabric_windows_t wt_fabric_sau_backend;

#endif /* WOLFTRUST_PORT_ARMV8M_FABRIC_SAU_H */
