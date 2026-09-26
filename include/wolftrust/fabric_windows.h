/* fabric_windows.h
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

#ifndef WOLFTRUST_FABRIC_WINDOWS_H
#define WOLFTRUST_FABRIC_WINDOWS_H

#include "wolftrust/types.h"

/* Per-dispatch guest RAM isolation, SoC- and architecture-neutral.
 *
 * Every dispatch closes the whole shared guest RAM extent (Secure to a
 * Non-secure master) and reopens only the arriving guest's declared writable
 * windows. The algorithm is identical across ports; only the primitive that
 * marks memory secure/Non-secure differs: the STM32H5 drives GTZC MPCBB blocks,
 * the MIMXRT700 drives SAU regions (per its reference manual the AHB secure
 * controller does not gate CPU0, so the SAU is the CPU's isolation layer). A
 * port supplies the extent and the three primitives. */
typedef struct wt_fabric_windows {
    uintptr_t extent_base;
    uintptr_t extent_end;                       /* one past the last byte */
    void (*close_all)(void);                    /* whole extent -> Secure */
    void (*open_window)(uintptr_t base, size_t size); /* [base,size) -> NS */
    void (*commit)(void);                       /* barrier after edits */
} wt_fabric_windows_t;

/* Close the extent, reopen each writable window that lies fully inside it,
 * then commit. A NULL descriptor or a NULL primitive is a no-op (the caller's
 * fail-closed path owns the missing-capability case). */
void wt_fabric_apply_windows(const wt_fabric_windows_t* fabric,
                             const wt_memory_window_t* windows, size_t count);

#endif /* WOLFTRUST_FABRIC_WINDOWS_H */
