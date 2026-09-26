/* fabric_windows.c
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

#include "wolftrust/fabric_windows.h"
#include "wolftrust/domain.h"

void wt_fabric_apply_windows(const wt_fabric_windows_t* fabric,
                             const wt_memory_window_t* windows, size_t count)
{
    size_t w;

    if (fabric == NULL || fabric->close_all == NULL ||
            fabric->open_window == NULL || fabric->commit == NULL) {
        return;
    }

    fabric->close_all();

    for (w = 0U; windows != NULL && w < count; ++w) {
        uintptr_t base = windows[w].base;
        uintptr_t end = base + windows[w].size;

        if ((windows[w].attributes & WT_MEMORY_ATTR_WRITE) == 0U) {
            continue;
        }
        /* Reject an empty or wrapping window and anything not wholly inside
         * the guest RAM extent; only writable RAM is reopened Non-secure. */
        if (end <= base || base < fabric->extent_base ||
                end > fabric->extent_end) {
            continue;
        }
        fabric->open_window(base, windows[w].size);
    }

    fabric->commit();
}
