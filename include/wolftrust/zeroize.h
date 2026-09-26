/* zeroize.h
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

#ifndef WOLFTRUST_ZEROIZE_H
#define WOLFTRUST_ZEROIZE_H

#include <stddef.h>

static inline void wt_forceZero(void* memory, size_t size)
{
    volatile unsigned char* bytes = (volatile unsigned char*)memory;

    while (size >= 4U) {
        bytes[0] = 0U;
        bytes[1] = 0U;
        bytes[2] = 0U;
        bytes[3] = 0U;
        bytes += 4;
        size -= 4U;
    }
    while (size > 0U) {
        *bytes++ = 0U;
        size--;
    }
}

#endif /* WOLFTRUST_ZEROIZE_H */
