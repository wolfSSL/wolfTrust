/* libc_min.c
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

/* The two routines GCC may emit calls to in a -nostdlib image. */

#include <stddef.h>
#include <stdint.h>

void* memset(void* dest, int value, size_t count);
void* memcpy(void* dest, const void* src, size_t count);

void* memset(void* dest, int value, size_t count)
{
    uint8_t* out = (uint8_t*)dest;
    size_t i;

    for (i = 0u; i < count; ++i) {
        out[i] = (uint8_t)value;
    }
    return dest;
}

void* memcpy(void* dest, const void* src, size_t count)
{
    uint8_t* out = (uint8_t*)dest;
    const uint8_t* in = (const uint8_t*)src;
    size_t i;

    for (i = 0u; i < count; ++i) {
        out[i] = in[i];
    }
    return dest;
}
