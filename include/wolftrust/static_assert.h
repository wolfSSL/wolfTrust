/* static_assert.h
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

#ifndef WOLFTRUST_STATIC_ASSERT_H
#define WOLFTRUST_STATIC_ASSERT_H

/* File-scope compile-time assertion that remains valid under ISO C99. */
#define WT_STATIC_ASSERT_JOIN_INNER(a, b) a##b
#define WT_STATIC_ASSERT_JOIN(a, b) WT_STATIC_ASSERT_JOIN_INNER(a, b)
#define WT_STATIC_ASSERT(condition, message) \
    typedef char WT_STATIC_ASSERT_JOIN(wt_static_assert_, __LINE__) \
        [(condition) ? 1 : -1]

#endif /* WOLFTRUST_STATIC_ASSERT_H */
