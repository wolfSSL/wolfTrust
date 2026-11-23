/* zeroize_probe.h
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

#ifndef WT_TEST_ZEROIZE_PROBE_H
#define WT_TEST_ZEROIZE_PROBE_H

#include "wolftrust/zeroize.h"

/* Forced into the production translation unit by the host test build. */
void wt_test_forceZero(void* memory, size_t size);
#define wt_forceZero wt_test_forceZero

#endif /* WT_TEST_ZEROIZE_PROBE_H */
