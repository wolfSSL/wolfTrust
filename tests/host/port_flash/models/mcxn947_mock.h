/* mcxn947_mock.h
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

/* Force-included ahead of port/mcxn947/flash_drv.c: reads through the Secure
 * alias come from the flash array. */
#ifndef WT_TEST_MCXN947_MOCK_H
#define WT_TEST_MCXN947_MOCK_H

#include <stdint.h>

uint8_t wt_mock_flash_rd8(uintptr_t address);

#define WT_FLASH_RD8(address) (wt_mock_flash_rd8(address))

#endif /* WT_TEST_MCXN947_MOCK_H */
