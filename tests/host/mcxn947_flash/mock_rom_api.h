/* mock_rom_api.h
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

/* Force-included ahead of rom_flash.c: the boot ROM API tree and the flash
 * read view come from the test's model instead of the part's addresses. */
#ifndef WT_TEST_MOCK_ROM_API_H
#define WT_TEST_MOCK_ROM_API_H

#include <stdint.h>

uintptr_t wt_mock_rom_tree(void);
uintptr_t wt_mock_flash_base(void);

#define WT_ROM_API_TREE_ADDR    (wt_mock_rom_tree())
#define WT_ROM_FLASH_VIEW_BASE  (wt_mock_flash_base())

#endif /* WT_TEST_MOCK_ROM_API_H */
