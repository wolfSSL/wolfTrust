/* flash_array.h
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

/* A RAM model of the flash windows the Secure image writes, shared by the
 * three port models: the update partition, both stores and guest 0's first
 * sector, each addressed by its Secure alias. A unit is programmed once
 * per erase; the knobs inject device failures. */

#ifndef WT_TEST_FLASH_ARRAY_H
#define WT_TEST_FLASH_ARRAY_H

#include <stdint.h>

#define FA_OK        0
#define FA_UNMAPPED -1
#define FA_TWICE    -2
#define FA_INJECTED -3

uint8_t* fa_map(uintptr_t s_addr, uint32_t size);
int fa_program(uintptr_t s_addr, const uint8_t* src, uint32_t size);
int fa_erase(uintptr_t s_addr, uint32_t size);
int fa_blank(uintptr_t s_addr, uint32_t size);
void fa_fail_programs_after(uint32_t count);
void fa_fail_erases_after(uint32_t count);
uint32_t fa_programs(void);
uint32_t fa_erases(void);
uint32_t fa_sector_erases(uintptr_t s_addr);

#endif /* WT_TEST_FLASH_ARRAY_H */
