/* stm32h563_mock.h
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

/* Force-included ahead of port/stm32h563/flash_drv.c: the flash controller,
 * the ICACHE and the flash array come from the model. */
#ifndef WT_TEST_STM32H563_MOCK_H
#define WT_TEST_STM32H563_MOCK_H

#include <stdint.h>

volatile uint32_t* wt_mock_flash_reg(uint32_t offset);
volatile uint32_t* wt_mock_icache_reg(uint32_t offset);
uint8_t wt_mock_flash_rd8(uintptr_t address);
void wt_mock_flash_wr32(uintptr_t address, uint32_t value);

#define WT_FLASH_REG(offset)          (*wt_mock_flash_reg(offset))
#define WT_ICACHE_REG(offset)         (*wt_mock_icache_reg(offset))
#define WT_FLASH_RD8(address)         (wt_mock_flash_rd8(address))
#define WT_FLASH_WR32(address, value) (wt_mock_flash_wr32((address), (value)))

#endif /* WT_TEST_STM32H563_MOCK_H */
