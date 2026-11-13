/* mock_l5_rng.h
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

/* Force-included ahead of rng_entropy.c: the real register header supplies
 * every offset and bit, then each access routes through the RCC and RNG
 * model in main.c. */
#ifndef WT_TEST_MOCK_L5_RNG_H
#define WT_TEST_MOCK_L5_RNG_H

#include <stdint.h>

#include "stm32l562_regs.h"

volatile uint32_t* wt_mock_reg(uintptr_t address);

#undef WT_REG32
#define WT_REG32(address) (*wt_mock_reg((uintptr_t)(address)))

#endif /* WT_TEST_MOCK_L5_RNG_H */
