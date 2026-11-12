/* mock_l5_gtzc.h
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

/* Force-included ahead of gtzc.c: the RCC and TZSC registers and both MPCBB
 * vectors are cells of the suite's model, applied on the next access. */
#ifndef WT_TEST_MOCK_L5_GTZC_H
#define WT_TEST_MOCK_L5_GTZC_H

#include <stdint.h>

#include "stm32l562_regs.h"

volatile uint32_t* wt_mock_reg(uintptr_t address);
volatile uint32_t* wt_mock_mpcbb(int controller);

#undef WT_REG32
#define WT_REG32(address) (*wt_mock_reg((uintptr_t)(address)))
#undef WT_GTZC_MPCBB1_VCTR
#define WT_GTZC_MPCBB1_VCTR (wt_mock_mpcbb(1))
#undef WT_GTZC_MPCBB2_VCTR
#define WT_GTZC_MPCBB2_VCTR (wt_mock_mpcbb(2))

#endif /* WT_TEST_MOCK_L5_GTZC_H */
