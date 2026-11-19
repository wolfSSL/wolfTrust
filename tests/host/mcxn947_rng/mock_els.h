/* mock_els.h
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


/* Every MCXN947 register access in the driver under test goes through the
 * model in main.c, which plays the ELS command interface. */

#ifndef WT_TEST_MOCK_ELS_H
#define WT_TEST_MOCK_ELS_H

#include <stdint.h>

volatile uint32_t* wt_mock_reg(uintptr_t address);

#define WT_REG32(address) (*wt_mock_reg((uintptr_t)(address)))

#endif /* WT_TEST_MOCK_ELS_H */
