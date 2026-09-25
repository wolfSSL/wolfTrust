/* mock_xspi_regs.h
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

/* Force-included ahead of xspi_nor.c: the real register header supplies the
 * layout, WT_REG32 collapses to the register address, and the driver's read
 * and write accessors route every access through the test's model. */
#ifndef WT_TEST_MOCK_XSPI_REGS_H
#define WT_TEST_MOCK_XSPI_REGS_H

#include <stdint.h>

#include "mimxrt798_regs.h"

uint32_t wt_mock_read(uint32_t address);
void wt_mock_write(uint32_t address, uint32_t value);

#undef WT_REG32
#define WT_REG32(address)       ((uint32_t)(address))
#define WT_XSPI_RD(reg)         wt_mock_read(reg)
#define WT_XSPI_WR(reg, value)  wt_mock_write((reg), (value))

#endif /* WT_TEST_MOCK_XSPI_REGS_H */
