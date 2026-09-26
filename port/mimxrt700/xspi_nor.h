/* xspi_nor.h
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

#ifndef WOLFTRUST_MIMXRT700_XSPI_NOR_H
#define WOLFTRUST_MIMXRT700_XSPI_NOR_H

#include <stdint.h>

#define WT_XSPI_NOR_OK         0
#define WT_XSPI_NOR_TIMEOUT   -1
#define WT_XSPI_NOR_BUS       -2
#define WT_XSPI_NOR_DEVICE    -3
#define WT_XSPI_NOR_ARGUMENT  -4

#define WT_XSPI_NOR_SECTOR    0x1000u
#define WT_XSPI_NOR_UNIT      16u

/* Addresses use the XSPI0 Non-secure aperture numbering (0x28000000 based),
 * the numbering the first loader programmed into the FRAD windows. Only the
 * update partition and the Secure NVM stores are writable through this path. */
int wt_xspi_nor_erase(uint32_t address, uint32_t size);
int wt_xspi_nor_program(uint32_t address, const uint8_t* data, uint32_t size);

#if defined(WT_REMEASURE_PROBE)
int wt_xspi_nor_probe_tamper(uint32_t address);
#endif

#endif /* WOLFTRUST_MIMXRT700_XSPI_NOR_H */
