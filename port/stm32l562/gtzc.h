/* gtzc.h
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

#ifndef WT_STM32L562_GTZC_H
#define WT_STM32L562_GTZC_H

#include <stdint.h>

/* Marks the SRAM blocks in [base, end) Secure (secure != 0) or Non-secure */
void wt_l5_gtzc_set_range(uintptr_t base, uintptr_t end, int secure);

/* Boot attribution: SPM SRAM and peripherals Secure, guest RAM and USART1
 * Non-secure, read back; returns 0, or -1 when a register did not take. */
int wt_l5_gtzc_init(void);

#endif /* WT_STM32L562_GTZC_H */
