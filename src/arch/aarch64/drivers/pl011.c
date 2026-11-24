/* pl011.c
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

#include "wolftrust/arch/aarch64/pl011.h"

#define PL011_DR      0x000u
#define PL011_FR      0x018u
#define PL011_IBRD    0x024u
#define PL011_FBRD    0x028u
#define PL011_LCR_H   0x02Cu
#define PL011_CR      0x030u
#define PL011_IMSC    0x038u
#define PL011_ICR     0x044u

#define PL011_FR_BUSY  (1u << 3)
#define PL011_FR_TXFF  (1u << 5)
#define PL011_LCR_H_FEN   (1u << 4)
#define PL011_LCR_H_WLEN8 (3u << 5)
#define PL011_CR_UARTEN   (1u << 0)
#define PL011_CR_TXE      (1u << 8)
#define PL011_CR_RXE      (1u << 9)

static volatile uint32_t* pl011_reg(uintptr_t base, uint32_t offset)
{
    return (volatile uint32_t*)(base + offset);
}

void wt_pl011_init(uintptr_t base, uint32_t clock_hz, uint32_t baud)
{
    uint32_t divisor;

    *pl011_reg(base, PL011_CR) = 0u;
    while ((*pl011_reg(base, PL011_FR) & PL011_FR_BUSY) != 0u) {
    }
    /* IBRD.FBRD = clock / (16 * baud) in 16.6 fixed point. */
    divisor = (clock_hz * 4u) / baud;
    *pl011_reg(base, PL011_IBRD) = divisor >> 6;
    *pl011_reg(base, PL011_FBRD) = divisor & 0x3Fu;
    *pl011_reg(base, PL011_LCR_H) = PL011_LCR_H_WLEN8 | PL011_LCR_H_FEN;
    *pl011_reg(base, PL011_IMSC) = 0u;
    *pl011_reg(base, PL011_ICR) = 0x7FFu;
    *pl011_reg(base, PL011_CR) = PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE;
}

void wt_pl011_putc(uintptr_t base, char c)
{
    while ((*pl011_reg(base, PL011_FR) & PL011_FR_TXFF) != 0u) {
    }
    *pl011_reg(base, PL011_DR) = (uint32_t)(uint8_t)c;
}

void wt_pl011_flush(uintptr_t base)
{
    while ((*pl011_reg(base, PL011_FR) & PL011_FR_BUSY) != 0u) {
    }
}
