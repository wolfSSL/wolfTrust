/* board.h
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

/* MIMXRT700 (MIMXRT798S compute Cortex-M33) board seams for the portable PSA
 * guest: the console is LPUART0 through its Non-secure alias, configured by
 * the first loader, so the guest only polls TDRE and writes DATA. */

#ifndef WOLFTRUST_PSA_GUEST_BOARD_H
#define WOLFTRUST_PSA_GUEST_BOARD_H

#include <stdint.h>

#define GUEST_UART_BASE      0x40110000u
#define GUEST_UART_STAT      (*(volatile uint32_t*)(GUEST_UART_BASE + 0x14u))
#define GUEST_UART_DATA      (*(volatile uint32_t*)(GUEST_UART_BASE + 0x1Cu))
#define GUEST_UART_STAT_TDRE 0x00800000u
#define GUEST_UART_POLL_LIMIT 100000u

static inline void guest_board_uart_init(void)
{
}

static inline void guest_board_uart_putc(char c)
{
    uint32_t t = GUEST_UART_POLL_LIMIT;

    while (((GUEST_UART_STAT & GUEST_UART_STAT_TDRE) == 0u) && (t > 0u)) {
        t--;
    }
    if (t != 0u) {
        GUEST_UART_DATA = (uint32_t)(uint8_t)c;
    }
}

/* Secure RAM the restart probe reads (WT_RAM_S_BASE in port/mimxrt700). */
#define GUEST_SECURE_RAM_ADDR 0x30188000u

#endif /* WOLFTRUST_PSA_GUEST_BOARD_H */
