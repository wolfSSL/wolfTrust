/* pal_console.c
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

/* Console backend the suite's logger calls: the Normal-world dispatcher owns
 * the Non-secure PL011; no partition maps a UART, so each one prints through
 * FFA_CONSOLE_LOG like the endpoints the suite never gives a UART. */

#include "pal_interfaces.h"
#include "pal_misc_asm.h"

void driver_uart_pl011_putc(uint8_t c);

#if defined(VM1_COMPILE)
#define WT_ACS_UART_DR      0x00u
#define WT_ACS_UART_FR      0x18u
#define WT_ACS_UART_FR_TXFF (1u << 5)

void driver_uart_pl011_putc(uint8_t c)
{
    volatile uint32_t* uart = (volatile uint32_t*)(uintptr_t)PLATFORM_NS_UART_BASE;

    while ((uart[WT_ACS_UART_FR / 4u] & WT_ACS_UART_FR_TXFF) != 0u) {
    }
    uart[WT_ACS_UART_DR / 4u] = (uint32_t)c;
}
#else
void driver_uart_pl011_putc(uint8_t c)
{
    pal_uart_putc_hypcall((char)c);
}
#endif
