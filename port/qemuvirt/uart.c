/* uart.c
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

/* Secure console of the QEMU virt port: the secure PL011. */

#include "memory_map.h"
#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/pl011.h"

void wt_platform_console_putc(char c)
{
    wt_pl011_putc(WT_UART_S_BASE, c);
}

void wt_platform_console_flush(void)
{
    wt_pl011_flush(WT_UART_S_BASE);
}
