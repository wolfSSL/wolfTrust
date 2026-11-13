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

/* STM32L562 (STM32L562E-DK) board seams for the portable PSA guest: the
 * console is USART1 through its Non-secure alias. The Secure side clocks it
 * and muxes PA9/PA10; the guest sets the baud and enables the transmitter. */

#ifndef WOLFTRUST_PSA_GUEST_BOARD_H
#define WOLFTRUST_PSA_GUEST_BOARD_H

#include <stdint.h>

#define GUEST_UART_BASE       0x40013800u
#define GUEST_UART_CR1        (*(volatile uint32_t*)(GUEST_UART_BASE + 0x00u))
#define GUEST_UART_BRR        (*(volatile uint32_t*)(GUEST_UART_BASE + 0x0Cu))
#define GUEST_UART_ISR        (*(volatile uint32_t*)(GUEST_UART_BASE + 0x1Cu))
#define GUEST_UART_TDR        (*(volatile uint32_t*)(GUEST_UART_BASE + 0x28u))
#define GUEST_UART_CR1_UE_TE  0x00000009u
#define GUEST_UART_ISR_TXE    0x00000080u
#define GUEST_UART_BRR_115200 (110000000u / 115200u)
#define GUEST_UART_POLL_LIMIT 100000u

static inline void guest_board_uart_init(void)
{
    if ((GUEST_UART_CR1 & GUEST_UART_CR1_UE_TE) != GUEST_UART_CR1_UE_TE) {
        GUEST_UART_BRR = GUEST_UART_BRR_115200;
        GUEST_UART_CR1 = GUEST_UART_CR1_UE_TE;
    }
}

static inline void guest_board_uart_putc(char c)
{
    uint32_t t = GUEST_UART_POLL_LIMIT;

    while (((GUEST_UART_ISR & GUEST_UART_ISR_TXE) == 0u) && (t > 0u)) {
        t--;
    }
    if (t != 0u) {
        GUEST_UART_TDR = (uint32_t)(uint8_t)c;
    }
}

/* Secure RAM the restart probe reads (WT_RAM_S_BASE in port/stm32l562). */
#define GUEST_SECURE_RAM_ADDR 0x30001000u

#endif /* WOLFTRUST_PSA_GUEST_BOARD_H */
