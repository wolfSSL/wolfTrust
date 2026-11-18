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

/* STM32L562 (STM32L562E-DK) board seams for the shared Non-secure guests:
 * the USART1 console (the ST-LINK virtual COM port, which the Secure image
 * pins and clocks) and the probe addresses. */

#ifndef WOLFTRUST_GUEST_BOARD_H
#define WOLFTRUST_GUEST_BOARD_H

#include <stdint.h>

#define GUEST_BOARD_NAME      "STM32L562"

#define GUEST_UART_BASE       0x40013800u
#define GUEST_USART_CR1       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x00u))
#define GUEST_USART_BRR       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x0Cu))
#define GUEST_USART_ISR       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x1Cu))
#define GUEST_USART_TDR       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x28u))
#define GUEST_USART_CR1_UE_TE 0x00000009u
#define GUEST_USART_ISR_TXE   (1u << 7)
#define GUEST_UART_POLL_LIMIT 100000u

#ifndef GUEST_UART_CLOCK_HZ
#define GUEST_UART_CLOCK_HZ   110000000u
#endif
#define GUEST_UART_BAUD       115200u

/* Both guests share USART1: the first to run configures it. */
static inline void guest_board_uart_init(void)
{
    if ((GUEST_USART_CR1 & GUEST_USART_CR1_UE_TE) != GUEST_USART_CR1_UE_TE) {
        GUEST_USART_BRR = GUEST_UART_CLOCK_HZ / GUEST_UART_BAUD;
        GUEST_USART_CR1 = GUEST_USART_CR1_UE_TE;
    }
}

static inline void guest_board_uart_putc(char c)
{
    uint32_t t = GUEST_UART_POLL_LIMIT;

    while (((GUEST_USART_ISR & GUEST_USART_ISR_TXE) == 0u) && (t > 0u)) {
        t--;
    }
    if (t != 0u) {
        GUEST_USART_TDR = (uint32_t)(uint8_t)c;
    }
}

/* A console identity for the mailbox: the USART's Non-secure base. */
static inline uint32_t guest_board_console_id(void)
{
    return GUEST_UART_BASE;
}

/* Secure RAM the restart probe reads (WT_RAM_S_BASE in port/stm32l562). */
#define GUEST_SECURE_RAM_ADDR 0x30001000u

/* The SPM's RNG through its Non-secure alias (periphneg). */
#define GUEST_PERIPH_NS_ADDR  0x420C0800u

#endif /* WOLFTRUST_GUEST_BOARD_H */
