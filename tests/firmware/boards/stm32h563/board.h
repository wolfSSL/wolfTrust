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

/* STM32H563 (NUCLEO-H563ZI) board seams for the shared Non-secure guests:
 * the console is USART3 through its Non-secure alias; the Secure side leaves
 * its clock and pins enabled, so the guest programs the baud rate itself. */

#ifndef WOLFTRUST_GUEST_BOARD_H
#define WOLFTRUST_GUEST_BOARD_H

#include <stdint.h>

#define GUEST_BOARD_NAME      "STM32H563"

#define GUEST_UART_BASE       0x40004800u
#define GUEST_USART_CR1       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x00u))
#define GUEST_USART_CR2       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x04u))
#define GUEST_USART_CR3       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x08u))
#define GUEST_USART_BRR       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x0Cu))
#define GUEST_USART_ISR       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x1Cu))
#define GUEST_USART_TDR       (*(volatile uint32_t*)(GUEST_UART_BASE + 0x28u))
#define GUEST_USART_CR1_UE    (1u << 0)
#define GUEST_USART_CR1_RE    (1u << 2)
#define GUEST_USART_CR1_TE    (1u << 3)
#define GUEST_USART_ISR_TXE   (1u << 7)
#define GUEST_UART_POLL_LIMIT 100000u

#ifndef GUEST_UART_CLOCK_HZ
#define GUEST_UART_CLOCK_HZ   120000000u
#endif
#define GUEST_UART_BAUD       115200u

static inline void guest_board_uart_init(void)
{
    GUEST_USART_CR1 = 0u;
    GUEST_USART_CR2 = 0u;
    GUEST_USART_CR3 = 0u;
    GUEST_USART_BRR = GUEST_UART_CLOCK_HZ / GUEST_UART_BAUD;
    GUEST_USART_CR1 = GUEST_USART_CR1_UE | GUEST_USART_CR1_TE |
                      GUEST_USART_CR1_RE;
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

/* Secure RAM the restart probe reads (WT_RAM_S_BASE in port/stm32h563). */
#define GUEST_SECURE_RAM_ADDR 0x30028000u

/* The SPM's RNG through its Non-secure alias (periphneg). */
#define GUEST_PERIPH_NS_ADDR  0x420C0800u

/* The board runs its own peripheral probe (board.c): the RNG alias plus
 * GPDMA copies out of the Secure image and Secure SRAM. */
#define GUEST_BOARD_PERIPH_PROBE 1

#endif /* WOLFTRUST_GUEST_BOARD_H */
