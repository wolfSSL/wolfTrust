/* smoke.c
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

/* EL3 smoke for the QEMU AArch64 scenario runner: prints the exception
 * level, the machine, the generic timer frequency, and which secondary
 * cores reached the park loop, then returns so the entry code exits. */

#include <stdint.h>

#define UART_DR       0x00u
#define UART_FR       0x18u
#define UART_FR_TXFF  (1u << 5)
#define PARK_SLOTS    4u
#define PARK_WAIT_MS  200u

volatile uint8_t g_parked[PARK_SLOTS];
volatile uint32_t g_ready;

static volatile uint32_t* uart_reg(uint32_t offset)
{
    return (volatile uint32_t*)(uintptr_t)(WT_SMOKE_UART + offset);
}

/* QEMU's PL011 transmits without CR/IBRD setup; this smoke never runs on silicon. */
static void put_char(char c)
{
    while ((*uart_reg(UART_FR) & UART_FR_TXFF) != 0u) {
    }
    *uart_reg(UART_DR) = (uint32_t)(uint8_t)c;
}

static void put_str(const char* s)
{
    while (*s != '\0') {
        put_char(*s);
        s++;
    }
}

static void put_hex(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    char buf[17];
    int i = 16;

    buf[i] = '\0';
    do {
        i--;
        buf[i] = digits[value & 0xFu];
        value >>= 4;
    } while (value != 0u && i > 0);
    put_str(&buf[i]);
}

static void put_dec(uint64_t value)
{
    char buf[21];
    int i = 20;

    buf[i] = '\0';
    do {
        i--;
        buf[i] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0u && i > 0);
    put_str(&buf[i]);
}

static uint64_t cntpct(void)
{
    uint64_t value;

    __asm__ volatile("isb; mrs %0, CNTPCT_EL0" : "=r"(value));
    return value;
}

static uint32_t parked_mask(void)
{
    uint32_t mask = 0u;
    uint32_t i;

    for (i = 0u; i < PARK_SLOTS; i++) {
        if (g_parked[i] != 0u) {
            mask |= (1u << i);
        }
    }
    return mask;
}

void smoke_main(void)
{
    uint64_t current_el;
    uint64_t cntfrq;
    uint64_t deadline;
    uint32_t expected = (uint32_t)((1u << WT_SMOKE_CPUS) - 2u);
    uint32_t mask;

    __asm__ volatile("mrs %0, CurrentEL" : "=r"(current_el));
    __asm__ volatile("mrs %0, CNTFRQ_EL0" : "=r"(cntfrq));

    deadline = cntpct() + ((cntfrq * PARK_WAIT_MS) / 1000u);
    do {
        mask = parked_mask();
    } while (mask != expected && cntpct() < deadline);

    put_str("[SMOKE] EL");
    put_dec(current_el >> 2);
    put_str(" machine=" WT_SMOKE_MACHINE " cntfrq=");
    put_dec(cntfrq);
    put_str(" parked_mask=0x");
    put_hex(mask);
    put_str("\r\n[SMOKE] exit 0\r\n");
}
