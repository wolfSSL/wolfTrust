/* ns.c
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

/* A minimal Normal-world payload for the ns-smoke scenario: print the exception
 * level on the NS console, negotiate FF-A with an SMC to the SPMD, and report
 * the version. It proves the world switch and the SPMD NS physical instance. */

#include "wolftrust/arch/aarch64/ffa_abi.h"

#include <stdint.h>

#define UART_DR         0x00u
#define UART_FR         0x18u
#define UART_FR_TXFF    (1u << 5)

static volatile uint32_t* uart_reg(uint32_t offset)
{
    return (volatile uint32_t*)(uintptr_t)(WT_NS_UART + offset);
}

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

static void put_hex(uint32_t value)
{
    static const char digits[] = "0123456789abcdef";
    char buf[9];
    int i = 8;

    buf[i] = '\0';
    do {
        i--;
        buf[i] = digits[value & 0xFu];
        value >>= 4;
    } while (value != 0u && i > 0);
    put_str(&buf[i]);
}

static uint32_t ffa_version(void)
{
    register uint64_t r0 __asm__("x0") = WT_FFA_VERSION;
    register uint64_t r1 __asm__("x1") = WT_FFA_VERSION_1_2;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1)
                     :
                     : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
                       "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory");
    return (uint32_t)r0;
}

void ns_main(void)
{
    uint64_t current_el;
    uint32_t version;

    __asm__ volatile("mrs %0, CurrentEL" : "=r"(current_el));
    put_str("[NS] hello el=");
    put_char((char)('0' + (char)((current_el >> 2) & 0x3u)));
    put_str("\r\n");

    version = ffa_version();
    if (version == WT_FFA_VERSION_1_2) {
        put_str("[NS] ffa version 1.2\r\n");
    }
    else {
        put_str("[NS] ffa version BAD 0x");
        put_hex(version);
        put_str("\r\n");
    }
}
