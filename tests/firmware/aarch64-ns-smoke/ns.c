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

/* One FF-A SMC to the SPMD at the NS physical instance: in0/in1 in x0/x1, the
 * reply x0-x3 written back to out[0..3]. */
static void ffa_smc(uint64_t in0, uint64_t in1, uint64_t* out)
{
    register uint64_t r0 __asm__("x0") = in0;
    register uint64_t r1 __asm__("x1") = in1;
    register uint64_t r2 __asm__("x2") = 0;
    register uint64_t r3 __asm__("x3") = 0;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                       "x13", "x14", "x15", "x16", "x17", "memory");
    out[0] = r0;
    out[1] = r1;
    out[2] = r2;
    out[3] = r3;
}

/* Walk the NS physical instance: FEATURES(VERSION) is supported, ID_GET returns
 * the caller's own id (the primary NS endpoint, 0), SPM_ID_GET returns the SPMC
 * id (0x8000). Returns non-zero when all three answer as expected. */
static int discover(void)
{
    uint64_t o[4];

    ffa_smc(WT_FFA_FEATURES, WT_FFA_VERSION, o);
    if ((uint32_t)o[0] != WT_FFA_SUCCESS32) {
        return 0;
    }
    ffa_smc(WT_FFA_ID_GET, 0u, o);
    if (((uint32_t)o[0] != WT_FFA_SUCCESS32) ||
        ((uint16_t)o[2] != WT_FFA_ID_NS_PRIMARY)) {
        return 0;
    }
    ffa_smc(WT_FFA_SPM_ID_GET, 0u, o);
    if (((uint32_t)o[0] != WT_FFA_SUCCESS32) ||
        ((uint16_t)o[2] != WT_FFA_ID_SPMC)) {
        return 0;
    }
    return 1;
}

void ns_main(void)
{
    uint64_t current_el;
    uint64_t o[4];

    __asm__ volatile("mrs %0, CurrentEL" : "=r"(current_el));
    put_str("[NS] hello el=");
    put_char((char)('0' + (char)((current_el >> 2) & 0x3u)));
    put_str("\r\n");

    ffa_smc(WT_FFA_VERSION, WT_FFA_VERSION_1_2, o);
    if ((uint32_t)o[0] == WT_FFA_VERSION_1_2) {
        put_str("[NS] ffa version 1.2\r\n");
    }
    else {
        put_str("[NS] ffa version BAD 0x");
        put_hex((uint32_t)o[0]);
        put_str("\r\n");
    }

    if (discover()) {
        put_str("[NS] discovery ok\r\n");
    }
    else {
        put_str("[NS] discovery BAD\r\n");
    }
}
