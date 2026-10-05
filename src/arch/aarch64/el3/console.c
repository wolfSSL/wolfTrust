/* console.c
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

/* EL3 console: formatting over the port's polled putc; no printf. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/esr.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/sysreg.h"

void wt_el3_puts(const char* text)
{
    while (*text != '\0') {
        wt_platform_console_putc(*text);
        text++;
    }
}

void wt_el3_puthex(uint64_t value, unsigned int digits)
{
    static const char table[] = "0123456789abcdef";
    unsigned int shift = digits * 4u;

    while (shift > 0u) {
        shift -= 4u;
        wt_platform_console_putc(table[(value >> shift) & 0xFu]);
    }
}

void wt_el3_putdec(uint64_t value)
{
    char buf[21];
    int i = 20;

    buf[i] = '\0';
    do {
        i--;
        buf[i] = (char)('0' + (value % 10u));
        value /= 10u;
    } while ((value != 0u) && (i > 0));
    wt_el3_puts(&buf[i]);
}

void wt_el3_fault(uint64_t kind, uint64_t esr, uint64_t far, uint64_t elr)
{
    char line[80];
    uint32_t el = 3u;

    if (kind >= WT_EL3_VEC_LOWER64_SYNC) {
        el = WT_SPSR_M_EL(wt_read_spsr_el3());
    }
    (void)wt_esr_format(line, sizeof(line), el, esr, far);
    wt_el3_puts(line);
    wt_el3_puts(" ELR=0x");
    wt_el3_puthex(elr, 16u);
    wt_el3_puts(" vector=");
    wt_el3_putdec(kind);
    wt_el3_puts("\r\n[EL3] panic code=0x");
    wt_el3_puthex(WT_ESR_EC(esr), 2u);
    wt_el3_puts("\r\n");
    wt_platform_console_flush();
    wt_el3_semihost_exit(WT_MON_EXIT_PANIC);
}
