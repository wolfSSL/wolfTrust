/* main.c
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

/* Host suite for port/stm32l562/guest_wrp.c: the guest flash WRP coverage
 * check over modelled FLASH_OPTR and WRP area registers. */

#include <stdint.h>
#include <stdio.h>

#include "wolftrust/platform.h"
#include "wolftrust/guest_verify.h"

#include "memory_map.h"

static int checks;
static int failures;

#define EXPECT(cond, what) \
    do { \
        checks++; \
        if (!(cond)) { \
            (void)fprintf(stderr, "line %d: %s\n", __LINE__, (what)); \
            failures++; \
        } \
    } while (0)

static uint32_t g_optr;
static uint32_t g_wrp1a;
static uint32_t g_wrp1b;
static uint32_t g_wrp2a;
static uint32_t g_wrp2b;
static volatile uint32_t g_cell;
static uint32_t g_unknown_regs;

volatile uint32_t* wt_mock_reg(uintptr_t address)
{
    switch (address - (uintptr_t)WT_FLASH_BASE_S) {
        case 0x40u:
            g_cell = g_optr;
            break;
        case 0x58u:
            g_cell = g_wrp1a;
            break;
        case 0x5Cu:
            g_cell = g_wrp1b;
            break;
        case 0x68u:
            g_cell = g_wrp2a;
            break;
        case 0x6Cu:
            g_cell = g_wrp2b;
            break;
        default:
            g_unknown_regs++;
            g_cell = 0u;
            break;
    }
    return &g_cell;
}

/* An area register: inclusive start and end pages; start > end is off. */
static uint32_t area(uint32_t start, uint32_t end)
{
    return start | (end << WT_FLASH_WRP_PEND_SHIFT);
}

#define OFF          area(0x7Fu, 0x00u)
#define BANK2        (WT_FLASH_NS_BASE + WT_FLASH_BANK_SIZE)
#define PAGE         WT_FLASH_PAGE_SIZE

static void clear(void)
{
    g_optr = WT_FLASH_OPTR_DBANK;
    g_wrp1a = OFF;
    g_wrp1b = OFF;
    g_wrp2a = OFF;
    g_wrp2b = OFF;
}

static int ok(uintptr_t base, size_t size)
{
    return wt_platform_guest_flash_wrp_ok(base, size) == WT_GUEST_VERIFY_OK;
}

int main(void)
{
    const uintptr_t guests = BANK2 + 0x20000u;
    const size_t span = 0x20000u;

    clear();
    EXPECT(!ok(guests, span), "no armed area leaves the guests unprotected");
    EXPECT(!ok(guests, 0u), "a zero-length window is refused");
    EXPECT(!ok(WT_FLASH_NS_BASE - PAGE, PAGE),
           "a window below flash is refused");
    EXPECT(!ok(WT_FLASH_NS_BASE + WT_FLASH_SIZE - PAGE, 2u * PAGE),
           "a window past the end of flash is refused");
    EXPECT(!ok(guests, (size_t)0u - 0x100u),
           "a window whose end wraps the address space is refused");
    EXPECT(!ok(UINTPTR_MAX - 0xFFu, 0x08040200u),
           "a window above flash whose end wraps into it is refused");

    g_wrp2a = area(0x40u, 0x7Fu);
    EXPECT(ok(guests, span), "WRP2A over pages 0x40-0x7F covers the guests");
    EXPECT(ok(guests + PAGE, PAGE), "and any page inside them");
    EXPECT(!ok(BANK2 + 0x1F800u, 2u * PAGE),
           "a window starting one page below the area is refused");

    g_wrp2a = area(0x40u, 0x5Fu);
    g_wrp2b = area(0x60u, 0x7Fu);
    EXPECT(ok(guests, span), "split A and B areas cover the guests together");
    g_wrp2a = area(0x40u, 0x5Eu);
    EXPECT(!ok(guests, span), "a one-page hole between A and B is refused");
    g_wrp2a = area(0x40u, 0x7Fu);
    g_wrp2b = area(0x7Fu, 0x00u);
    EXPECT(ok(guests, span), "a disabled B does not undo a covering A");

    clear();
    g_wrp1a = area(0x40u, 0x7Fu);
    EXPECT(!ok(guests, span), "bank 1's area does not protect bank 2");
    EXPECT(ok(WT_FLASH_NS_BASE + 0x20000u, span),
           "bank 1's area protects the same pages of bank 1");
    EXPECT(!ok(BANK2 - PAGE, 2u * PAGE), "a window across the banks is refused");

    /* SWAP_BANK puts bank 1's option bytes behind the upper address range. */
    g_optr = WT_FLASH_OPTR_DBANK | WT_FLASH_OPTR_SWAP_BANK;
    EXPECT(ok(guests, span), "under SWAP_BANK, WRP1A protects the upper range");
    g_wrp1a = OFF;
    g_wrp2a = area(0x40u, 0x7Fu);
    EXPECT(!ok(guests, span), "and WRP2A no longer does");

    /* Single-bank mode: the dual-bank WRP map no longer applies. */
    clear();
    g_wrp2a = area(0x40u, 0x7Fu);
    g_optr = 0u;
    EXPECT(!ok(guests, span), "a covering WRP2A is refused with DBANK clear");
    g_wrp1a = area(0x00u, 0x7Fu);
    EXPECT(!ok(WT_FLASH_NS_BASE + 0x20000u, span),
           "and so is a covering WRP1A");

    EXPECT(g_unknown_regs == 0u, "only FLASH_OPTR and the WRP areas were read");
    (void)printf("stm32l562 wrp: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
