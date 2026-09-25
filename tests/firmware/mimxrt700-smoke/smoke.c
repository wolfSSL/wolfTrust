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

/* MIMXRT700 BootROM XIP smoke: proves the FCB + MBI wrapping boots our own
 * image from XSPI0. Leaves a marker and a live counter in SRAM for the
 * debugger; no clocks, pins, or UART are touched. */

#include <stdint.h>

#define SMOKE_MARKER_ADDR   0x20180000u
#define SMOKE_COUNTER_ADDR  0x20180004u
#define SMOKE_MARKER        0x52543030u

extern uint32_t _estack;

void Reset_Handler(void);
static void Default_Handler(void);

__attribute__((section(".vectors"), used))
const uint32_t g_vectors[16] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0u, 0u, 0u,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0u,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
};

static void Default_Handler(void)
{
    for (;;) {
    }
}

void Reset_Handler(void)
{
    volatile uint32_t* marker = (volatile uint32_t*)SMOKE_MARKER_ADDR;
    volatile uint32_t* counter = (volatile uint32_t*)SMOKE_COUNTER_ADDR;
    uint32_t n = 0u;

    *marker = SMOKE_MARKER;
    for (;;) {
        *counter = n++;
        __asm volatile("nop");
    }
}
