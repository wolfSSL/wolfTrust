/* guest0.c
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

/* Bare-metal Non-secure bring-up guest for the MIMXRT700 compute Cortex-M33.
 * wolfBoot authenticates the wolfTrust Secure image, which launches this guest
 * in the Non-secure state; the guest drives the WolfTrust_FFM_* veneers to
 * prove the Secure runtime booted and services a Non-secure PSA client.
 * Progress lands in an SWD-readable mailbox at the base of guest RAM and, best
 * effort, on LPUART0 (the EVK MCU-Link console the first loader already set up). */

#include <stddef.h>
#include <stdint.h>

#include "psa/client.h"

/* SERVICE_HSM from the platform manifest (port/mimxrt700/manifest.json). */
#define GUEST0_SERVICE_HSM_SID   4102u
#define GUEST0_SERVICE_VERSION   1u

/* One source builds both guests; the Makefile names each on the console. */
#ifndef GUEST_NAME
#error "GUEST_NAME must name the guest"
#endif

/* SWD-readable status words at the base of the guest RAM window. */
#define GUEST0_SIGNATURE         0x47543030u   /* debugger tag, "guest0 ran" */
#define GUEST0_STATUS_RUNNING    0x00000000u
#define GUEST0_STATUS_DONE       0x600D600Du
#define GUEST0_STATUS_FAIL       0xBAD00000u

/* LPUART0 through its Non-secure alias. The first loader configured the clock,
 * pins, and baud, so the guest only polls TDRE and writes DATA. */
#define GUEST0_LPUART0_BASE      0x40110000u
#define GUEST0_LPUART0_VERID     (*(volatile uint32_t*)(GUEST0_LPUART0_BASE + 0x00u))
#define GUEST0_LPUART0_STAT      (*(volatile uint32_t*)(GUEST0_LPUART0_BASE + 0x14u))
#define GUEST0_LPUART0_DATA      (*(volatile uint32_t*)(GUEST0_LPUART0_BASE + 0x1Cu))
#define GUEST0_LPUART0_STAT_TDRE 0x00800000u
#define GUEST0_UART_TX_POLL_LIMIT 100000u

typedef struct wt_guest0_mailbox {
    uint32_t signature;
    uint32_t step;
    uint32_t framework;
    uint32_t hsm_version;
    int32_t  hsm_handle;
    uint32_t status;
    uint32_t console;
    uint32_t probe;
    uint32_t probe_read;
    uint32_t beat;          /* advances while the guest idles once done */
} wt_guest0_mailbox_t;

__attribute__((section(".shared"), used))
volatile wt_guest0_mailbox_t g_guest0_mailbox;

#if defined(WT_AHBSC_PROBE)
/* Isolation probe: GUEST_PROBE_ADDR is the peer guest's RAM, Secure to the SAU
 * while this guest runs. A privileged guest can switch off the Non-secure MPU
 * wolfTrust programs for it, so attribution alone must stop the store. Latch:
 * 1 attempted (the store faulted), 2 blocked, 3 leaked. */
#define GUEST0_MPU_CTRL          (*(volatile uint32_t*)0xE000ED94u)
#define GUEST0_PROBE_ATTEMPTED   1u
#define GUEST0_PROBE_BLOCKED     2u
#define GUEST0_PROBE_LEAKED      3u

static void guest0_fabric_probe(volatile wt_guest0_mailbox_t* mb)
{
    volatile uint32_t* target = (volatile uint32_t*)GUEST_PROBE_ADDR;
    uint32_t readback;

    GUEST0_MPU_CTRL = 0u;
    __asm volatile("dsb\n isb" ::: "memory");
    /* Latched only once the MPU is off, so 1 means the peer store was issued. */
    mb->probe = GUEST0_PROBE_ATTEMPTED;
    __asm volatile("dsb" ::: "memory");
    *target = GUEST_PROBE_VALUE;
    __asm volatile("dsb" ::: "memory");
    readback = *target;
    mb->probe_read = readback;
    if (readback == GUEST_PROBE_VALUE) {
        mb->probe = GUEST0_PROBE_LEAKED;
    }
    else {
        mb->probe = GUEST0_PROBE_BLOCKED;
    }
}
#endif

extern uint32_t _estack;
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;

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

static void guest0_uart_putc(char c)
{
    uint32_t t = GUEST0_UART_TX_POLL_LIMIT;

    while (((GUEST0_LPUART0_STAT & GUEST0_LPUART0_STAT_TDRE) == 0u) &&
           (t > 0u)) {
        t--;
    }
    if (t != 0u) {
        GUEST0_LPUART0_DATA = (uint32_t)(uint8_t)c;
    }
}

static void guest0_uart_puts(const char* s)
{
    while (*s != '\0') {
        guest0_uart_putc(*s);
        s++;
    }
}

void Reset_Handler(void)
{
    volatile wt_guest0_mailbox_t* mb = &g_guest0_mailbox;
    uint32_t* src;
    uint32_t* dst;
    uint32_t fw;
    psa_handle_t handle;
    int ok = 1;

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; ) {
        *dst = *src;
        dst++;
        src++;
    }
    for (dst = &_sbss; dst < &_ebss; ) {
        *dst = 0u;
        dst++;
    }

    mb->signature = GUEST0_SIGNATURE;
    mb->step = 1u;
    mb->framework = 0u;
    mb->hsm_version = 0u;
    mb->hsm_handle = 0;
    mb->status = GUEST0_STATUS_RUNNING;
    mb->console = GUEST0_LPUART0_VERID;
    mb->probe = 0u;
    mb->probe_read = 0u;
    mb->beat = 0u;

    guest0_uart_puts("wolfTrust RT700 " GUEST_NAME ": start\r\n");

    fw = psa_framework_version();
    mb->framework = fw;
    mb->step = 2u;
    if (fw != PSA_FRAMEWORK_VERSION) {
        ok = 0;
    }

    mb->hsm_version = psa_version(GUEST0_SERVICE_HSM_SID);
    mb->step = 3u;

    handle = psa_connect(GUEST0_SERVICE_HSM_SID, GUEST0_SERVICE_VERSION);
    mb->hsm_handle = (int32_t)handle;
    mb->step = 4u;
    if (PSA_HANDLE_IS_VALID(handle)) {
        psa_close(handle);
        mb->step = 5u;
    }
    else {
        ok = 0;
    }

    if (ok != 0) {
        mb->status = GUEST0_STATUS_DONE;
        guest0_uart_puts("wolfTrust RT700 " GUEST_NAME
                         ": FF-M connect ok, done\r\n");
    }
    else {
        mb->status = GUEST0_STATUS_FAIL;
        guest0_uart_puts("wolfTrust RT700 " GUEST_NAME ": FAIL\r\n");
    }

#if defined(WT_AHBSC_PROBE)
    guest0_fabric_probe(mb);
#endif

    for (;;) {
        mb->beat++;
    }
}

/* The freestanding client core marshals its iovec through memset; -fno-builtin
 * keeps these loops from being turned into calls to themselves. */
void* memset(void* dst, int c, size_t n)
{
    uint8_t* p = (uint8_t*)dst;
    size_t i;

    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)c;
    }
    return dst;
}

void* memcpy(void* dst, const void* src, size_t n)
{
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    size_t i;

    for (i = 0u; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}
