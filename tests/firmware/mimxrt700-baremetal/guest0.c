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
#define GUEST0_SERVICE_ITS_SID   4099u
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

#if defined(WT_PERIPH_NEG_PROBE)
static void guest0_uart_puts(const char* s);

/* A privileged guest switches off its own MPU and reads the SPM's TRNG through
 * the Non-secure alias. The SAU must fault the read; returning at all leaks. */
static void guest0_periph_probe(volatile wt_guest0_mailbox_t* mb)
{
    *(volatile uint32_t*)0xE000ED94u = 0u;
    __asm volatile("dsb\n isb" ::: "memory");
    mb->probe = 1u;
    __asm volatile("dsb" ::: "memory");
    mb->probe_read = *(volatile const uint32_t*)GUEST_PERIPH_ADDR;
    mb->probe = 3u;
    guest0_uart_puts("wolfTrust RT700 " GUEST_NAME ": periph probe LEAKED\r\n");
}
#endif

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
#if defined(WT_HANDLER_OVERRUN_PROBE)
static void Overrun_Handler(void);
#endif
#if defined(WT_NS_ENTRY_MASK_PROBE)
static void EntryMask_Tick_Handler(void);
#endif

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
#if defined(WT_HANDLER_OVERRUN_PROBE)
    (uint32_t)Overrun_Handler,
#else
    (uint32_t)Default_Handler,
#endif
#if defined(WT_NS_ENTRY_MASK_PROBE)
    (uint32_t)EntryMask_Tick_Handler,
#else
    (uint32_t)Default_Handler,
#endif
};

static void Default_Handler(void)
{
    for (;;) {
    }
}

#if defined(WT_HANDLER_OVERRUN_PROBE)
/* Re-pends itself and never returns, so a leaked pend would reach guest1. */
static void Overrun_Handler(void)
{
    *(volatile uint32_t*)0xE000ED04u = (1u << 28);
    for (;;) {
    }
}
#endif

#if defined(WT_NS_ENTRY_MASK_PROBE)
#define GUEST0_SYST_CSR (*(volatile uint32_t*)0xE000E010u)
#define GUEST0_SYST_RVR (*(volatile uint32_t*)0xE000E014u)
#define GUEST0_SYST_CVR (*(volatile uint32_t*)0xE000E018u)
#define GUEST0_ENTRY_MASK_ROUNDS 8u
#define GUEST0_ENTRY_MASK_RELOAD 200u
#define GUEST0_ENTRY_MASK_OK     0x4D41534Bu

static volatile uint32_t g_entry_mask_ticks;
static volatile uint32_t g_entry_mask_from_secure;
static volatile uint32_t g_entry_mask_nested_ok;

/* Comes due during an FF-M entry and makes its own entry. EXC_RETURN.S set
 * means it preempted Secure code: held to the entry's exit, never inside. */
static void EntryMask_Tick_Handler(void)
{
    uint32_t exc_return = (uint32_t)(uintptr_t)__builtin_return_address(0);
    psa_handle_t h;

    GUEST0_SYST_CSR = 0u;
    if ((exc_return & 0x40u) != 0u) {
        g_entry_mask_from_secure++;
    }
    h = psa_connect(GUEST0_SERVICE_HSM_SID, GUEST0_SERVICE_VERSION);
    if (PSA_HANDLE_IS_VALID(h)) {
        psa_close(h);
        g_entry_mask_nested_ok++;
    }
    g_entry_mask_ticks++;
}
#endif

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

#if defined(WT_NS_ENTRY_MASK_PROBE)
/* Each round arms a short Non-secure SysTick, then enters FF-M: the tick
 * comes due mid-entry, and every round must see it taken at the entry's exit. */
static void guest0_entry_mask_probe(volatile wt_guest0_mailbox_t* mb)
{
    psa_handle_t h;
    uint32_t round;
    uint32_t spin;
    uint32_t outer_ok = 0u;

    *(volatile uint32_t*)0xE000ED20u |= (0xFFu << 24);
    for (round = 0u; round < GUEST0_ENTRY_MASK_ROUNDS; round++) {
        *(volatile uint32_t*)0xE000ED04u = (1u << 25);
        GUEST0_SYST_RVR = GUEST0_ENTRY_MASK_RELOAD;
        GUEST0_SYST_CVR = 0u;
        GUEST0_SYST_CSR = 7u;
        h = psa_connect(GUEST0_SERVICE_HSM_SID, GUEST0_SERVICE_VERSION);
        if (PSA_HANDLE_IS_VALID(h)) {
            psa_close(h);
            outer_ok++;
        }
        for (spin = 0u; spin < 1000000u && g_entry_mask_ticks <= round;
                spin++) {
        }
    }
    GUEST0_SYST_CSR = 0u;
    if (outer_ok == GUEST0_ENTRY_MASK_ROUNDS &&
            g_entry_mask_ticks == GUEST0_ENTRY_MASK_ROUNDS &&
            g_entry_mask_from_secure == GUEST0_ENTRY_MASK_ROUNDS &&
            g_entry_mask_nested_ok == GUEST0_ENTRY_MASK_ROUNDS) {
        mb->probe = GUEST0_ENTRY_MASK_OK;
        guest0_uart_puts("wolfTrust RT700 " GUEST_NAME
                         ": NS entry mask ok\r\n");
    }
    else {
        mb->probe = 0xBAD00000u | ((outer_ok & 0xFu) << 12) |
                    ((g_entry_mask_ticks & 0xFu) << 8) |
                    ((g_entry_mask_from_secure & 0xFu) << 4) |
                    (g_entry_mask_nested_ok & 0xFu);
        guest0_uart_puts("wolfTrust RT700 " GUEST_NAME
                         ": NS entry mask FAIL\r\n");
    }
}
#endif

void Reset_Handler(void)
{
    volatile wt_guest0_mailbox_t* mb = &g_guest0_mailbox;
    uint32_t* src;
    uint32_t* dst;
    uint32_t fw;
    uint32_t tries;
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

#if defined(WT_GUEST_FAULT_PROBE)
    /* A Non-secure read of Secure RAM faults on every launch. */
    mb->probe_read = *(volatile const uint32_t*)GUEST_FAULT_ADDR;
#endif
#if defined(WT_HANDLER_OVERRUN_PROBE)
    /* Pend PendSV_NS at the lowest priority, as an RTOS does; its handler
     * never returns, on every launch. */
    *(volatile uint32_t*)0xE000ED20u |= (0xFFu << 16);
    *(volatile uint32_t*)0xE000ED04u = (1u << 28);
    __asm volatile("dsb\n isb" ::: "memory");
#endif

#if defined(WT_NS_ENTRY_MASK_PROBE)
    guest0_entry_mask_probe(mb);
#endif

    fw = psa_framework_version();
    mb->framework = fw;
    mb->step = 2u;
    if (fw != PSA_FRAMEWORK_VERSION) {
        ok = 0;
    }

    mb->hsm_version = psa_version(GUEST0_SERVICE_HSM_SID);
    mb->step = 3u;

    /* A failed connect to the mandatory service is retried: each attempt
     * re-enters the relay, so a faulting relay spends its restart budget
     * (spbudgetneg) instead of surviving on one entry per guest. */
    handle = PSA_NULL_HANDLE;
    for (tries = 0u; tries < 4u; tries++) {
        handle = psa_connect(GUEST0_SERVICE_HSM_SID, GUEST0_SERVICE_VERSION);
        if (PSA_HANDLE_IS_VALID(handle)) {
            break;
        }
    }
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

    /* Touch a second service so the storage SP wakes: the crossdomain and
     * keystoreneg probes fault on its entry, so this connect failing is their
     * verdict, never this guest's. */
    handle = psa_connect(GUEST0_SERVICE_ITS_SID, GUEST0_SERVICE_VERSION);
    if (PSA_HANDLE_IS_VALID(handle)) {
        psa_close(handle);
        guest0_uart_puts("wolfTrust RT700 " GUEST_NAME
                         ": storage connect ok\r\n");
    }

#if defined(WT_AHBSC_PROBE)
    guest0_fabric_probe(mb);
#endif
#if defined(WT_PERIPH_NEG_PROBE)
    guest0_periph_probe(mb);
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
