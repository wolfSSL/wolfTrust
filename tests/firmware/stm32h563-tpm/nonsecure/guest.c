/* guest.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Bare-metal wolfTPM client. fwTPM runs inside the Secure service. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

#include "memory_map.h"
#include "wolftrust/crypto_native_client.h"
#if defined(WT_ENGINE_HSM)
int wolfhsm_guest_init(void);
#endif
#include "wolftrust/tpm_psa_transport.h"

#include "tpm_tests.h"
#define GUEST_NAME "tpm-guest0"

#ifndef WT_GUEST_UART_CLOCK_HZ
#define WT_GUEST_UART_CLOCK_HZ 120000000u
#endif

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;

#define USART3_BASE           0x40004800u
#define USART_CR1(b)          (*(volatile uint32_t *)((b) + 0x00u))
#define USART_CR2(b)          (*(volatile uint32_t *)((b) + 0x04u))
#define USART_CR3(b)          (*(volatile uint32_t *)((b) + 0x08u))
#define USART_BRR(b)          (*(volatile uint32_t *)((b) + 0x0Cu))
#define USART_ISR(b)          (*(volatile uint32_t *)((b) + 0x1Cu))
#define USART_TDR(b)          (*(volatile uint32_t *)((b) + 0x28u))
#define USART_CR1_UE          (1u << 0)
#define USART_CR1_RE          (1u << 2)
#define USART_CR1_TE          (1u << 3)
#define USART_ISR_TXE         (1u << 7)

static void default_handler(void) { for (;;) {} }

void Reset_Handler(void);
void NMI_Handler(void) __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void) __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void) __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void) __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));
void SVC_Handler(void) __attribute__((weak, alias("default_handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("default_handler")));
void PendSV_Handler(void) __attribute__((weak, alias("default_handler")));
void SysTick_Handler(void) __attribute__((weak, alias("default_handler")));

__attribute__((used, section(".vectors")))
const uint32_t g_vectors[16] = {
    [0]  = (uint32_t)&_estack,
    [1]  = (uint32_t)&Reset_Handler,
    [2]  = (uint32_t)&NMI_Handler,
    [3]  = (uint32_t)&HardFault_Handler,
    [4]  = (uint32_t)&MemManage_Handler,
    [5]  = (uint32_t)&BusFault_Handler,
    [6]  = (uint32_t)&UsageFault_Handler,
    [11] = (uint32_t)&SVC_Handler,
    [12] = (uint32_t)&DebugMon_Handler,
    [14] = (uint32_t)&PendSV_Handler,
    [15] = (uint32_t)&SysTick_Handler
};

/* Both guests share USART3 (WT_SHARED_UART=3); lines carry the guest tag. */
static void wt_uart_init(void)
{
    USART_CR1(USART3_BASE) = 0u;
    USART_CR2(USART3_BASE) = 0u;
    USART_CR3(USART3_BASE) = 0u;
    USART_BRR(USART3_BASE) = WT_GUEST_UART_CLOCK_HZ / 115200u;
    USART_CR1(USART3_BASE) = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

static void wt_uart_putc(char c)
{
    while ((USART_ISR(USART3_BASE) & USART_ISR_TXE) == 0u) { }
    USART_TDR(USART3_BASE) = (uint32_t)(uint8_t)c;
}

static void wt_uart_puts(const char *s)
{
    while (*s) wt_uart_putc(*s++);
}

static void wt_uart_put_i32(int32_t v)
{
    char buf[12];
    uint32_t u;
    uint32_t i = 0;

    if (v < 0) {
        wt_uart_putc('-');
        u = (uint32_t)(-(v + 1)) + 1u;
    }
    else {
        u = (uint32_t)v;
    }
    if (u == 0u) { wt_uart_putc('0'); return; }
    while (u != 0u) { buf[i++] = (char)('0' + (u % 10u)); u /= 10u; }
    while (i != 0u) wt_uart_putc(buf[--i]);
}

static void guest_line(const char *s)
{
    wt_uart_puts(GUEST_NAME ": ");
    wt_uart_puts(s);
    wt_uart_puts("\r\n");
}

static void guest_line_i32(const char *s, int32_t v)
{
    wt_uart_puts(GUEST_NAME ": ");
    wt_uart_puts(s);
    wt_uart_put_i32(v);
    wt_uart_puts("\r\n");
}

static void wt_copy_data(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
}

static void wt_zero_bss(void)
{
    uint32_t *dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0u;
}

static void wt_spin(uint32_t n)
{
    volatile uint32_t i;
    for (i = 0u; i < n; i++) { }
}

/* ---- entropy: wolfCrypt seeds from the Secure vault RNG over the mediated
 * native wire (the native client supplies wolftrust_guest_rng_stub), the
 * same source every other guest uses. ---- */

int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    (void)os;
    return wolftrust_guest_rng_stub((unsigned char*)output, (unsigned int)sz);
}

/* ---- guest0: platform hooks for the shared wolfTPM application suite.
 * Every wolfTPM2_* call becomes a TPM 2.0 command carried by SERVICE_TPM. */

void wt_tpm_puts(const char *text)
{
    wt_uart_puts(text);
}

void wt_tpm_print_i32(int value)
{
    wt_uart_put_i32((int32_t)value);
}

void wt_tpm_wait(void)
{
    wt_spin(200000u);
}

static int run_app(void)
{
    int rc;

    guest_line("alive");
    rc = wt_tpm_run();
#if defined(WT_TPM_EXIT_BKPT) && (WT_TPM_EXIT_BKPT == 1)
    if (rc == 0) {
        /* Emulator harness end-marker; never on hardware. */
        __asm volatile("bkpt 0x7f");
    }
#endif
    return rc;
}

void Reset_Handler(void)
{
    wt_copy_data();
    wt_zero_bss();
    wt_uart_init();
    (void)run_app();
    for (;;) { __asm volatile("wfi"); }
}
