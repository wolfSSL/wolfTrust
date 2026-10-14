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

/* Single-source bare-metal NS guests for the stm32h563-tpm end-to-end test.
 * The role is fixed at compile time: WT_TPM_ROLE_APP builds guest0, a
 * wolfTPM application whose every TPM 2.0 command rides SERVICE_TPM;
 * WT_TPM_ROLE_FTPM builds guest1, the isolated firmware TPM that serves
 * them with wolfTPM's fwTPM responder. Neither guest calls PSA Crypto; the
 * only Secure crossings are the mediated TPM door and SERVICE_HSM entropy. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

#include "memory_map.h"
#include "wolftrust/crypto_native_client.h"
#include "wolftrust/tpm_psa_transport.h"

#if defined(WT_TPM_ROLE_APP)
#include "tpm_tests.h"
#define GUEST_NAME "tpm-guest0"
#elif defined(WT_TPM_ROLE_FTPM)
#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_command.h>
#define GUEST_NAME "ftpm-guest1"
#else
#error "build with WT_TPM_ROLE_APP or WT_TPM_ROLE_FTPM"
#endif

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

__attribute__((section(".vectors")))
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

#if defined(WT_TPM_ROLE_APP)
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
#endif /* WT_TPM_ROLE_APP */

#if defined(WT_TPM_ROLE_FTPM)
/* ---- guest1: the isolated firmware TPM. wolfTPM's fwTPM responder serves
 * whole command frames fetched from SERVICE_TPM; the application never
 * touches this guest's memory, only the mediated slot. Volatile profile: no
 * in-memory NV, so state lives for the power cycle. ---- */

static FWTPM_CTX g_ftpm;
static byte g_cmd[WT_TPM_FRAME_MAX];
/* FWTPM_ProcessCommand ignores the capacity passed in and writes up to
 * FWTPM_MAX_COMMAND_SIZE, so the response buffer must cover that bound or an
 * oversized response overruns it (CWE-787). The mediated transport still
 * bounds what leaves the guest to WT_TPM_FRAME_MAX in run_ftpm below. */
static byte g_rsp[FWTPM_MAX_COMMAND_SIZE];
typedef char wt_ftpm_rsp_cap_ok[(sizeof(g_rsp) >= FWTPM_MAX_COMMAND_SIZE)
                                ? 1 : -1];
typedef char wt_ftpm_relay_cap_match[
    (FWTPM_MAX_COMMAND_SIZE == WT_TPM_FRAME_MAX) ? 1 : -1];

static int ftpm_heap_scrub_test(void)
{
    volatile uint8_t *first;
    volatile uint8_t *reused;
    uintptr_t first_addr;
    size_t i;
    int scrubbed = 1;

    first = (volatile uint8_t *)malloc(64U);
    if (first == NULL) {
        return -1;
    }
    for (i = 0U; i < 64U; i++) {
        first[i] = 0xA5U;
    }
    first_addr = (uintptr_t)first;
    free((void *)first);
    first = NULL;
    reused = (volatile uint8_t *)malloc(64U);
    if (reused == NULL || (uintptr_t)reused != first_addr) {
        scrubbed = 0;
    }
    if (reused != NULL) {
        for (i = 0U; i < 64U; i++) {
            if (reused[i] != 0U) {
                scrubbed = 0;
            }
        }
        free((void *)reused);
    }
    return scrubbed != 0 ? 0 : -1;
}

#if defined(WT_TPM_TRACE_COMMANDS) && (WT_TPM_TRACE_COMMANDS == 1)
static uint32_t tpm_command_code(const byte *command, size_t length)
{
    if (length < TPM2_HEADER_SIZE) {
        return 0u;
    }
    return ((uint32_t)command[6] << 24) |
           ((uint32_t)command[7] << 16) |
           ((uint32_t)command[8] << 8) |
           (uint32_t)command[9];
}

static void trace_tpm_command(const byte *command, size_t length)
{
    const char *name = NULL;

    switch (tpm_command_code(command, length)) {
        case TPM_CC_Startup:
            name = "command Startup";
            break;
        case TPM_CC_Shutdown:
            name = "command Shutdown";
            break;
        case TPM_CC_GetCapability:
            name = "command GetCapability";
            break;
        case TPM_CC_Hash:
            name = "command Hash";
            break;
        case TPM_CC_GetRandom:
            name = "command GetRandom";
            break;
        case TPM_CC_CreatePrimary:
            name = "command CreatePrimary";
            break;
        case TPM_CC_Create:
            name = "command Create";
            break;
        case TPM_CC_Load:
            name = "command Load";
            break;
        case TPM_CC_Sign:
            name = "command Sign";
            break;
        case TPM_CC_VerifySignature:
            name = "command VerifySignature";
            break;
        case TPM_CC_PCR_Extend:
            name = "command PCR_Extend";
            break;
        case TPM_CC_PCR_Read:
            name = "command PCR_Read";
            break;
        case TPM_CC_FlushContext:
            name = "command FlushContext";
            break;
        case TPM_CC_ECDH_ZGen:
            name = "command ECDH_ZGen";
            break;
        default:
            break;
    }
    if (name != NULL) {
        guest_line(name);
    }
}
#endif

static int run_ftpm(void)
{
    size_t cmd_len = 0U;
    int rsp_len;
    int rc;

    guest_line("alive");
    if (ftpm_heap_scrub_test() != 0) {
        guest_line("heap scrub FAILED");
        return -1;
    }
    guest_line("heap scrub ok");
    rc = FWTPM_Init(&g_ftpm);
    if (rc != 0) { guest_line_i32("ftpm init FAILED rc=", rc); return -1; }
    guest_line("ready");

    for (;;) {
        rc = wt_tpm_psa_fetch(g_cmd, sizeof(g_cmd), &cmd_len);
        if (rc == WT_TPM_E_EMPTY) {
            wt_spin(256u);
            continue;
        }
        if (rc != 0) {
            guest_line_i32("ftpm fetch FAILED rc=", rc);
            wt_spin(200000u);
            continue;
        }
#if defined(WT_TPM_TRACE_COMMANDS) && (WT_TPM_TRACE_COMMANDS == 1)
        trace_tpm_command(g_cmd, cmd_len);
#endif
        rsp_len = (int)sizeof(g_rsp);
        rc = FWTPM_ProcessCommand(&g_ftpm, g_cmd, (int)cmd_len, g_rsp,
                                  &rsp_len, 0);
        if (rc != 0 || rsp_len <= 0 || (size_t)rsp_len > WT_TPM_FRAME_MAX) {
            /* A fetched command must always be answered or the slot stays in
             * service and the application polls forever: reply TPM_RC_FAILURE. */
            guest_line_i32("ftpm command FAILED rc=", rc);
            memset(g_rsp, 0, 10);
            g_rsp[0] = 0x80; g_rsp[1] = 0x01;      /* TPM_ST_NO_SESSIONS */
            g_rsp[5] = 0x0A;                       /* size 10 */
            g_rsp[8] = 0x01; g_rsp[9] = 0x01;      /* TPM_RC_FAILURE */
            rsp_len = 10;
        }
        rc = wt_tpm_psa_respond(g_rsp, (size_t)rsp_len);
        if (rc != 0) {
            guest_line_i32("ftpm respond FAILED rc=", rc);
        }
    }
}
#endif /* WT_TPM_ROLE_FTPM */

void Reset_Handler(void)
{
    wt_copy_data();
    wt_zero_bss();
    wt_uart_init();
#if defined(WT_TPM_ROLE_APP)
    (void)run_app();
#else
    (void)run_ftpm();
#endif
    for (;;) { __asm volatile("wfi"); }
}
