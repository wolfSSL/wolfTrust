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

/* Portable bare-metal application for the TPM 2.0 (WT_INTERFACE_TPM) or
 * PKCS#11 (WT_INTERFACE_PKCS11) interface: the OS-neutral suite runs on any
 * port with a linker window and a console. */

#include <stdint.h>
#include <stddef.h>

#include "board.h"

#if defined(WT_INTERFACE_TPM)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "tpm_tests.h"
#elif defined(WT_INTERFACE_PKCS11)
#include "pkcs11_tests.h"
#else
#error "build with WT_INTERFACE_TPM or WT_INTERFACE_PKCS11"
#endif

#define GUEST_SPIN_COUNT 200000u

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

static void guest_puts(const char* s)
{
    while (*s != '\0') {
        guest_board_uart_putc(*s);
        s++;
    }
}

static void guest_put_u32(uint32_t v)
{
    char buf[10];
    uint32_t i = 0u;

    if (v == 0u) {
        guest_board_uart_putc('0');
        return;
    }
    while (v != 0u) {
        buf[i] = (char)('0' + (v % 10u));
        i++;
        v /= 10u;
    }
    while (i != 0u) {
        i--;
        guest_board_uart_putc(buf[i]);
    }
}

static void guest_spin(void)
{
    volatile uint32_t i;

    for (i = 0u; i < GUEST_SPIN_COUNT; i++) {
    }
}

#if defined(WT_INTERFACE_TPM)
/* wolfCrypt seeds from the Secure vault RNG over the engine's mediated wire. */
int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    (void)os;
    return wolftrust_guest_rng_stub((unsigned char*)output, (unsigned int)sz);
}

void wt_tpm_puts(const char* text)
{
    guest_puts(text);
}

void wt_tpm_print_i32(int value)
{
    if (value < 0) {
        guest_board_uart_putc('-');
        guest_put_u32((uint32_t)(-(value + 1)) + 1u);
    }
    else {
        guest_put_u32((uint32_t)value);
    }
}

void wt_tpm_wait(void)
{
    guest_spin();
}

static int guest_run(void)
{
    return wt_tpm_run();
}
#else
void wt_pkcs11_puts(const char* text)
{
    guest_puts(text);
}

void wt_pkcs11_print_u32(unsigned int value)
{
    guest_put_u32((uint32_t)value);
}

void wt_pkcs11_wait(void)
{
    guest_spin();
}

static int guest_run(void)
{
    int rc;

    rc = wt_pkcs11_run();
    guest_puts(WT_PKCS11_APP_NAME ": suite ");
    guest_puts(wt_pkcs11_suite_name());
    guest_puts((rc == 0) ? " complete\r\n" : " failed\r\n");
    return rc;
}
#endif

void Reset_Handler(void)
{
    uint32_t* src;
    uint32_t* dst;
    int rc;

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

    guest_board_uart_init();
    guest_puts(GUEST_APP_NAME ": alive\r\n");
    rc = guest_run();
#if defined(WT_M33MU_EXPECT_BKPT)
    if (rc == 0) {
        __asm volatile("bkpt #0x7f");
    }
    else {
        __asm volatile("bkpt #0x7e");
    }
#else
    (void)rc;
#endif
    for (;;) {
        __asm volatile("wfi");
    }
}
