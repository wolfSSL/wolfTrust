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

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#include "memory_map.h"

#ifdef WT_ENGINE_HSM
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfhsm/wh_client.h"

#define WT_ALIGNED_WORD __attribute__((aligned(4)))

int wolfhsm_guest_init(uint32_t client_id);
int wolfcrypt_benchmark_main(int argc, char** argv);

/* Static buffers to keep large structs off the stack. */
static ecc_key  s_ecc_key;
static WC_RNG   s_rng;
static Aes      s_aes;
static uint8_t  s_sig[80];
static uint8_t  s_digest[WC_SHA256_DIGEST_SIZE];
static uint8_t  s_rand[32] WT_ALIGNED_WORD;
static uint8_t  s_aes_out[32] WT_ALIGNED_WORD;
static uint8_t  s_aes_plain[32] WT_ALIGNED_WORD;
#endif /* WT_ENGINE_HSM */

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;

#define USART2_BASE           0x40004400u
#define USART3_BASE           0x40004800u
#define USART_CR1(base)       (*(volatile uint32_t *)((base) + 0x00u))
#define USART_CR2(base)       (*(volatile uint32_t *)((base) + 0x04u))
#define USART_CR3(base)       (*(volatile uint32_t *)((base) + 0x08u))
#define USART_BRR(base)       (*(volatile uint32_t *)((base) + 0x0Cu))
#define USART_ISR(base)       (*(volatile uint32_t *)((base) + 0x1Cu))
#define USART_TDR(base)       (*(volatile uint32_t *)((base) + 0x28u))

#define USART_CR1_UE          (1u << 0)
#define USART_CR1_RE          (1u << 2)
#define USART_CR1_TE          (1u << 3)
#define USART_ISR_TXE         (1u << 7)

#ifndef WT_GUEST_CORE_CLOCK_HZ
#define WT_GUEST_CORE_CLOCK_HZ 240000000u
#endif

#ifndef WT_GUEST_UART_CLOCK_HZ
#define WT_GUEST_UART_CLOCK_HZ 120000000u
#endif

#define SYST_CSR     (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR     (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR     (*(volatile uint32_t *)0xE000E018u)
#define SYST_CSR_CLKSOURCE   (1u << 2)
#define SYST_CSR_TICKINT     (1u << 1)
#define SYST_CSR_ENABLE      (1u << 0)

typedef struct wt_guest_mailbox {
    volatile uint32_t boot_count;
    volatile uint32_t heartbeat;
    volatile uint32_t signature;
    volatile uint32_t virtual_ms;
    volatile uint32_t lines_printed;
    volatile uint32_t next_print_ms;
    volatile uint32_t run_token;
} wt_guest_mailbox_t;

static wt_guest_mailbox_t g_mailbox __attribute__((section(".shared")));
static volatile uint32_t g_tick_ms;

static void default_handler(void)
{
    for (;;) {
    }
}

void Reset_Handler(void);
void NMI_Handler(void) __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void) __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void) __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void) __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));
void SVC_Handler(void) __attribute__((weak, alias("default_handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("default_handler")));
void PendSV_Handler(void) __attribute__((weak, alias("default_handler")));
void SysTick_Handler(void);

__attribute__((section(".vectors")))
const uint32_t g_vectors[16] = {
    [0] = (uint32_t)&_estack,
    [1] = (uint32_t)&Reset_Handler,
    [2] = (uint32_t)&NMI_Handler,
    [3] = (uint32_t)&HardFault_Handler,
    [4] = (uint32_t)&MemManage_Handler,
    [5] = (uint32_t)&BusFault_Handler,
    [6] = (uint32_t)&UsageFault_Handler,
    [11] = (uint32_t)&SVC_Handler,
    [12] = (uint32_t)&DebugMon_Handler,
    [14] = (uint32_t)&PendSV_Handler,
    [15] = (uint32_t)&SysTick_Handler
};

static uintptr_t wt_uart_base(void)
{
#if WT_SHARED_UART == 1 || WT_SHARED_UART == 2
    return USART2_BASE;
#elif WT_SHARED_UART == 3
    return USART3_BASE;
#else
    return ((uintptr_t)&_estack == (WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE)) ?
           USART3_BASE : USART2_BASE;
#endif
}

static uint32_t wt_guest_id(void)
{
    return ((uintptr_t)&_estack == (WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE)) ?
           1u : 0u;
}

static void wt_copy_data(void)
{
    uint32_t* src = &_sidata;
    uint32_t* dst = &_sdata;

    while (dst < &_edata) {
        *dst++ = *src++;
    }
}

static void wt_zero_bss(void)
{
    uint32_t* dst = &_sbss;

    while (dst < &_ebss) {
        *dst++ = 0u;
    }
}

static void wt_uart_init(void)
{
    uintptr_t base = wt_uart_base();
    uint32_t brr = WT_GUEST_UART_CLOCK_HZ / 115200u;

    USART_CR1(base) = 0u;
    USART_CR2(base) = 0u;
    USART_CR3(base) = 0u;
    USART_BRR(base) = brr;
    USART_CR1(base) = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

static void wt_uart_putc(char c)
{
    uintptr_t base = wt_uart_base();

    while ((USART_ISR(base) & USART_ISR_TXE) == 0u) {
    }

    USART_TDR(base) = (uint32_t)(uint8_t)c;
}

static void wt_uart_put_u32(uint32_t value)
{
    char buf[10];
    uint32_t i = 0u;

    if (value == 0u) {
        wt_uart_putc('0');
        return;
    }

    while (value != 0u) {
        buf[i++] = (char)('0' + (value % 10u));
        value /= 10u;
    }

    while (i > 0u) {
        wt_uart_putc(buf[--i]);
    }
}

static void wt_systick_init(void)
{
    SYST_CSR = 0u;
    SYST_RVR = (WT_GUEST_CORE_CLOCK_HZ / 1000u) - 1u;
    SYST_CVR = 0u;
    SYST_CSR = SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE;
}

void SysTick_Handler(void)
{
    g_tick_ms++;
    g_mailbox.heartbeat++;
}

#ifdef WT_ENGINE_HSM

static void print_str(const char *s)
{
    while (*s != '\0') {
        wt_uart_putc(*s++);
    }
}

static void print_hex_byte(uint8_t b)
{
    static const char hex[] = "0123456789abcdef";
    wt_uart_putc(hex[(b >> 4) & 0xFu]);
    wt_uart_putc(hex[b & 0xFu]);
}

static int mem_equal(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint8_t diff = 0u;
    uint32_t i;

    for (i = 0u; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    return diff == 0u;
}

typedef void (*wt_benchmark_emit_fn)(void *ctx, char c);

typedef struct wt_benchmark_buf {
    char  *buf;
    size_t len;
    size_t pos;
} wt_benchmark_buf_t;

#if !WT_ENGINE_HSM
static void wt_benchmark_emit_uart(void *ctx, char c)
{
    (void)ctx;
    wt_uart_putc(c);
}
#endif

static void wt_benchmark_emit_buf(void *ctx, char c)
{
    wt_benchmark_buf_t *out = (wt_benchmark_buf_t *)ctx;

    if (out->len != 0u && out->pos < (out->len - 1u)) {
        out->buf[out->pos] = c;
    }
    out->pos++;
}

static size_t wt_benchmark_strlen(const char *s)
{
    size_t len = 0u;

    while (s[len] != '\0') {
        len++;
    }

    return len;
}

static void wt_benchmark_emit_repeat(wt_benchmark_emit_fn emit, void *ctx,
                                     char c, int count, int *written)
{
    while (count > 0) {
        emit(ctx, c);
        (*written)++;
        count--;
    }
}

static void wt_benchmark_emit_string(wt_benchmark_emit_fn emit, void *ctx,
                                     const char *s, size_t len, int width,
                                     int left, int *written)
{
    int pad = width - (int)len;
    size_t i;

    if (pad < 0) {
        pad = 0;
    }
    if (!left) {
        wt_benchmark_emit_repeat(emit, ctx, ' ', pad, written);
    }
    for (i = 0u; i < len; i++) {
        emit(ctx, s[i]);
        (*written)++;
    }
    if (left) {
        wt_benchmark_emit_repeat(emit, ctx, ' ', pad, written);
    }
}

static char wt_benchmark_digit(unsigned int value, int upper)
{
    if (value < 10u) {
        return (char)('0' + value);
    }
    return (char)((upper ? 'A' : 'a') + (value - 10u));
}

static void wt_benchmark_emit_uint(wt_benchmark_emit_fn emit, void *ctx,
                                   uint64_t value, unsigned int base,
                                   int upper, int negative, int width,
                                   int precision, int left, int zero,
                                   int prefix_hex, int *written)
{
    char tmp[32];
    int digits = 0;
    int min_digits;
    int sign_len = negative ? 1 : 0;
    int prefix_len = prefix_hex ? 2 : 0;
    int body_len;
    int pad;
    int i;

    if (value == 0u) {
        tmp[digits++] = '0';
    }
    else {
        while (value != 0u && digits < (int)sizeof(tmp)) {
            tmp[digits++] = wt_benchmark_digit((unsigned int)(value % base),
                                               upper);
            value /= base;
        }
    }

    if (precision == 0 && digits == 1 && tmp[0] == '0') {
        digits = 0;
    }
    min_digits = digits;
    if (precision > min_digits) {
        min_digits = precision;
    }
    body_len = sign_len + prefix_len + min_digits;
    pad = width - body_len;
    if (pad < 0) {
        pad = 0;
    }

    if (!left && (!zero || precision >= 0)) {
        wt_benchmark_emit_repeat(emit, ctx, ' ', pad, written);
    }
    if (negative) {
        emit(ctx, '-');
        (*written)++;
    }
    if (prefix_hex) {
        emit(ctx, '0');
        emit(ctx, upper ? 'X' : 'x');
        (*written) += 2;
    }
    if (!left && zero && precision < 0) {
        wt_benchmark_emit_repeat(emit, ctx, '0', pad, written);
    }
    wt_benchmark_emit_repeat(emit, ctx, '0', min_digits - digits, written);
    for (i = digits - 1; i >= 0; i--) {
        emit(ctx, tmp[i]);
        (*written)++;
    }
    if (left) {
        wt_benchmark_emit_repeat(emit, ctx, ' ', pad, written);
    }
}

static uint64_t wt_benchmark_signed_mag(int64_t value, int *negative)
{
    if (value < 0) {
        *negative = 1;
        return (uint64_t)(-(value + 1)) + 1u;
    }

    *negative = 0;
    return (uint64_t)value;
}

static void wt_benchmark_emit_fixed(wt_benchmark_emit_fn emit, void *ctx,
                                    double value, int width, int precision,
                                    int left, int zero, int *written)
{
    uint64_t whole;
    uint64_t frac = 0u;
    uint64_t scale = 1u;
    int negative = 0;
    int i;
    char tmp[64];
    wt_benchmark_buf_t out;
    int scratch_written = 0;

    if (precision < 0) {
        precision = 6;
    }
    if (precision > 9) {
        precision = 9;
    }
    if (value < 0.0) {
        negative = 1;
        value = -value;
    }
    whole = (uint64_t)value;
    for (i = 0; i < precision; i++) {
        scale *= 10u;
    }
    if (precision > 0) {
        frac = (uint64_t)((value - (double)whole) * (double)scale + 0.5);
        if (frac >= scale) {
            whole++;
            frac -= scale;
        }
    }

    out.buf = tmp;
    out.len = sizeof(tmp);
    out.pos = 0u;
    wt_benchmark_emit_uint(wt_benchmark_emit_buf, &out, whole, 10u, 0,
                           negative, 0, -1, 0, 0, 0, &scratch_written);
    if (precision > 0) {
        wt_benchmark_emit_buf(&out, '.');
        for (i = precision - 1; i >= 0; i--) {
            uint64_t div = 1u;
            int j;
            for (j = 0; j < i; j++) {
                div *= 10u;
            }
            wt_benchmark_emit_buf(&out,
                                  (char)('0' + ((frac / div) % 10u)));
        }
    }
    if (out.pos >= sizeof(tmp)) {
        out.pos = sizeof(tmp) - 1u;
    }
    tmp[out.pos] = '\0';

    wt_benchmark_emit_string(emit, ctx, tmp, out.pos, width, left, written);
    (void)zero;
}

static int wt_benchmark_vformat(wt_benchmark_emit_fn emit, void *ctx,
                                const char *fmt, va_list ap)
{
    int written = 0;

    while (*fmt != '\0') {
        int left = 0;
        int zero = 0;
        int width = 0;
        int precision = -1;
        int length = 0;
        char spec;

        if (*fmt != '%') {
            emit(ctx, *fmt++);
            written++;
            continue;
        }
        fmt++;
        if (*fmt == '%') {
            emit(ctx, *fmt++);
            written++;
            continue;
        }

        for (;;) {
            if (*fmt == '-') {
                left = 1;
                fmt++;
            }
            else if (*fmt == '0') {
                zero = 1;
                fmt++;
            }
            else if (*fmt == '+' || *fmt == ' ' || *fmt == '#') {
                fmt++;
            }
            else {
                break;
            }
        }

        if (*fmt == '*') {
            width = va_arg(ap, int);
            if (width < 0) {
                left = 1;
                width = -width;
            }
            fmt++;
        }
        else {
            while (*fmt >= '0' && *fmt <= '9') {
                width = (width * 10) + (*fmt - '0');
                fmt++;
            }
        }

        if (*fmt == '.') {
            fmt++;
            precision = 0;
            if (*fmt == '*') {
                precision = va_arg(ap, int);
                fmt++;
            }
            else {
                while (*fmt >= '0' && *fmt <= '9') {
                    precision = (precision * 10) + (*fmt - '0');
                    fmt++;
                }
            }
            if (precision < 0) {
                precision = -1;
            }
        }

        if (*fmt == 'l') {
            length = 1;
            fmt++;
            if (*fmt == 'l') {
                length = 2;
                fmt++;
            }
        }
        else if (*fmt == 'z') {
            length = 1;
            fmt++;
        }
        else if (*fmt == 'h') {
            fmt++;
            if (*fmt == 'h') {
                fmt++;
            }
        }

        spec = *fmt;
        if (spec == '\0') {
            break;
        }
        fmt++;

        switch (spec) {
        case 'c': {
            char c = (char)va_arg(ap, int);
            wt_benchmark_emit_string(emit, ctx, &c, 1u, width, left,
                                     &written);
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            size_t len;
            if (s == NULL) {
                s = "(null)";
            }
            len = wt_benchmark_strlen(s);
            if (precision >= 0 && (size_t)precision < len) {
                len = (size_t)precision;
            }
            wt_benchmark_emit_string(emit, ctx, s, len, width, left,
                                     &written);
            break;
        }
        case 'd':
        case 'i': {
            int64_t value;
            int negative;
            if (length == 2) {
                value = va_arg(ap, long long);
            }
            else if (length == 1) {
                value = va_arg(ap, long);
            }
            else {
                value = va_arg(ap, int);
            }
            wt_benchmark_emit_uint(emit, ctx,
                                   wt_benchmark_signed_mag(value, &negative),
                                   10u, 0, negative, width, precision, left,
                                   zero, 0, &written);
            break;
        }
        case 'u':
        case 'x':
        case 'X': {
            uint64_t value;
            if (length == 2) {
                value = va_arg(ap, unsigned long long);
            }
            else if (length == 1) {
                value = va_arg(ap, unsigned long);
            }
            else {
                value = va_arg(ap, unsigned int);
            }
            wt_benchmark_emit_uint(emit, ctx, value,
                                   (spec == 'u') ? 10u : 16u,
                                   spec == 'X', 0, width, precision, left,
                                   zero, 0, &written);
            break;
        }
        case 'p': {
            uintptr_t value = (uintptr_t)va_arg(ap, void *);
            wt_benchmark_emit_uint(emit, ctx, value, 16u, 0, 0, width,
                                   precision, left, zero, 1, &written);
            break;
        }
        case 'f':
            wt_benchmark_emit_fixed(emit, ctx, va_arg(ap, double), width,
                                    precision, left, zero, &written);
            break;
        default:
            emit(ctx, spec);
            written++;
            break;
        }
    }

    return written;
}

#if !WT_ENGINE_HSM
static int wt_benchmark_vprintf(const char *fmt, va_list ap)
{
    return wt_benchmark_vformat(wt_benchmark_emit_uart, NULL, fmt, ap);
}
#endif

#if WT_ENGINE_HSM
static uint32_t g_benchmark_failed;

static int wt_str_contains(const char *s, const char *needle)
{
    const char *n;
    const char *p;

    if (s == NULL || needle == NULL || *needle == '\0') {
        return 0;
    }

    while (*s != '\0') {
        n = needle;
        p = s;
        while (*n != '\0' && *p == *n) {
            p++;
            n++;
        }
        if (*n == '\0') {
            return 1;
        }
        s++;
    }

    return 0;
}

static void wt_benchmark_note_output(const char *s)
{
    if (wt_str_contains(s, " failed:")) {
        g_benchmark_failed = 1u;
    }
}
#endif

int wt_benchmark_printf(const char *fmt, ...)
{
    va_list ap;
    int ret;
#if WT_ENGINE_HSM
    char buf[192];
    wt_benchmark_buf_t out;

    out.buf = buf;
    out.len = sizeof(buf);
    out.pos = 0u;

    va_start(ap, fmt);
    ret = wt_benchmark_vformat(wt_benchmark_emit_buf, &out, fmt, ap);
    va_end(ap);

    if (out.pos < sizeof(buf)) {
        buf[out.pos] = '\0';
    }
    else {
        buf[sizeof(buf) - 1u] = '\0';
    }
    wt_benchmark_note_output(buf);
    print_str(buf);

    return ret;
#else

    va_start(ap, fmt);
    ret = wt_benchmark_vprintf(fmt, ap);
    va_end(ap);

    return ret;
#endif
}

int wt_benchmark_snprintf(char *buf, size_t len, const char *fmt, ...)
{
    va_list ap;
    wt_benchmark_buf_t out;
    int ret;

    out.buf = buf;
    out.len = len;
    out.pos = 0u;

    va_start(ap, fmt);
    ret = wt_benchmark_vformat(wt_benchmark_emit_buf, &out, fmt, ap);
    va_end(ap);

    if (len != 0u) {
        if (out.pos < len) {
            buf[out.pos] = '\0';
        }
        else {
            buf[len - 1u] = '\0';
        }
    }

    return ret;
}

int wt_benchmark_atoi(const char *s)
{
    int value = 0;

    while (*s >= '0' && *s <= '9') {
        value = (value * 10) + (*s - '0');
        s++;
    }

    return value;
}

double current_time(int reset)
{
    static uint32_t base_ms;
    uint32_t now_ms = g_tick_ms;

    if (reset != 0) {
        base_ms = now_ms;
        return 0.0;
    }

    return (double)(now_ms - base_ms) / 1000.0;
}

/* Fixed 32-byte input for SHA-256: bytes 0x00..0x1F */
static const uint8_t s_hash_input[32] WT_ALIGNED_WORD = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const uint8_t s_aes_key[16] WT_ALIGNED_WORD = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t s_aes_iv[16] WT_ALIGNED_WORD = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const uint8_t s_aes_input[32] WT_ALIGNED_WORD = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};

static const uint8_t s_aes_expected[32] WT_ALIGNED_WORD = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
};

static int run_aes_cbc_bench(void)
{
    int rc;

    rc = wc_AesInit(&s_aes, NULL, WH_DEV_ID);
    if (rc != 0) {
        return rc;
    }

    rc = wc_AesSetKey(&s_aes, s_aes_key, sizeof(s_aes_key), s_aes_iv,
                      AES_ENCRYPTION);
    if (rc == 0) {
        rc = wc_AesCbcEncrypt(&s_aes, s_aes_out, s_aes_input,
                              sizeof(s_aes_input));
    }
    wc_AesFree(&s_aes);
    if (rc != 0) {
        return rc;
    }
    if (!mem_equal(s_aes_out, s_aes_expected, sizeof(s_aes_expected))) {
        return -1;
    }

    rc = wc_AesInit(&s_aes, NULL, WH_DEV_ID);
    if (rc != 0) {
        return rc;
    }

    rc = wc_AesSetKey(&s_aes, s_aes_key, sizeof(s_aes_key), s_aes_iv,
                      AES_DECRYPTION);
    if (rc == 0) {
        rc = wc_AesCbcDecrypt(&s_aes, s_aes_plain, s_aes_out,
                              sizeof(s_aes_out));
    }
    wc_AesFree(&s_aes);
    if (rc != 0) {
        return rc;
    }
    if (!mem_equal(s_aes_plain, s_aes_input, sizeof(s_aes_input))) {
        return -2;
    }

    return 0;
}

static int run_wolfcrypt_benchmark(void)
{
    int rc;
    char *argv[] = {
        (char *)"wolfcrypt-benchmark",
        (char *)"-blocks",
        (char *)"1",
        (char *)"16"
    };

    g_benchmark_failed = 0u;
    rc = wolfcrypt_benchmark_main((int)(sizeof(argv) / sizeof(argv[0])),
                                  argv);
    if (rc != 0) {
        return rc;
    }

    return (g_benchmark_failed != 0u) ? -1 : 0;
}

static void run_hsm_selftest(void)
{
    int      rc;
    word32   sig_len;
    int      verify_ok = 0;
    uint32_t bench_i;

    /* --- Step 1: Init wolfHSM client --- */
    rc = wolfhsm_guest_init(wt_guest_id() + 1u);
    if (rc != 0) {
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":hsm-init ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return; /* fall through to heartbeat loop */
    }

    /* --- Step 2: Init RNG via HSM --- */
    rc = wc_InitRng_ex(&s_rng, NULL, WH_DEV_ID);
    if (rc != 0) {
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":HSM FAIL ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return;
    }

    /* --- Step 3: Init ECC key via HSM --- */
    rc = wc_ecc_init_ex(&s_ecc_key, NULL, WH_DEV_ID);
    if (rc != 0) {
        wc_FreeRng(&s_rng);
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":HSM FAIL ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return;
    }

    /* --- Step 4: Generate P-256 key via HSM --- */
    rc = wc_ecc_make_key_ex(&s_rng, 32, &s_ecc_key, ECC_SECP256R1);
    if (rc != 0) {
        wc_ecc_free(&s_ecc_key);
        wc_FreeRng(&s_rng);
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":HSM FAIL ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return;
    }

    /* --- Step 5: Broad wolfCrypt/HSM workload, run by both guests. --- */
    for (bench_i = 0u; bench_i < 3u; bench_i++) {
        rc = wc_RNG_GenerateBlock(&s_rng, s_rand, sizeof(s_rand));
        if (rc != 0) {
            wc_ecc_free(&s_ecc_key);
            wc_FreeRng(&s_rng);
            wt_uart_putc('g');
            wt_uart_put_u32(wt_guest_id());
            print_str(":HSM FAIL ");
            wt_uart_put_u32((uint32_t)rc);
            wt_uart_putc('\n');
            return;
        }

        rc = run_aes_cbc_bench();
        if (rc != 0) {
            wc_ecc_free(&s_ecc_key);
            wc_FreeRng(&s_rng);
            wt_uart_putc('g');
            wt_uart_put_u32(wt_guest_id());
            print_str(":AES FAIL ");
            wt_uart_put_u32((uint32_t)rc);
            wt_uart_putc('\n');
            return;
        }
    }

    /* --- Step 6: SHA-256 locally while HSM SHA uses STM32 HASH internally. --- */
    rc = wc_Sha256Hash(s_hash_input, sizeof(s_hash_input), s_digest);
    if (rc != 0) {
        wc_ecc_free(&s_ecc_key);
        wc_FreeRng(&s_rng);
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":HSM FAIL ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return;
    }

    /* --- Step 7: Run wolfCrypt's normal benchmark flow through the HSM devID. --- */
    wt_uart_putc('g');
    wt_uart_put_u32(wt_guest_id());
    print_str(":wolfCrypt benchmark start\n");
    rc = run_wolfcrypt_benchmark();
    if (rc != 0) {
        wc_ecc_free(&s_ecc_key);
        wc_FreeRng(&s_rng);
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":BENCH FAIL ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return;
    }
    wt_uart_putc('g');
    wt_uart_put_u32(wt_guest_id());
    print_str(":wolfCrypt benchmark done\n");

    /* --- Step 8: Sign the digest via HSM --- */
    sig_len = (word32)sizeof(s_sig);
    rc = wc_ecc_sign_hash(s_digest, WC_SHA256_DIGEST_SIZE,
                          s_sig, &sig_len, &s_rng, &s_ecc_key);
    if (rc != 0) {
        wc_ecc_free(&s_ecc_key);
        wc_FreeRng(&s_rng);
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":HSM FAIL ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return;
    }

    /* --- Step 9: Verify the signature via HSM --- */
    rc = wc_ecc_verify_hash(s_sig, sig_len,
                            s_digest, WC_SHA256_DIGEST_SIZE,
                            &verify_ok, &s_ecc_key);

    wc_ecc_free(&s_ecc_key);
    wc_FreeRng(&s_rng);

    if (rc != 0 || verify_ok != 1) {
        wt_uart_putc('g');
        wt_uart_put_u32(wt_guest_id());
        print_str(":HSM FAIL ");
        wt_uart_put_u32((uint32_t)rc);
        wt_uart_putc('\n');
        return;
    }

    /* --- Step 10: Success --- */
    wt_uart_putc('g');
    wt_uart_put_u32(wt_guest_id());
    print_str(":sig[0]=");
    print_hex_byte(s_sig[0]);
    wt_uart_putc('\n');

    wt_uart_putc('g');
    wt_uart_put_u32(wt_guest_id());
    print_str(":bench wolfCrypt RNG/AES-CBC/ECC OK\n");

    wt_uart_putc('g');
    wt_uart_put_u32(wt_guest_id());
    print_str(":HSM OK\n");

    g_mailbox.signature = 0x47534D4Fu | (wt_guest_id() << 24);
}

#endif /* WT_ENGINE_HSM */

__attribute__((section(".reset")))
void Reset_Handler(void)
{
    if (g_mailbox.boot_count == 0u) {
        wt_copy_data();
        wt_zero_bss();
        wt_uart_init();

        g_mailbox.boot_count = 1u;
        g_mailbox.signature = 0x47554530u + wt_guest_id();
        g_mailbox.heartbeat = 0u;
        g_mailbox.virtual_ms = 0u;
        g_mailbox.lines_printed = 0u;

#ifdef WT_ENGINE_HSM
        run_hsm_selftest();
#else
        wt_systick_init();
#endif
    }

    for (;;) {
#ifdef WT_ENGINE_HSM
        __asm volatile("nop");
#else
        __asm volatile("wfi");
#endif
    }
}
