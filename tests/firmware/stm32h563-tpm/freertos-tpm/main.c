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

#include <stddef.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "task.h"

#include "wolfssl/wolfcrypt/random.h"
#include "wolftrust/crypto_native_client.h"

#include "tpm_tests.h"

typedef union wt_heap_header {
    size_t size;
    uint64_t align;
} wt_heap_header_t;

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

static void default_handler(void)
{
    for (;;) {}
}

void Reset_Handler(void);
void NMI_Handler(void) __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void) __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void) __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void) __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);
void DebugMon_Handler(void) __attribute__((weak, alias("default_handler")));

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
    [15] = (uint32_t)&SysTick_Handler,
};

static void copy_data(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;

    while (dst < &_edata) {
        *dst++ = *src++;
    }
}

static void zero_bss(void)
{
    uint32_t *dst = &_sbss;

    while (dst < &_ebss) {
        *dst++ = 0u;
    }
}

static void uart_init(void)
{
    USART_CR1(USART3_BASE) = 0u;
    USART_CR2(USART3_BASE) = 0u;
    USART_CR3(USART3_BASE) = 0u;
    USART_BRR(USART3_BASE) = 120000000u / 115200u;
    USART_CR1(USART3_BASE) = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

static void uart_putc(char c)
{
    while ((USART_ISR(USART3_BASE) & USART_ISR_TXE) == 0u) {}
    USART_TDR(USART3_BASE) = (uint32_t)(uint8_t)c;
}

void wt_tpm_puts(const char *text)
{
    while (*text != '\0') {
        uart_putc(*text++);
    }
}

void wt_tpm_print_i32(int value)
{
    char text[12];
    unsigned int magnitude;
    unsigned int index = 0u;

    if (value < 0) {
        uart_putc('-');
        magnitude = (unsigned int)(-(value + 1)) + 1u;
    }
    else {
        magnitude = (unsigned int)value;
    }
    if (magnitude == 0u) {
        uart_putc('0');
        return;
    }
    while (magnitude != 0u) {
        text[index++] = (char)('0' + (magnitude % 10u));
        magnitude /= 10u;
    }
    while (index != 0u) {
        uart_putc(text[--index]);
    }
}

void wt_tpm_wait(void)
{
    vTaskDelay(pdMS_TO_TICKS(1));
}

void wt_tpm_sleep_ms(unsigned int ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

int wc_GenerateSeed(OS_Seed *os, byte *output, word32 size)
{
    (void)os;
    return wolftrust_guest_rng_stub((unsigned char *)output,
                                    (unsigned int)size);
}

void *XMALLOC(size_t size, void *heap, int type)
{
    wt_heap_header_t *header;

    (void)heap;
    (void)type;
    if (size > (SIZE_MAX - sizeof(*header))) {
        return NULL;
    }
    header = (wt_heap_header_t *)pvPortMalloc(size + sizeof(*header));
    if (header == NULL) {
        return NULL;
    }
    header->size = size;
    return (void *)(header + 1);
}

void XFREE(void *ptr, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (ptr != NULL) {
        vPortFree(((wt_heap_header_t *)ptr) - 1);
    }
}

void *XREALLOC(void *ptr, size_t size, void *heap, int type)
{
    wt_heap_header_t *old_header;
    unsigned char *old_data = (unsigned char *)ptr;
    unsigned char *new_data;
    size_t copy_size;
    size_t index;

    if (ptr == NULL) {
        return XMALLOC(size, heap, type);
    }
    if (size == 0u) {
        XFREE(ptr, heap, type);
        return NULL;
    }
    old_header = ((wt_heap_header_t *)ptr) - 1;
    new_data = (unsigned char *)XMALLOC(size, heap, type);
    if (new_data == NULL) {
        return NULL;
    }
    copy_size = old_header->size < size ? old_header->size : size;
    for (index = 0u; index < copy_size; index++) {
        new_data[index] = old_data[index];
    }
    XFREE(ptr, heap, type);
    return new_data;
}

static void test_task(void *arg)
{
    int rc;

    (void)arg;
    wt_tpm_puts("tpm-freertos: scheduler started\r\n");
    rc = wt_tpm_run();
    if (rc == 0) {
        wt_tpm_puts("tpm-freertos: suite complete\r\n");
#if defined(WT_M33MU_EXPECT_BKPT) && (WT_M33MU_EXPECT_BKPT == 1)
        __asm volatile("bkpt 0x7f");
#endif
    }
    else {
        wt_tpm_puts("tpm-freertos: suite failed\r\n");
#if defined(WT_M33MU_EXPECT_BKPT) && (WT_M33MU_EXPECT_BKPT == 1)
        __asm volatile("bkpt 0x7e");
#endif
    }
    vTaskSuspend(NULL);
    for (;;) {}
}

__attribute__((section(".reset")))
void Reset_Handler(void)
{
    copy_data();
    zero_bss();
    uart_init();
    wt_tpm_puts("tpm-freertos: alive\r\n");

    if (xTaskCreate(test_task, "tpm", 3072, NULL,
                    tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
        wt_tpm_puts("tpm-freertos: xTaskCreate failed\r\n");
        for (;;) {}
    }
    vTaskStartScheduler();
    wt_tpm_puts("tpm-freertos: scheduler exited\r\n");
    for (;;) {}
}

int printf(const char *format, ...)
{
    (void)format;
    return 0;
}
