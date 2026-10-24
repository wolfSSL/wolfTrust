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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "task.h"

#include "wolftrust/pkcs11_provider.h"
#include "wolftrust/pkcs11_psa_transport.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"

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

#if defined(WT_ENGINE_HSM)
int wolfhsm_guest_init(void);
#endif

/* Software ECC needs more stack than the HSM callback path. */
#if defined(WT_ENGINE_NATIVE)
#define WT_PROVIDER_STACK_WORDS 4096U
#else
#define WT_PROVIDER_STACK_WORDS 2048U
#endif

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

static uint8_t g_request[WT_PKCS11_MESSAGE_MAX];
static uint8_t g_response[WT_PKCS11_MESSAGE_MAX];

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
    [15] = (uint32_t)&SysTick_Handler,
};

static void uart_putc(char c)
{
    while ((USART_ISR(USART3_BASE) & USART_ISR_TXE) == 0u) {}
    USART_TDR(USART3_BASE) = (uint32_t)(uint8_t)c;
}

static void provider_puts(const char* text)
{
    while (*text != '\0') {
        uart_putc(*text++);
    }
}

void wt_pkcs11_sleep_ms(unsigned int ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

static int provider_heap_scrub_test(void)
{
    volatile uint8_t* first;
    volatile uint8_t* reused;
    uintptr_t first_addr;
    size_t i;
    int scrubbed = 1;

    first = (volatile uint8_t*)pvPortMalloc(64U);
    if (first == NULL) {
        return -1;
    }
    for (i = 0U; i < 64U; i++) {
        first[i] = 0xA5U;
    }
    first_addr = (uintptr_t)first;
    vPortFree((void*)first);
    first = NULL;
    reused = (volatile uint8_t*)pvPortMalloc(64U);
    if (reused == NULL || (uintptr_t)reused != first_addr) {
        scrubbed = 0;
    }
    if (reused != NULL) {
        for (i = 0U; i < 64U; i++) {
            if (reused[i] != 0U) {
                scrubbed = 0;
            }
        }
        vPortFree((void*)reused);
    }
    return scrubbed != 0 ? 0 : -1;
}

static void provider_task(void* arg)
{
    int rc;

    (void)arg;
    if (provider_heap_scrub_test() != 0) {
        provider_puts("pkcs11-provider: heap scrub failed\r\n");
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(1000U));
        }
    }
    provider_puts("pkcs11-provider: heap scrub ok\r\n");
#if defined(WT_ENGINE_HSM)
    rc = wolfhsm_guest_init();
    if (rc != 0) {
        provider_puts("pkcs11-provider: wolfHSM init failed\r\n");
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(1000U));
        }
    }
#endif
    provider_puts("pkcs11-provider: ready\r\n");
    for (;;) {
        rc = wt_pkcs11_psa_provider_step(g_request, sizeof(g_request),
                g_response, sizeof(g_response), wt_pkcs11_provider_dispatch,
                NULL);
        if (rc != 0) {
            vTaskDelay(1U);
        }
    }
}

__attribute__((section(".reset")))
void Reset_Handler(void)
{
    uint32_t* src = &_sidata;
    uint32_t* dst = &_sdata;

    while (dst < &_edata) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss; ++dst) {
        *dst = 0u;
    }
    USART_CR1(USART3_BASE) = 0u;
    USART_CR2(USART3_BASE) = 0u;
    USART_CR3(USART3_BASE) = 0u;
    USART_BRR(USART3_BASE) = 120000000u / 115200u;
    USART_CR1(USART3_BASE) = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
    provider_puts("pkcs11-provider: alive\r\n");
    if (xTaskCreate(provider_task, "p11-provider", WT_PROVIDER_STACK_WORDS, NULL,
                    tskIDLE_PRIORITY + 1U, NULL) != pdPASS) {
        provider_puts("pkcs11-provider: task create failed\r\n");
        for (;;) {}
    }
    vTaskStartScheduler();
    for (;;) {}
}

void* XMALLOC(size_t size, void* heap, int type)
{
    wt_heap_header_t* header;
    (void)heap;
    (void)type;
    if (size > SIZE_MAX - sizeof(*header)) {
        return NULL;
    }
    header = (wt_heap_header_t*)pvPortMalloc(size + sizeof(*header));
    if (header == NULL) {
        return NULL;
    }
    header->size = size;
    return header + 1;
}

void XFREE(void* ptr, void* heap, int type)
{
    (void)heap;
    (void)type;
    if (ptr != NULL) {
        vPortFree(((wt_heap_header_t*)ptr) - 1);
    }
}

void* XREALLOC(void* ptr, size_t size, void* heap, int type)
{
    wt_heap_header_t* old_header;
    uint8_t* copy;
    size_t amount;

    if (ptr == NULL) {
        return XMALLOC(size, heap, type);
    }
    if (size == 0U) {
        XFREE(ptr, heap, type);
        return NULL;
    }
    old_header = ((wt_heap_header_t*)ptr) - 1;
    copy = (uint8_t*)XMALLOC(size, heap, type);
    if (copy == NULL) {
        return NULL;
    }
    amount = old_header->size < size ? old_header->size : size;
    for (size_t i = 0U; i < amount; i++) {
        copy[i] = ((uint8_t*)ptr)[i];
    }
    XFREE(ptr, heap, type);
    return copy;
}

int printf(const char* format, ...)
{
    (void)format;
    return 0;
}
