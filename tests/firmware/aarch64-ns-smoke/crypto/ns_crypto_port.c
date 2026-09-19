/* ns_crypto_port.c
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

/* Runtime the bare-metal conformance guest needs under wolfCrypt and wolfPSA:
 * a first-fit heap, the string helpers libc_min.c lacks, and a DRBG seed. The
 * seed is emulator test entropy only, never a silicon source. */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifndef WT_NS_HEAP_SIZE
#define WT_NS_HEAP_SIZE 0x80000u
#endif
#define WT_NS_HEAP_ALIGN 16u

typedef struct wt_ns_block {
    size_t size;
    size_t used;
} wt_ns_block_t;

static uint8_t g_heap[WT_NS_HEAP_SIZE] __attribute__((aligned(16)));
static int g_heap_ready;

void* memcpy(void* dst, const void* src, size_t n);
void* memset(void* dst, int c, size_t n);

static wt_ns_block_t* heap_next(wt_ns_block_t* b)
{
    return (wt_ns_block_t*)(void*)((uint8_t*)b + sizeof(*b) + b->size);
}

static int heap_in_range(const wt_ns_block_t* b)
{
    return ((const uint8_t*)b + sizeof(*b)) <= (g_heap + sizeof(g_heap));
}

static void heap_init(void)
{
    wt_ns_block_t* first = (wt_ns_block_t*)(void*)g_heap;

    first->size = sizeof(g_heap) - sizeof(*first);
    first->used = 0u;
    g_heap_ready = 1;
}

void* malloc(size_t n)
{
    wt_ns_block_t* b;
    wt_ns_block_t* split;
    wt_ns_block_t* next;
    void* ret = NULL;

    if (g_heap_ready == 0) {
        heap_init();
    }
    if (n == 0u) {
        n = 1u;
    }
    n = (n + (WT_NS_HEAP_ALIGN - 1u)) & ~(size_t)(WT_NS_HEAP_ALIGN - 1u);
    b = (wt_ns_block_t*)(void*)g_heap;
    while ((ret == NULL) && heap_in_range(b)) {
        if (b->used == 0u) {
            /* Merge the free run ahead so freed neighbours are reusable. */
            next = heap_next(b);
            while (heap_in_range(next) && (next->used == 0u)) {
                b->size += sizeof(*next) + next->size;
                next = heap_next(b);
            }
            if (b->size >= n) {
                if (b->size >= (n + sizeof(*b) + WT_NS_HEAP_ALIGN)) {
                    split = (wt_ns_block_t*)(void*)((uint8_t*)b + sizeof(*b) + n);
                    split->size = b->size - n - sizeof(*b);
                    split->used = 0u;
                    b->size = n;
                }
                b->used = 1u;
                ret = (uint8_t*)b + sizeof(*b);
            }
        }
        if (ret == NULL) {
            b = heap_next(b);
        }
    }
    return ret;
}

void free(void* p)
{
    wt_ns_block_t* b;

    if (p != NULL) {
        b = (wt_ns_block_t*)(void*)((uint8_t*)p - sizeof(*b));
        b->used = 0u;
    }
}

void* calloc(size_t count, size_t size)
{
    size_t total = count * size;
    void* p = NULL;

    if ((size == 0u) || ((total / size) == count)) {
        p = malloc(total);
    }
    if (p != NULL) {
        (void)memset(p, 0, total);
    }
    return p;
}

void* realloc(void* p, size_t n)
{
    wt_ns_block_t* b;
    void* q;

    if (p == NULL) {
        return malloc(n);
    }
    b = (wt_ns_block_t*)(void*)((uint8_t*)p - sizeof(*b));
    if (b->size >= n) {
        return p;
    }
    q = malloc(n);
    if (q != NULL) {
        (void)memcpy(q, p, b->size);
        free(p);
    }
    return q;
}

size_t strlen(const char* s)
{
    size_t n = 0u;

    while (s[n] != '\0') {
        n++;
    }
    return n;
}

int strcmp(const char* a, const char* b)
{
    while ((*a != '\0') && (*a == *b)) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char* a, const char* b, size_t n)
{
    while ((n > 0u) && (*a != '\0') && (*a == *b)) {
        a++;
        b++;
        n--;
    }
    if (n == 0u) {
        return 0;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

char* strncpy(char* dst, const char* src, size_t n)
{
    size_t i = 0u;

    while ((i < n) && (src[i] != '\0')) {
        dst[i] = src[i];
        i++;
    }
    while (i < n) {
        dst[i] = '\0';
        i++;
    }
    return dst;
}

/* wolfPSA's trace helper links the hosted stdio; tracing stays off here. */
void* _impure_ptr;

char* getenv(const char* name)
{
    (void)name;
    return NULL;
}

int fputs(const char* s, void* stream)
{
    (void)s;
    (void)stream;
    return 0;
}

int fputc(int c, void* stream)
{
    (void)stream;
    return c;
}

int vfprintf(void* stream, const char* fmt, va_list args)
{
    (void)stream;
    (void)fmt;
    (void)args;
    return 0;
}

static uint64_t read_cntpct(void)
{
    uint64_t v;

    __asm__ volatile("isb\n\tmrs %0, CNTPCT_EL0" : "=r"(v));
    return v;
}

int wt_ns_generate_seed(unsigned char* output, unsigned int sz)
{
    static uint64_t state;
    uint64_t x;
    unsigned int i;

    if (state == 0u) {
        state = read_cntpct() | 1u;
    }
    for (i = 0u; i < sz; i++) {
        x = state ^ read_cntpct();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state = x;
        output[i] = (unsigned char)((x * 0x2545F4914F6CDD1Dull) >> 56);
    }
    return 0;
}
