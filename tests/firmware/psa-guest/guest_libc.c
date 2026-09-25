/* guest_libc.c
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

/* The libc the freestanding guest links: the Secure runner's string and
 * ctype stubs, the two copy loops gcc emits calls to, and a first-fit
 * allocator for wolfCrypt's memory.c. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../../src/services/wolfhsm/runner/libc_stubs.c"

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    while (n-- > 0u) {
        *d++ = *s++;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;

    while (n-- > 0u) {
        *d++ = (unsigned char)c;
    }
    return dst;
}

/* wolfPSA allocates a slot per key, so the conformance suites need a heap
 * that really frees: one static arena of 8-byte-aligned blocks, first-fit,
 * neighbours merged on every free. */
#define GUEST_HEAP_POOL_SZ (32u * 1024u)

typedef struct guest_heap_block {
    uint32_t size;
    uint32_t used;
} guest_heap_block_t;

static uint8_t s_heap_pool[GUEST_HEAP_POOL_SZ] __attribute__((aligned(8)));
static int s_heap_ready;

static guest_heap_block_t *guest_heap_next(const guest_heap_block_t *block)
{
    const uint8_t *next = (const uint8_t *)block + sizeof(*block) + block->size;

    if (next >= s_heap_pool + GUEST_HEAP_POOL_SZ) {
        return NULL;
    }
    return (guest_heap_block_t *)(uintptr_t)next;
}

static void guest_heap_init(void)
{
    guest_heap_block_t *first = (guest_heap_block_t *)(uintptr_t)s_heap_pool;

    if (s_heap_ready == 0) {
        first->size = GUEST_HEAP_POOL_SZ - (uint32_t)sizeof(*first);
        first->used = 0u;
        s_heap_ready = 1;
    }
}

void *malloc(size_t size)
{
    guest_heap_block_t *block;
    guest_heap_block_t *rest;
    uint32_t need;

    if (size == 0u || size > GUEST_HEAP_POOL_SZ) {
        return NULL;
    }
    guest_heap_init();
    need = (uint32_t)((size + 7u) & ~(size_t)7u);
    for (block = (guest_heap_block_t *)(uintptr_t)s_heap_pool; block != NULL;
         block = guest_heap_next(block)) {
        if (block->used != 0u || block->size < need) {
            continue;
        }
        if (block->size >= need + (uint32_t)sizeof(*block) + 8u) {
            rest = (guest_heap_block_t *)(uintptr_t)
                ((uint8_t *)block + sizeof(*block) + need);
            rest->size = block->size - need - (uint32_t)sizeof(*block);
            rest->used = 0u;
            block->size = need;
        }
        block->used = 1u;
        return (void *)((uint8_t *)block + sizeof(*block));
    }
    return NULL;
}

void free(void *ptr)
{
    guest_heap_block_t *block;
    guest_heap_block_t *next;

    if (ptr == NULL) {
        return;
    }
    block = (guest_heap_block_t *)(uintptr_t)((uint8_t *)ptr - sizeof(*block));
    block->used = 0u;
    for (block = (guest_heap_block_t *)(uintptr_t)s_heap_pool; block != NULL;
         block = guest_heap_next(block)) {
        next = guest_heap_next(block);
        while (block->used == 0u && next != NULL && next->used == 0u) {
            block->size += (uint32_t)sizeof(*next) + next->size;
            next = guest_heap_next(block);
        }
    }
}

void *realloc(void *ptr, size_t size)
{
    guest_heap_block_t *block;
    void *new_ptr;

    if (size == 0u) {
        free(ptr);
        return NULL;
    }
    if (ptr == NULL) {
        return malloc(size);
    }
    block = (guest_heap_block_t *)(uintptr_t)((uint8_t *)ptr - sizeof(*block));
    if (block->size >= size) {
        return ptr;
    }
    new_ptr = malloc(size);
    if (new_ptr != NULL) {
        memcpy(new_ptr, ptr, block->size);
        free(ptr);
    }
    return new_ptr;
}
