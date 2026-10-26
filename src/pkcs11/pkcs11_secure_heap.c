/* pkcs11_secure_heap.c
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

#include "wolftrust/zeroize.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef WT_PKCS11_HEAP_SIZE
#define WT_PKCS11_HEAP_SIZE  0x60000U
#endif
#define WT_PKCS11_HEAP_ALIGN 16U

typedef struct wt_pkcs11_heap_block {
    size_t size;
    size_t used;
} wt_pkcs11_heap_block_t;

#define WT_PKCS11_HEAP_HEADER_SIZE \
    ((sizeof(wt_pkcs11_heap_block_t) + WT_PKCS11_HEAP_ALIGN - 1U) & \
     ~(size_t)(WT_PKCS11_HEAP_ALIGN - 1U))

static uint8_t g_heap[WT_PKCS11_HEAP_SIZE] __attribute__((aligned(16)));
static int g_heap_ready;

static int heap_block_valid(const wt_pkcs11_heap_block_t* block)
{
    uintptr_t address = (uintptr_t)block;
    uintptr_t begin = (uintptr_t)g_heap;
    uintptr_t end = begin + sizeof(g_heap);
    size_t remaining;

    if (address < begin || address > end - WT_PKCS11_HEAP_HEADER_SIZE ||
            ((address - begin) & (WT_PKCS11_HEAP_ALIGN - 1U)) != 0U) {
        return 0;
    }
    remaining = (size_t)(end - address) - WT_PKCS11_HEAP_HEADER_SIZE;
    if (block->size == 0U ||
            (block->size & (WT_PKCS11_HEAP_ALIGN - 1U)) != 0U ||
            block->size > remaining || block->used > 1U) {
        return 0;
    }
    return 1;
}

static wt_pkcs11_heap_block_t* heap_next(wt_pkcs11_heap_block_t* block)
{
    return (wt_pkcs11_heap_block_t*)(void*)((uint8_t*)block +
        WT_PKCS11_HEAP_HEADER_SIZE + block->size);
}

static wt_pkcs11_heap_block_t* heap_find_pointer(const void* pointer)
{
    wt_pkcs11_heap_block_t* block =
        (wt_pkcs11_heap_block_t*)(void*)g_heap;

    while (heap_block_valid(block)) {
        if ((const uint8_t*)pointer ==
                (const uint8_t*)block + WT_PKCS11_HEAP_HEADER_SIZE) {
            return block;
        }
        block = heap_next(block);
    }
    return NULL;
}

static void heap_init(void)
{
    wt_pkcs11_heap_block_t* first =
        (wt_pkcs11_heap_block_t*)(void*)g_heap;

    first->size = sizeof(g_heap) - WT_PKCS11_HEAP_HEADER_SIZE;
    first->used = 0U;
    g_heap_ready = 1;
}

void* XMALLOC(size_t size, void* heap, int type)
{
    wt_pkcs11_heap_block_t* block;
    wt_pkcs11_heap_block_t* next;
    wt_pkcs11_heap_block_t* split;
    void* result = NULL;

    (void)heap;
    (void)type;
    if (g_heap_ready == 0) {
        heap_init();
    }
    if (size == 0U) {
        size = 1U;
    }
    if (size > sizeof(g_heap) - WT_PKCS11_HEAP_HEADER_SIZE -
            (WT_PKCS11_HEAP_ALIGN - 1U)) {
        return NULL;
    }
    size = (size + WT_PKCS11_HEAP_ALIGN - 1U) &
           ~(size_t)(WT_PKCS11_HEAP_ALIGN - 1U);
    block = (wt_pkcs11_heap_block_t*)(void*)g_heap;
    while (result == NULL && heap_block_valid(block)) {
        if (block->used == 0U) {
            next = heap_next(block);
            while (heap_block_valid(next) && next->used == 0U) {
                block->size += WT_PKCS11_HEAP_HEADER_SIZE + next->size;
                next = heap_next(block);
            }
            if (block->size >= size) {
                if (block->size >= size + WT_PKCS11_HEAP_HEADER_SIZE +
                        WT_PKCS11_HEAP_ALIGN) {
                    split = (wt_pkcs11_heap_block_t*)(void*)((uint8_t*)block +
                        WT_PKCS11_HEAP_HEADER_SIZE + size);
                    split->size = block->size - size - WT_PKCS11_HEAP_HEADER_SIZE;
                    split->used = 0U;
                    block->size = size;
                }
                block->used = 1U;
                result = (uint8_t*)block + WT_PKCS11_HEAP_HEADER_SIZE;
            }
        }
        if (result == NULL) {
            block = heap_next(block);
        }
    }
    return result;
}

void XFREE(void* pointer, void* heap, int type)
{
    wt_pkcs11_heap_block_t* block;

    (void)heap;
    (void)type;
    if (pointer != NULL) {
        block = heap_find_pointer(pointer);
        if (block != NULL && block->used != 0U) {
            wt_forceZero(pointer, block->size);
            block->used = 0U;
        }
    }
}

void* XREALLOC(void* pointer, size_t size, void* heap, int type)
{
    wt_pkcs11_heap_block_t* block;
    void* replacement;
    size_t copy_size;

    if (pointer == NULL) {
        return XMALLOC(size, heap, type);
    }
    if (size == 0U) {
        XFREE(pointer, heap, type);
        return NULL;
    }
    block = heap_find_pointer(pointer);
    if (block == NULL || block->used == 0U) {
        return NULL;
    }
    if (block->size >= size) {
        return pointer;
    }
    replacement = XMALLOC(size, heap, type);
    if (replacement != NULL) {
        copy_size = block->size < size ? block->size : size;
        (void)memcpy(replacement, pointer, copy_size);
        XFREE(pointer, heap, type);
    }
    return replacement;
}
