/* pkcs11_secure_heap.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 */

#include "wolftrust/zeroize.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WT_PKCS11_HEAP_SIZE  0x60000U
#define WT_PKCS11_HEAP_ALIGN 16U

typedef struct wt_pkcs11_heap_block {
    size_t size;
    size_t used;
} wt_pkcs11_heap_block_t;

static uint8_t g_heap[WT_PKCS11_HEAP_SIZE] __attribute__((aligned(16)));
static int g_heap_ready;

static int heap_block_valid(const wt_pkcs11_heap_block_t* block)
{
    uintptr_t address = (uintptr_t)block;
    uintptr_t begin = (uintptr_t)g_heap;
    uintptr_t end = begin + sizeof(g_heap);
    size_t remaining;

    if (address < begin || address > end - sizeof(*block) ||
            ((address - begin) & (WT_PKCS11_HEAP_ALIGN - 1U)) != 0U) {
        return 0;
    }
    remaining = (size_t)(end - address) - sizeof(*block);
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
        sizeof(*block) + block->size);
}

static wt_pkcs11_heap_block_t* heap_find_pointer(const void* pointer)
{
    wt_pkcs11_heap_block_t* block =
        (wt_pkcs11_heap_block_t*)(void*)g_heap;

    while (heap_block_valid(block)) {
        if ((const uint8_t*)pointer ==
                (const uint8_t*)block + sizeof(*block)) {
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

    first->size = sizeof(g_heap) - sizeof(*first);
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
    if (size > sizeof(g_heap) - sizeof(*block) -
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
                block->size += sizeof(*next) + next->size;
                next = heap_next(block);
            }
            if (block->size >= size) {
                if (block->size >= size + sizeof(*block) +
                        WT_PKCS11_HEAP_ALIGN) {
                    split = (wt_pkcs11_heap_block_t*)(void*)((uint8_t*)block +
                        sizeof(*block) + size);
                    split->size = block->size - size - sizeof(*block);
                    split->used = 0U;
                    block->size = size;
                }
                block->used = 1U;
                result = (uint8_t*)block + sizeof(*block);
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
