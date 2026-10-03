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

/* Host rows for the freestanding AArch64 memmove: overlap in both directions
 * and separately allocated buffers, whose relative order it must not ask the
 * compiler for (the build renames the routines so the host libc stays in
 * use). */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void* wt_min_memmove(void* dest, const void* src, size_t count);

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

static void fill(uint8_t* buf, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        buf[i] = (uint8_t)(i + 1u);
    }
}

int main(void)
{
    static const uint8_t forward[16] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 15, 16
    };
    static const uint8_t backward[16] = {
        1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
    };
    uint8_t buf[16];
    uint8_t* heap_src;
    uint8_t* heap_dst;
    uint8_t stack_dst[16];

    fill(buf, sizeof(buf));
    check(wt_min_memmove(buf, buf + 2, 14u) == buf &&
          memcmp(buf, forward, sizeof(buf)) == 0,
          "an overlapping move to a lower address copies forward intact");

    fill(buf, sizeof(buf));
    check(wt_min_memmove(buf + 2, buf, 14u) == buf + 2 &&
          memcmp(buf, backward, sizeof(buf)) == 0,
          "an overlapping move to a higher address copies backward intact");

    heap_src = (uint8_t*)malloc(16u);
    heap_dst = (uint8_t*)malloc(16u);
    if ((heap_src == NULL) || (heap_dst == NULL)) {
        free(heap_src);
        free(heap_dst);
        printf("aarch64_libc: allocation failed\n");
        return 1;
    }
    fill(heap_src, 16u);
    (void)memset(heap_dst, 0, 16u);
    (void)wt_min_memmove(heap_dst, heap_src, 16u);
    check(memcmp(heap_dst, heap_src, 16u) == 0,
          "a move between separately allocated buffers copies them");
    (void)memset(stack_dst, 0, sizeof(stack_dst));
    (void)wt_min_memmove(stack_dst, heap_src, sizeof(stack_dst));
    check(memcmp(stack_dst, heap_src, sizeof(stack_dst)) == 0,
          "a move from the heap onto the stack copies it");
    (void)memset(heap_dst, 0, 16u);
    (void)wt_min_memmove(heap_dst, stack_dst, 16u);
    check(memcmp(heap_dst, stack_dst, 16u) == 0,
          "a move from the stack onto the heap copies it");
    check(wt_min_memmove(heap_dst, heap_src, 0u) == heap_dst,
          "a zero-length move returns the destination");
    free(heap_src);
    free(heap_dst);

    printf("aarch64_libc: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
