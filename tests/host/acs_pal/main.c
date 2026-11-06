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

/* Host rows for the FF-A ACS platform page pool: an allocation is released
 * only by its own base and span, so a free naming the wrong size, a tail
 * page, or a page never handed out cannot release a neighbour's page. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pal_interfaces.h"

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("PASS: %s\n", what);
    }
    else {
        failures++;
        printf("FAIL: %s\n", what);
    }
}

#define PAGE  ((uint64_t)PAGE_SIZE_4K)
#define PAGES 5

static int page_zeroed(const uint8_t* p)
{
    uint32_t i;

    for (i = 0u; i < PAGE_SIZE_4K; i++) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    uint8_t* one;
    uint8_t* two;
    uint8_t* next;
    uint8_t* all[PAGES];
    int i;

    one = (uint8_t*)pal_memory_alloc(PAGE);
    two = (uint8_t*)pal_memory_alloc(2u * PAGE);
    check((one != NULL) && (two != NULL) && (two == one + PAGE),
          "a page and a page pair come out of the pool in order");
    check(pal_memory_free(one, 2u * PAGE) == PAL_ERROR,
          "a page is not released as a pair");
    next = (uint8_t*)pal_memory_alloc(PAGE);
    check((next != NULL) && (next != one) && (next != two) &&
          (next != two + PAGE),
          "the refused free left the page and its neighbour allocated");
    check(pal_memory_free(next, PAGE) == PAL_SUCCESS,
          "the extra page is released");
    check(pal_memory_free(two, PAGE) == PAL_ERROR,
          "a pair is not released as a page");
    check(pal_memory_free(two + PAGE, PAGE) == PAL_ERROR,
          "a pair's tail page is not released on its own");
    check(pal_memory_free(two + PAGE, 2u * PAGE) == PAL_ERROR,
          "a pair is not released from its tail");
    check(pal_memory_free(one + 16u, PAGE) == PAL_ERROR,
          "an address inside a page is not a base");
    check(pal_memory_free(one, 3u * PAGE) == PAL_ERROR,
          "a size the pool never hands out is refused");
    check(pal_memory_free(one, 0u) == PAL_ERROR, "so is a zero size");
    next = (uint8_t*)pal_memory_alloc(PAGE);
    check((next != NULL) && (next != one) && (next != two) &&
          (next != two + PAGE),
          "every refused free left the pool as it was");
    check(pal_memory_free(next, PAGE) == PAL_SUCCESS,
          "the extra page is released again");
    check(pal_memory_free(two, 2u * PAGE) == PAL_SUCCESS,
          "the pair is released by its base and span");
    check(pal_memory_free(two, 2u * PAGE) == PAL_ERROR,
          "and not a second time");
    check(pal_memory_free(one, PAGE) == PAL_SUCCESS,
          "the page is released by its base and span");
    check(pal_memory_free(one, PAGE) == PAL_ERROR, "and not a second time");

    check(pal_memory_alloc(3u * PAGE) == NULL,
          "three pages are never handed out");
    for (i = 0; i < PAGES; i++) {
        all[i] = (uint8_t*)pal_memory_alloc(PAGE);
        if (all[i] != NULL) {
            memset(all[i], 0xA5, PAGE_SIZE_4K);
        }
    }
    check((all[PAGES - 1] != NULL) && (pal_memory_alloc(PAGE) == NULL),
          "the pool holds five pages and no more");
    check(pal_memory_free(all[1], PAGE) == PAL_SUCCESS &&
          pal_memory_free(all[2], PAGE) == PAL_SUCCESS,
          "two neighbours are released");
    two = (uint8_t*)pal_memory_alloc(2u * PAGE);
    check((two == all[1]) && page_zeroed(two) && page_zeroed(two + PAGE),
          "the pair reuses them, wiped");
    check(pal_memory_free(all[1], PAGE) == PAL_ERROR,
          "a page inside the new pair is no longer a page allocation");
    check(pal_memory_free(two, 2u * PAGE) == PAL_SUCCESS &&
          pal_memory_free(all[0], PAGE) == PAL_SUCCESS &&
          pal_memory_free(all[3], PAGE) == PAL_SUCCESS &&
          pal_memory_free(all[4], PAGE) == PAL_SUCCESS,
          "everything is released");
    for (i = 0; i < PAGES; i++) {
        all[i] = (uint8_t*)pal_memory_alloc(PAGE);
    }
    check((all[PAGES - 1] != NULL) && (pal_memory_alloc(PAGE) == NULL),
          "all five pages come back");

    printf("%d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
