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

/* WT-FFM-0069: a partition's line is claimed from a hostile controller state
 * (Non-secure routed, enabled, pending), at bring-up and again on restart. */

#include "wolftrust/irq_claim.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WORDS 8u
#define SECURE_WORDS 2u

static int checks;
static int failures;
static uint32_t g_iser[WORDS];
static uint32_t g_ispr[WORDS];
static uint32_t g_itns[WORDS];
static int g_route_stuck;
static int g_disable_stuck;
static int g_touched;

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

void wt_arch_nvic_disable(uint32_t word, uint32_t mask)
{
    g_touched = 1;
    if (g_disable_stuck == 0) {
        g_iser[word] &= ~mask;
    }
}

void wt_arch_nvic_clear_pending(uint32_t word, uint32_t mask)
{
    g_touched = 1;
    g_ispr[word] &= ~mask;
}

void wt_arch_nvic_route_secure(uint32_t word, uint32_t mask)
{
    g_touched = 1;
    if (g_route_stuck == 0) {
        g_itns[word] &= ~mask;
    }
}

uint32_t wt_arch_nvic_enabled(uint32_t word)
{
    return g_iser[word];
}

uint32_t wt_arch_nvic_non_secure(uint32_t word)
{
    return g_itns[word];
}

void wt_arch_nvic_barrier(void)
{
}

static void seed_hostile(void)
{
    memset(g_iser, 0xFF, sizeof(g_iser));
    memset(g_ispr, 0xFF, sizeof(g_ispr));
    memset(g_itns, 0xFF, sizeof(g_itns));
    g_route_stuck = 0;
    g_disable_stuck = 0;
    g_touched = 0;
}

static int line_claimed(uint32_t irq)
{
    uint32_t word = irq >> 5;
    uint32_t mask = 1u << (irq & 31u);

    return (g_iser[word] & mask) == 0u && (g_ispr[word] & mask) == 0u &&
        (g_itns[word] & mask) == 0u &&
        g_iser[word] == ~mask && g_ispr[word] == ~mask &&
        g_itns[word] == ~mask;
}

int main(void)
{
    printf("WT-FFM-0069 partition interrupt claim\n");

    seed_hostile();
    check(wt_irq_claim(63u, WORDS) == 0 && line_claimed(63u),
          "hostile line is disabled, cleared, and Secure-routed at bring-up");
    seed_hostile();
    check(wt_irq_claim(63u, WORDS) == 0 && line_claimed(63u),
          "restart claims the line again from a hostile state");
    seed_hostile();
    check(wt_irq_claim(63u, SECURE_WORDS) == 0 && line_claimed(63u),
          "last line of a 64-entry Secure vector table is claimed");
    seed_hostile();
    check(wt_irq_claim(64u, SECURE_WORDS) == -1 && g_touched == 0,
          "line past the Secure vector table is refused before any write");
    seed_hostile();
    check(wt_irq_claim(WORDS * 32u, WORDS) == -1 && g_touched == 0,
          "line beyond the controller is refused without a register write");
    seed_hostile();
    g_route_stuck = 1;
    check(wt_irq_claim(8u, WORDS) == -1,
          "routing that does not read back Secure fails the claim");
    seed_hostile();
    g_disable_stuck = 1;
    check(wt_irq_claim(8u, WORDS) == -1,
          "enable bit that does not clear fails the claim");

    printf("%d checks, %d failures\n", checks, failures);
    if (failures != 0) {
        return 1;
    }
    printf("PASS: irq_claim (WT-FFM-0069)\n");
    return 0;
}
