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

/* The MIMXRT700 entropy callback against a TRNG model: reading ENT[15] ends a
 * page and starts the next generation, ERR latches a health failure. No
 * request may serve words an earlier request already saw, and a latched ERR
 * fails every request even while a page is still valid. */

#define _POSIX_C_SOURCE 200809L

#include "mock_trng_regs.h"
#include "wolftrust/spm_transport.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);

#define GENERATION_POLLS  3

static int checks;
static int failures;

static uint32_t g_mctl;
static uint32_t g_ent_latch;
static uint32_t g_page;
static int g_generating;
static int g_polls_left;
static int g_fail_next;
static unsigned int g_ent_reads;

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

volatile uint32_t* wt_mock_trng_mctl(void)
{
    if ((g_mctl & (WT_TRNG_MCTL_PRGM | WT_TRNG_MCTL_ENT_VAL |
                   WT_TRNG_MCTL_ERR)) == 0u && g_generating == 0) {
        g_generating = 1;
        g_polls_left = GENERATION_POLLS;
    }
    else if (g_generating != 0 && --g_polls_left <= 0) {
        g_generating = 0;
        if (g_fail_next != 0) {
            g_mctl |= WT_TRNG_MCTL_ERR;
        }
        else {
            g_page++;
            g_mctl |= WT_TRNG_MCTL_ENT_VAL;
        }
    }
    return &g_mctl;
}

volatile uint32_t* wt_mock_trng_ent(uint32_t index)
{
    g_ent_reads++;
    if ((g_mctl & WT_TRNG_MCTL_ENT_VAL) == 0u) {
        g_ent_latch = 0u;
    }
    else {
        g_ent_latch = 0xA5000000u | (g_page << 8) | index;
        if (index == WT_TRNG_ENT_COUNT - 1u) {
            g_mctl &= ~WT_TRNG_MCTL_ENT_VAL;
            g_generating = 1;
            g_polls_left = GENERATION_POLLS;
        }
    }
    return &g_ent_latch;
}

int wt_spm_sp_call(struct wt_spm_call* call)
{
    (void)call;
    return -1;
}

static void model_reset(uint32_t mctl)
{
    g_mctl = mctl;
    g_page = 0u;
    g_generating = 0;
    g_polls_left = 0;
    g_fail_next = 0;
    g_ent_reads = 0u;
}

static int words_disjoint(const unsigned char* a, size_t a_len,
                          const unsigned char* b, size_t b_len)
{
    size_t i;
    size_t j;
    uint32_t wa;
    uint32_t wb;

    for (i = 0u; i + sizeof(wa) <= a_len; i += sizeof(wa)) {
        (void)memcpy(&wa, a + i, sizeof(wa));
        for (j = 0u; j + sizeof(wb) <= b_len; j += sizeof(wb)) {
            (void)memcpy(&wb, b + j, sizeof(wb));
            if (wa == wb && (a != b || i != j)) {
                return 0;
            }
        }
    }
    return 1;
}

static int all_zero(const unsigned char* buf, size_t len)
{
    size_t i;

    for (i = 0u; i < len; i++) {
        if (buf[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/* ERR latched while a page is still valid voids it; the shared callback
 * then zeroes the buffer and refuses every later request. */
static void case_err_with_valid_page(void)
{
    unsigned char first[32];

    (void)memset(first, 0xA5, sizeof(first));
    model_reset(WT_TRNG_MCTL_ENT_VAL | WT_TRNG_MCTL_ERR);
    check(wolftrust_rng_generate_block(first, sizeof(first)) != 0 &&
              g_ent_reads == 0u,
          "ERR with ENT_VAL still set fails without reading ENT");
    check(all_zero(first, sizeof(first)), "a failed request zeroes the buffer");
    model_reset(WT_TRNG_MCTL_ENT_VAL);
    check(wolftrust_rng_generate_block(first, sizeof(first)) != 0 &&
              g_ent_reads == 0u,
          "a failed request latches: the source is not asked again");
}

/* A generation that fails its health tests mid-request fails it, and the
 * page already copied out is wiped from the caller's buffer. */
static void case_err_next_generation(void)
{
    unsigned char span[100];

    (void)memset(span, 0xA5, sizeof(span));
    model_reset(WT_TRNG_MCTL_ENT_VAL);
    g_fail_next = 1;
    check(wolftrust_rng_generate_block(span, sizeof(span)) != 0 &&
              g_ent_reads == WT_TRNG_ENT_COUNT,
          "ERR on the next generation fails a multi-page request");
    check(all_zero(span, sizeof(span)),
          "the first page is not left in a failed request's buffer");
}

/* A generation that never completes times out. */
static void case_stall(void)
{
    unsigned char first[32];

    model_reset(0u);
    g_generating = 1;
    g_polls_left = 0x7FFFFFFF;
    check(wolftrust_rng_generate_block(first, sizeof(first)) != 0 &&
              g_ent_reads == 0u, "a stalled generation times out");
}

/* The failure latch is process state, so each failing case gets its own. */
static void run_isolated(void (*fn)(void), const char* what)
{
    pid_t pid = fork();
    int status = 0;

    if (pid == 0) {
        failures = 0;
        fn();
        (void)fflush(stdout);
        _exit(failures == 0 ? 0 : 1);
    }
    if (pid < 0 || waitpid(pid, &status, 0) < 0) {
        check(0, what);
        return;
    }
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, what);
}

int main(void)
{
    unsigned char first[32];
    unsigned char second[32];
    unsigned char span[100];
    unsigned int reads;
    int rc;

    printf("RUN: unit/rt700_trng\n");

    /* A health failure latched before the first page fails init, and init
     * is retried on the next request. */
    model_reset(WT_TRNG_MCTL_PRGM | WT_TRNG_MCTL_ERR);
    rc = wolftrust_rng_generate_block(first, sizeof(first));
    check(rc != 0 && g_ent_reads == 0u,
          "ERR at init fails the request without reading ENT");

    model_reset(WT_TRNG_MCTL_PRGM);
    rc = wolftrust_rng_generate_block(first, sizeof(first));
    check(rc == 0, "first 32-byte request succeeds");
    check((g_mctl & WT_TRNG_MCTL_PRGM) == 0u, "init leaves programming mode");
    check(g_ent_reads == WT_TRNG_ENT_COUNT,
          "a short request consumes its whole page");

    reads = g_ent_reads;
    rc = wolftrust_rng_generate_block(second, sizeof(second));
    check(rc == 0 && g_ent_reads - reads == WT_TRNG_ENT_COUNT,
          "second 32-byte request reads a fresh page");
    check(memcmp(first, second, sizeof(first)) != 0 &&
              words_disjoint(first, sizeof(first), second, sizeof(second)),
          "back-to-back short requests share no entropy word");

    reads = g_ent_reads;
    rc = wolftrust_rng_generate_block(span, sizeof(span));
    check(rc == 0 && g_ent_reads - reads == 2u * WT_TRNG_ENT_COUNT,
          "a 100-byte request spans two pages");
    check(words_disjoint(span, sizeof(span), span, sizeof(span)) &&
              words_disjoint(span, sizeof(span), second, sizeof(second)),
          "no word repeats within or across requests");

    run_isolated(case_err_with_valid_page,
                 "ERR with a valid page: refused, zeroed, latched");
    run_isolated(case_err_next_generation,
                 "ERR on the next generation: refused and zeroed");
    run_isolated(case_stall, "a stalled generation times out");

    model_reset(WT_TRNG_MCTL_ENT_VAL);
    check(wolftrust_rng_generate_block(first, 0u) == 0,
          "a zero-length request succeeds");
    check(wolftrust_rng_generate_block(NULL, 8u) != 0,
          "a NULL buffer is refused");

    if (failures == 0) {
        printf("PASS: unit/rt700_trng (%d checks)\n", checks);
        return 0;
    }
    printf("FAIL: unit/rt700_trng (%d/%d failed)\n", failures, checks);
    return 1;
}
