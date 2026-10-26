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


/* Host suite for the MCXN947 ELS entropy driver over a model of the RND_REQ
 * command: requests serve fresh DMA pages and wipe them, and a request that
 * misses its deadline must target memory outside the stack and leave the
 * source refusing every later call, as must a request the engine fails; a
 * locked engine refuses before any request. Each case runs in its own process
 * (the driver latches failure). Built without PIE so the 32-bit DMA register
 * holds a host address of static storage. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mcxn947_regs.h"
#include "wolftrust/spm_transport.h"

#define WT_ELS_PAGE_BYTES 64u
#define WT_ELS_PAGE_WORDS_TEST (WT_ELS_PAGE_BYTES / 4u)

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
extern volatile uint32_t g_wt_els_errors;

static int checks;
static int failures;

#define EXPECT(cond, what) \
    do { \
        checks++; \
        if (!(cond)) { \
            (void)fprintf(stderr, "line %d: %s\n", __LINE__, (what)); \
            failures++; \
        } \
    } while (0)

static volatile uint32_t g_status;
static volatile uint32_t g_ctrl;
static volatile uint32_t g_scratch;
static volatile uint32_t g_err_clr;
static int g_fail_request;
static uint32_t g_dma_addr;
static uint32_t g_dma_len;
static uint32_t g_requests;
static uint32_t g_last_dma_addr;
static int g_hang;
static uint32_t g_ctrl_seen;
static uintptr_t g_stack_marker;

static int on_stack(uint32_t addr)
{
    uint32_t m = (uint32_t)g_stack_marker;
    uint32_t d = (addr > m) ? addr - m : m - addr;

    return d < 0x10000u;
}

static uint32_t page_word(uint32_t request, uint32_t word)
{
    return 0xA5000000u | (request << 8) | word;
}

/* A START seen on the next status read issues the request: it fills the page
 * at once, or with g_hang stays BUSY past the driver's deadline. */
static void wt_mock_step(void)
{
    volatile uint32_t *dst;
    uint32_t i;

    if (g_ctrl != g_ctrl_seen) {
        if ((g_ctrl & WT_ELS_CTRL_START) != 0u) {
            /* START self-clears, so an identical later write is a new one. */
            g_ctrl &= ~WT_ELS_CTRL_START;
            g_requests++;
            g_last_dma_addr = g_dma_addr;
            if (g_hang) {
                g_status = WT_ELS_STATUS_BUSY;
            }
            else if (g_fail_request) {
                g_status = WT_ELS_STATUS_ERR;
            }
            else {
                g_status = 0u;
                if (!on_stack(g_dma_addr)) {
                    dst = (volatile uint32_t *)(uintptr_t)g_dma_addr;
                    for (i = 0u; i < g_dma_len / 4u; ++i) {
                        dst[i] = page_word(g_requests, i);
                    }
                }
            }
        }
        g_ctrl_seen = g_ctrl;
    }
}

volatile uint32_t* wt_mock_reg(uintptr_t address)
{
    switch (address) {
        case WT_ELS_BASE_S + 0x00u:
            wt_mock_step();
            return &g_status;
        case WT_ELS_BASE_S + 0x04u:
            return &g_ctrl;
        case WT_ELS_BASE_S + 0x38u:
            return (volatile uint32_t *)&g_dma_addr;
        case WT_ELS_BASE_S + 0x3Cu:
            return (volatile uint32_t *)&g_dma_len;
        case WT_ELS_BASE_S + 0x50u:
            return &g_err_clr;
        default:
            return &g_scratch;
    }
}

int wt_spm_sp_call(struct wt_spm_call* call)
{
    (void)call;
    return -1;
}

/* out[off..off+len) must hold request's page words starting at word 0. */
static int served_from(const unsigned char *out, unsigned int len,
                       uint32_t request)
{
    uint32_t w;
    unsigned int i;

    for (i = 0u; i < len; ++i) {
        w = page_word(request, i / 4u);
        if (out[i] != (unsigned char)(w >> (8u * (i % 4u)))) {
            return 0;
        }
    }
    return 1;
}

static int page_wiped(void)
{
    const volatile uint32_t *page =
        (const volatile uint32_t *)(uintptr_t)g_last_dma_addr;
    uint32_t i;

    for (i = 0u; i < WT_ELS_PAGE_WORDS_TEST; ++i) {
        if (page[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void test_completed_requests(void)
{
    unsigned char out[100];
    uint32_t first;

    g_hang = 0;
    memset(out, 0, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, 40u) == 0,
           "a completed RND_REQ serves its words");
    EXPECT(g_requests == 1u, "40 bytes take one page");
    EXPECT(g_dma_len == WT_ELS_PAGE_BYTES, "a request covers a whole page");
    EXPECT(!on_stack(g_last_dma_addr),
           "the DMA page is not on the caller's stack");
    EXPECT(served_from(out, 40u, 1u), "the 40 bytes are the page's words");
    EXPECT(page_wiped(), "the page is wiped after the request");

    first = g_requests;
    memset(out, 0, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, 16u) == 0,
           "a second request succeeds");
    EXPECT(g_requests == first + 1u, "every call issues a fresh request");
    EXPECT(served_from(out, 16u, first + 1u),
           "unused words of the earlier page are never served");

    first = g_requests;
    memset(out, 0, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "a request spanning two pages succeeds");
    EXPECT(g_requests == first + 2u, "100 bytes take two pages");
    EXPECT(served_from(out, WT_ELS_PAGE_BYTES, first + 1u),
           "the first 64 bytes are the first page");
    EXPECT(served_from(out + WT_ELS_PAGE_BYTES,
                       (unsigned int)sizeof(out) - WT_ELS_PAGE_BYTES,
                       first + 2u),
           "the remaining 36 bytes are the second page");
    EXPECT(page_wiped(), "the page is wiped after a multi-page request");
}

static void test_late_completion(void)
{
    unsigned char out[16];
    uint32_t before;

    g_hang = 1;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a request past its deadline fails");
    EXPECT(!on_stack(g_last_dma_addr),
           "the timed-out request's DMA target is not on the stack");
    /* The request completes after the driver gave up. */
    g_status = 0u;
    before = g_requests;
    g_hang = 0;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "the source refuses every call after a timeout");
    EXPECT(g_requests == before, "no new request is issued after a timeout");
}

static void test_locked_engine(void)
{
    unsigned char out[16];

    g_status = WT_ELS_STATUS_LOCKED;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a locked engine refuses");
    EXPECT(g_requests == 0u, "a locked engine is never sent a request");
    EXPECT(g_wt_els_errors == 1u, "the refusal is counted");
    g_status = 0u;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "the engine serves once it is no longer locked");
    EXPECT(served_from(out, sizeof(out), 1u), "and serves its page");
}

static void test_failed_request(void)
{
    unsigned char out[16];
    uint32_t before;

    g_fail_request = 1;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a request the engine fails is refused");
    EXPECT(g_requests == 1u, "the failed request was issued");
    EXPECT(g_wt_els_errors == 1u, "the failure is counted");
    EXPECT((g_err_clr & WT_ELS_ERR_STATUS_CLR_ALL) != 0u,
           "the error status is cleared");
    g_fail_request = 0;
    g_status = 0u;
    before = g_requests;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "the source refuses every call after a failed request");
    EXPECT(g_requests == before, "no new request is issued after a failure");
}

int main(int argc, char **argv)
{
    uint8_t marker = 0u;
    const char *which = (argc > 1) ? argv[1] : "default";

    g_stack_marker = (uintptr_t)&marker;
    if (strcmp(which, "locked") == 0) {
        test_locked_engine();
    }
    else if (strcmp(which, "error") == 0) {
        test_failed_request();
    }
    else {
        test_completed_requests();
        test_late_completion();
    }
    (void)printf("mcxn947 rng %s: %d checks, %d failures\n", which, checks,
                 failures);
    return failures == 0 ? 0 : 1;
}
