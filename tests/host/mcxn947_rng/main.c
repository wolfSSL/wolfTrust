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
 * command: a request that misses its deadline must target memory outside the
 * stack and must leave the source refusing every later call. The register
 * holds 32 bits, so only the low half of a host address is compared. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mcxn947_regs.h"
#include "wolftrust/spm_transport.h"

#define WT_ELS_PAGE_BYTES 64u

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);

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
static uint32_t g_dma_addr;
static uint32_t g_dma_len;
static uint32_t g_requests;
static uint32_t g_last_dma_addr;
static int g_hang;
static uint32_t g_ctrl_seen;

/* A START seen on the next status read issues the request: it completes at
 * once, or with g_hang stays BUSY past the driver's deadline. */
static void wt_mock_step(void)
{
    if (g_ctrl != g_ctrl_seen) {
        if ((g_ctrl & WT_ELS_CTRL_START) != 0u) {
            /* START self-clears, so an identical later write is a new one. */
            g_ctrl &= ~WT_ELS_CTRL_START;
            g_requests++;
            g_last_dma_addr = g_dma_addr;
            g_status = g_hang ? WT_ELS_STATUS_BUSY : 0u;
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
        default:
            return &g_scratch;
    }
}

int wt_spm_sp_call(struct wt_spm_call* call)
{
    (void)call;
    return -1;
}

static int on_stack(uint32_t addr, const void *marker)
{
    uint32_t m = (uint32_t)(uintptr_t)marker;
    uint32_t d = (addr > m) ? addr - m : m - addr;

    return d < 0x10000u;
}

static void test_completed_request(void)
{
    unsigned char out[40];
    uint8_t marker = 0u;

    g_hang = 0;
    memset(out, 0, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "a completed RND_REQ serves its words");
    EXPECT(g_requests == 1u, "40 bytes take one page");
    EXPECT(g_dma_len == WT_ELS_PAGE_BYTES, "a request covers a whole page");
    EXPECT(!on_stack(g_last_dma_addr, &marker),
           "the DMA page is not on the caller's stack");
}

static void test_late_completion(void)
{
    unsigned char out[16];
    uint8_t marker = 0u;
    uint32_t before;

    g_hang = 1;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a request past its deadline fails");
    EXPECT(!on_stack(g_last_dma_addr, &marker),
           "the timed-out request's DMA target is not on the stack");
    /* The request completes after the driver gave up. */
    g_status = 0u;
    before = g_requests;
    g_hang = 0;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "the source refuses every call after a timeout");
    EXPECT(g_requests == before, "no new request is issued after a timeout");
}

int main(void)
{
    test_completed_request();
    test_late_completion();
    (void)printf("mcxn947 rng: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
