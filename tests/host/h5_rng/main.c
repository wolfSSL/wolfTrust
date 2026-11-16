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

/* The entropy contract (rng_port.h) on the STM32H563 driver over a model of
 * wolfHAL's RNG: init is retried after a failure, a failed generate zeroes
 * the buffer and latches the source, and the timeout ticks advance. */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <wolfHAL/error.h>
#include <wolfHAL/rng/rng.h>
#include <wolfHAL/timeout.h>

#include "wolftrust/spm_transport.h"

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
extern whal_Timeout g_whalTimeout;

static int checks;
static int failures;
static int g_init_failures_left;
static int g_generate_fail_at;
static unsigned int g_inits;
static unsigned int g_generates;
static uint8_t g_next_byte;

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

whal_Error whal_Rng_Init(whal_Rng *rngDev)
{
    (void)rngDev;
    g_inits++;
    if (g_init_failures_left > 0) {
        g_init_failures_left--;
        return WHAL_ETIMEOUT;
    }
    return WHAL_SUCCESS;
}

whal_Error whal_Rng_Generate(whal_Rng *rngDev, void *rngData, size_t rngDataSz)
{
    uint8_t* out = (uint8_t*)rngData;
    size_t i;

    (void)rngDev;
    g_generates++;
    if (g_generate_fail_at != 0 && (int)g_generates == g_generate_fail_at) {
        /* A partial fill, as a timeout mid-request leaves one. */
        for (i = 0u; i < rngDataSz / 2u; i++) {
            out[i] = 0xA5u;
        }
        return WHAL_ETIMEOUT;
    }
    for (i = 0u; i < rngDataSz; i++) {
        out[i] = g_next_byte++;
    }
    return WHAL_SUCCESS;
}

int wt_spm_sp_call(struct wt_spm_call* call)
{
    (void)call;
    return -1;
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

static void case_init_retry(void)
{
    unsigned char out[32];

    g_init_failures_left = 2;
    check(wolftrust_rng_generate_block(out, sizeof(out)) != 0 &&
              g_generates == 0u, "a failed init refuses the request");
    check(all_zero(out, sizeof(out)), "a refused request leaves zeros");
    check(wolftrust_rng_generate_block(out, sizeof(out)) != 0 &&
              g_inits == 2u, "init is retried on the next request");
    check(wolftrust_rng_generate_block(out, sizeof(out)) == 0 &&
              g_inits == 3u && g_generates == 1u,
          "the request succeeds once init does");
    check(wolftrust_rng_generate_block(out, sizeof(out)) == 0 &&
              g_inits == 3u, "init runs once");
}

static void case_generate_failure(void)
{
    unsigned char out[32];
    unsigned char again[16];

    (void)memset(out, 0x11, sizeof(out));
    (void)memset(again, 0x11, sizeof(again));
    g_generates = 0u;
    g_generate_fail_at = 2;
    check(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
          "the first request succeeds");
    check(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
          "a failed generate fails the request");
    check(all_zero(out, sizeof(out)),
          "the partial fill is wiped from the caller's buffer");
    check(wolftrust_rng_generate_block(again, sizeof(again)) != 0 &&
              g_generates == 2u,
          "the source is latched: the next request is refused unasked");
    check(all_zero(again, sizeof(again)),
          "a refused request leaves zeros");
}

static void run_isolated(void (*fn)(void), const char* what)
{
    pid_t pid;
    int status = 0;

    (void)fflush(stdout);
    pid = fork();
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
    uint32_t tick;

    printf("RUN: unit/h5_rng\n");
    /* The failing cases first, each on a fresh, uninitialised source. */
    run_isolated(case_init_retry, "init failures are retried");
    run_isolated(case_generate_failure,
                 "a failed generate zeroes the buffer and latches");
    check(wolftrust_rng_generate_block(first, sizeof(first)) == 0 &&
              g_inits == 1u && g_generates == 1u,
          "the first request initialises the RNG and generates");
    check(wolftrust_rng_generate_block(second, sizeof(second)) == 0 &&
              memcmp(first, second, sizeof(first)) != 0,
          "a second request returns fresh bytes");
    check(wolftrust_rng_generate_block(first, 0u) == 0 && g_generates == 2u,
          "a zero-length request succeeds without generating");
    check(wolftrust_rng_generate_block(NULL, 8u) != 0,
          "a NULL buffer is refused");
    tick = g_whalTimeout.GetTick();
    check(g_whalTimeout.GetTick() == tick + 1u &&
              g_whalTimeout.timeoutTicks != 0u,
          "the wolfHAL timeout ticks advance and are bounded");

    if (failures == 0) {
        printf("PASS: unit/h5_rng (%d checks)\n", checks);
        return 0;
    }
    printf("FAIL: unit/h5_rng (%d/%d failed)\n", failures, checks);
    return 1;
}
