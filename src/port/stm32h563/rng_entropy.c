/* rng_entropy.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <wolfHAL/error.h>
#include <wolfHAL/rng/rng.h>
#include <wolfHAL/rng/stm32h5_rng.h>
#include <wolfHAL/timeout.h>
#include "board.h"

/* Prototype matches the declaration in user_settings.h (CUSTOM_RAND_GENERATE_BLOCK). */
int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);

static bool s_rng_ready;
#ifdef WT_INSECURE_TEST_RNG
static uint32_t s_test_rng_state = 0xA5A5A5A5u;
#endif

static uint32_t s_rng_timeout_tick;

static uint32_t wt_rng_timeout_tick(void)
{
    return ++s_rng_timeout_tick;
}

whal_Timeout g_whalTimeout = {
    .timeoutTicks = 1000000u,
    .startTick = 0u,
    .GetTick = wt_rng_timeout_tick,
};

#ifdef WT_INSECURE_TEST_RNG
static int wt_insecure_test_rng_generate(unsigned char *output, unsigned int sz)
{
    while (sz != 0u) {
        unsigned int n = sz < 4u ? sz : 4u;

        s_test_rng_state = (s_test_rng_state * 1103515245u) + 12345u;
        for (unsigned int i = 0u; i < n; ++i) {
            *output++ = (unsigned char)(s_test_rng_state >> (8u * i));
        }
        sz -= n;
    }

    return 0;
}
#endif

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz)
{
    if (output == NULL && sz != 0u) {
        return -1;
    }

    if (!s_rng_ready) {
        if (whal_Rng_Init(BOARD_RNG_DEV) != WHAL_SUCCESS) {
#ifdef WT_INSECURE_TEST_RNG
            return wt_insecure_test_rng_generate(output, sz);
#else
            return -1;
#endif
        }
        s_rng_ready = true;
    }

    if (sz == 0u) {
        return 0;
    }

    if (whal_Rng_Generate(BOARD_RNG_DEV, output, (size_t)sz) == WHAL_SUCCESS) {
        return 0;
    }

#ifdef WT_INSECURE_TEST_RNG
    return wt_insecure_test_rng_generate(output, sz);
#else
    return -1;
#endif
}
