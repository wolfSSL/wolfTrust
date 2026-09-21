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
#include <string.h>

#include <wolfHAL/error.h>
#include <wolfHAL/rng/rng.h>
#include <wolfHAL/rng/stm32h5_rng.h>
#include <wolfHAL/timeout.h>

#include "wolfHAL_board.h"

#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/arch.h"

/* Prototype matches the declaration in user_settings.h (CUSTOM_RAND_GENERATE_BLOCK). */
int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
/* Privileged half, invoked by the SVC dispatcher for confined callers. */
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

static bool s_rng_ready;
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

int wolftrust_rng_generate_block_direct(unsigned char *output, unsigned int sz)
{
    if (output == NULL && sz != 0u) {
        return -1;
    }

    if (!s_rng_ready) {
        if (whal_Rng_Init(BOARD_RNG_DEV) != WHAL_SUCCESS) {
            return -1;
        }
        s_rng_ready = true;
    }

    if (sz == 0u) {
        return 0;
    }

    if (whal_Rng_Generate(BOARD_RNG_DEV, output, (size_t)sz) == WHAL_SUCCESS) {
        return 0;
    }

    return -1;
}

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz)
{
    /* A confined keystore partition cannot touch the RNG peripheral or its
     * clock; the SVC dispatcher runs the direct half privileged. */
    if (wt_arch_thread_unprivileged()) {
        wt_spm_call_t call;

        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_KEYSTORE_ENTROPY;
        call.buffer = output;
        call.num_bytes = sz;
        if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS) {
            return -1;
        }
        return call.ret_int;
    }
    return wolftrust_rng_generate_block_direct(output, sz);
}
