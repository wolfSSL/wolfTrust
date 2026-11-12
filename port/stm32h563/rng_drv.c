/* rng_drv.c
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

/* The STM32H563 RNG through wolfHAL, behind the shared entropy callback. */

#include <stddef.h>
#include <stdint.h>

#include <wolfHAL/error.h>
#include <wolfHAL/rng/rng.h>
#include <wolfHAL/rng/stm32h5_rng.h>
#include <wolfHAL/timeout.h>

#include "rng_port.h"
#include "wolfHAL_board.h"

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

int wt_port_rng_init(void)
{
    return (whal_Rng_Init(BOARD_RNG_DEV) == WHAL_SUCCESS) ? 0 : -1;
}

int wt_port_rng_fill(unsigned char *out, unsigned int sz)
{
    return (whal_Rng_Generate(BOARD_RNG_DEV, out, (size_t)sz) == WHAL_SUCCESS)
               ? 0 : -1;
}
