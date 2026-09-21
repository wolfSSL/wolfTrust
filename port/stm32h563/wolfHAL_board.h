/* wolfHAL_board.h
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

/* Minimal wolfHAL board configuration for the wolfTrust STM32H563 secure
 * firmware.  This intentionally exposes only the hardware RNG required by
 * the wolfHSM entropy hook.
 */

#ifndef WOLFTRUST_STM32H563_WOLFHAL_BOARD_H
#define WOLFTRUST_STM32H563_WOLFHAL_BOARD_H

#include <wolfHAL/wolfHAL.h>
#include <wolfHAL/platform/st/stm32h563xx.h>
#include <wolfHAL/rng/stm32h5_rng.h>
#include <wolfHAL/timeout.h>

extern whal_Timeout g_whalTimeout;

#define BOARD_RNG_DEV WHAL_INTERNAL_DEV

#define WHAL_CFG_STM32H5_RNG_DEV { \
    .base = WHAL_STM32H563_RNG_BASE + 0x10000000u, \
    .cfg = (void *)&(const whal_Stm32h5_Rng_Cfg){ \
        .timeout = &g_whalTimeout, \
    }, \
}

#endif /* WOLFTRUST_STM32H563_WOLFHAL_BOARD_H */
