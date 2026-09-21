/* wolfpsa_zephyr_init.c
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

/* Zephyr SYS_INIT wrapper for wolfPSA.
 *
 * Runs at SYS_INIT priority just after the wolfhsm-client module's hook
 * (which registers wh_Client_CryptoCb against WH_DEV_ID). We:
 *   1. tell wolfPSA to thread WH_DEV_ID through every wc_*Init() call
 *      it issues (the runtime-devid patch carried in the lib/wolfPSA
 *      submodule provides wolfPSA_SetDefaultDevID for this).
 *   2. call psa_crypto_init() so the PSA Crypto API is usable from
 *      app code that runs out of main().
 */

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>

#ifdef CONFIG_WOLFTRUST_WOLFHSM_CLIENT
#include "wolfhsm/wh_client.h"
#endif

LOG_MODULE_REGISTER(wolfpsa_zephyr, LOG_LEVEL_INF);

static int wolfpsa_zephyr_sys_init(void)
{
    psa_status_t st;

#ifdef CONFIG_WOLFTRUST_WOLFHSM_CLIENT
    (void)wolfPSA_SetDefaultDevID(WH_DEV_ID);
#endif

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        LOG_ERR("psa_crypto_init failed st=%d", (int)st);
        return -EIO;
    }

#ifdef CONFIG_WOLFTRUST_WOLFHSM_CLIENT
    LOG_INF("wolfPSA up; default devId=0x%08x", (unsigned)WH_DEV_ID);
#else
    LOG_INF("wolfPSA up; native engine (Non-secure wolfCrypt)");
#endif
    return 0;
}

/* APPLICATION priority guarantees we run AFTER the wolfhsm-client module's
 * POST_KERNEL hook (so the crypto_cb device is registered before we ask
 * wolfPSA to use it) but before main(). */
SYS_INIT(wolfpsa_zephyr_sys_init, APPLICATION,
         CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
