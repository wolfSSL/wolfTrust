/* wolfhsm_zephyr_init.c
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

/* Register the wolfHSM client at POST_KERNEL before wolfPSA or app startup. */

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

LOG_MODULE_REGISTER(wolftrust_wolfhsm_client, LOG_LEVEL_INF);

int  wolfhsm_guest_init(void);

static int wolftrust_wolfhsm_client_sys_init(void)
{
    int rc;

    rc = wolfhsm_guest_init();
    if (rc != WH_ERROR_OK) {
        LOG_ERR("wolfhsm_guest_init failed rc=%d", rc);
        return rc;
    }

    /* Direct initialization registers the wolfHSM callback. If the Secure
     * Partition is restarting, the shared glue registers a retry callback. */
    /* wolfCrypt's "default devId" (wc_CryptoCb_DefaultDevID) returns the
     * first registered crypto_cb device; with WH_DEV_ID being the only
     * device wolfHSM registers, that's already WH_DEV_ID. wolfPSA threads its
     * own runtime-settable devId via wolfPSA_SetDefaultDevID() — done in
     * the wolfpsa module's SYS_INIT hook. */

    LOG_INF("wolfHSM devId=0x%08x registered", (unsigned)WH_DEV_ID);
    return 0;
}

SYS_INIT(wolftrust_wolfhsm_client_sys_init, POST_KERNEL,
         CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
