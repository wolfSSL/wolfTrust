/* conf_nvm_sync.c
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

/* Target side of the survive-reset NVM seam (P5 K2): trap the DRIVER
 * partition's shadow buffer through the same SVC #1 the psa_* veneers use, so
 * the privileged SPM can drive the flash controller. The host test provides a
 * flash-simulator implementation of wt_conf_nvm_sync instead of this file. */

#include "conf_nvm.h"

#include "wolftrust/ffm.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"

#include "memory_map.h"
#include "pal_config.h"

#include <string.h>

/* The scheduler carves these holes out of other partitions' domains using the
 * memory_map.h constants; the Arm tests probe them via the pal_config.h ones.
 * A drift between the two silently breaks the L3 MMIO-isolation panic tests. */
#if SERVER_PARTITION_MMIO_0_START != WT_CONF_SERVER_MMIO_BASE || \
    SERVER_PARTITION_MMIO_0_END != (WT_CONF_SERVER_MMIO_BASE + \
                                    WT_CONF_SERVER_MMIO_SIZE)
#error "pal_config SERVER MMIO does not match memory_map WT_CONF_SERVER_MMIO"
#endif
#if DRIVER_PARTITION_MMIO_0_START != WT_CONF_DRV_MMIO_BASE || \
    DRIVER_PARTITION_MMIO_0_END != (WT_CONF_DRV_MMIO_BASE + \
                                    WT_CONF_DRV_MMIO_SIZE)
#error "pal_config DRIVER MMIO does not match memory_map WT_CONF_DRV_MMIO"
#endif

int wt_conf_nvm_sync(uint8_t *buf, uint32_t len, int store)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONF_NVM_SYNC;
    call.buffer = buf;
    call.num_bytes = (size_t)len;
    call.call_type = store;

    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS) {
        return -1;
    }
    return call.ret_int;
}

int wt_conf_irq_set(int on)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONF_IRQ_SET;
    call.call_type = on;

    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS) {
        return -1;
    }
    return call.ret_int;
}
