/* vnet_service.c — wolfTrust VNET service: static storage, NSC veneers.
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

#ifdef CONFIG_VNET

#include <stdint.h>
#include <string.h>
#include "wolftrust/types.h"
#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/vnet/vnet_abi.h"
#include "wolftrust/vnet/vnet_switch.h"
#include "wolftrust/vnet/vnet_errors.h"
#include "wolftrust/services/vnet_service.h"

static vnet_vnic_t       g_vnics[WT_MAX_GUESTS];
static vnet_frame_t      g_frames[WT_VNET_POOL_SLOTS];
static vnet_fdb_entry_t  g_fdb[WT_VNET_FDB_ENTRIES];
static vnet_rx_desc_t    g_ring_storage[WT_MAX_GUESTS][WT_VNET_RX_QUEUE_DEPTH];
static vnet_rx_desc_t   *g_rings[WT_MAX_GUESTS];
static vnet_switch_t     g_switch;
static bool              g_switch_ready;

void wt_vnet_service_init_state(void)
{
    uint32_t i;
    for (i = 0; i < (uint32_t)WT_MAX_GUESTS; ++i) {
        g_rings[i] = g_ring_storage[i];
    }
    if (vnet_switch_init(&g_switch, g_vnics, (uint32_t)WT_MAX_GUESTS,
                         g_frames, (uint16_t)WT_VNET_POOL_SLOTS,
                         g_fdb, (uint16_t)WT_VNET_FDB_ENTRIES,
                         g_rings, (uint16_t)WT_VNET_RX_QUEUE_DEPTH,
                         (bool)(WT_VNET_UNKNOWN_UCAST_FLOOD != 0)) == WT_VNET_OK) {
        g_switch_ready = true;
    }
}

void wt_vnet_service_init(void)
{
    wt_vnet_service_init_state();
    wt_arch_route_irq_to_guest((uint32_t)WT_VNET_RX_IRQ);
}

void wt_vnet_service_refresh_irq(wt_guest_id_t guest_id)
{
    bool pending;
    if (!g_switch_ready) return;
    if ((uint32_t)guest_id >= (uint32_t)WT_MAX_GUESTS) return;
    pending = vnet_switch_irq_pending(&g_switch, (uint32_t)guest_id);
    wt_arch_set_guest_irq_pending((uint32_t)WT_VNET_RX_IRQ, pending);
}

void wt_vnet_service_reset_guest(wt_guest_id_t guest_id)
{
    if (!g_switch_ready) return;
    if ((uint32_t)guest_id >= (uint32_t)WT_MAX_GUESTS) return;
    (void)vnet_switch_reset_vm(&g_switch, (uint32_t)guest_id);
}

vnet_switch_t* wt_vnet_service_switch(void)
{
    return g_switch_ready ? &g_switch : NULL;
}

#endif /* CONFIG_VNET */
