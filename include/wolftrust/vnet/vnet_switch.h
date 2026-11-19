/* vnet_switch.h
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

#ifndef WOLFTRUST_VNET_SWITCH_H
#define WOLFTRUST_VNET_SWITCH_H

#include <stdbool.h>
#include <stdint.h>
#include "wolftrust/vnet/vnet_abi.h"
#include "wolftrust/vnet/vnet_config.h"
#include "wolftrust/vnet/vnet_mac.h"
#include "wolftrust/vnet/vnet_pool.h"
#include "wolftrust/vnet/vnet_ring.h"
#include "wolftrust/vnet/vnet_fdb.h"
#include "wolftrust/vnet/vnet_stats.h"

typedef struct vnet_vnic {
    bool         open;
    bool         mac_set;
    vnet_mac_t   mac;
    uint16_t     mtu;
    bool         rx_irq_pending;
    vnet_ring_t  rxq;
    vnet_stats_t stats;
} vnet_vnic_t;

typedef struct vnet_switch {
    vnet_vnic_t *vnics;
    uint32_t     nvm;
    vnet_pool_t  pool;
    vnet_fdb_t   fdb;
    bool         unknown_unicast_flood;
    vnet_stats_t global_stats;
} vnet_switch_t;

/* All storage is caller-owned and must outlive sw.
 *
 *   vnics            — array of nvm vnet_vnic_t (zero-initialised by init)
 *   frame_storage    — array of frame_count vnet_frame_t
 *   fdb_storage      — array of fdb_capacity vnet_fdb_entry_t
 *   rx_ring_storage  — array of nvm pointers, each pointing to a
 *                       caller-allocated buffer of rx_ring_capacity
 *                       vnet_rx_desc_t entries
 */
int vnet_switch_init(vnet_switch_t    *sw,
                     vnet_vnic_t      *vnics,
                     uint32_t          nvm,
                     vnet_frame_t     *frame_storage,
                     uint16_t          frame_count,
                     vnet_fdb_entry_t *fdb_storage,
                     uint16_t          fdb_capacity,
                     vnet_rx_desc_t  **rx_ring_storage,
                     uint16_t          rx_ring_capacity,
                     bool              unknown_unicast_flood);

int  vnet_switch_open(vnet_switch_t *sw, uint32_t vm_id, vnet_info_t *info_out);
/* Return vm_id's port to its boot state: drop its queued frames, release its
 * FDB entries, and clear its open and MAC binding. */
int  vnet_switch_reset_vm(vnet_switch_t *sw, uint32_t vm_id);
int  vnet_switch_assign_mac(vnet_switch_t *sw, uint32_t vm_id,
                            const vnet_mac_t *mac);

int  vnet_switch_tx(vnet_switch_t *sw, uint32_t src_vm,
                    const uint8_t *frame, uint16_t len,
                    uint32_t now_tick);

int  vnet_switch_poll_rx(vnet_switch_t *sw, uint32_t vm_id,
                         vnet_rx_meta_t *meta);
int  vnet_switch_read_rx(vnet_switch_t *sw, uint32_t vm_id,
                         uint16_t slot, uint16_t gen,
                         uint8_t *dst, uint16_t dst_len);
int  vnet_switch_release_rx(vnet_switch_t *sw, uint32_t vm_id,
                            uint16_t slot, uint16_t gen);

int  vnet_switch_irq_ack(vnet_switch_t *sw, uint32_t vm_id);
bool vnet_switch_irq_pending(const vnet_switch_t *sw, uint32_t vm_id);

uint16_t vnet_switch_drop_expired(vnet_switch_t *sw,
                                  uint32_t       now_tick,
                                  uint32_t       timeout_ticks);

const vnet_stats_t *vnet_switch_vnic_stats(const vnet_switch_t *sw,
                                           uint32_t             vm_id);
const vnet_stats_t *vnet_switch_global_stats(const vnet_switch_t *sw);

#endif
