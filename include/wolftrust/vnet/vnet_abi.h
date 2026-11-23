/* vnet_abi.h — public ABI for the wolfTrust VNET service.
 *
 * Both the secure side (which defines the NSC veneers) and the
 * non-secure guest (which links against secure_cmse_implib.o to import
 * them) include this header. Keep it free of secure-side internals.
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

#ifndef WOLFTRUST_VNET_ABI_H
#define WOLFTRUST_VNET_ABI_H

#include <stdbool.h>
#include <stdint.h>
#include "wolftrust/vnet/vnet_config.h"
#include "wolftrust/vnet/vnet_mac.h"
#include "wolftrust/vnet/vnet_errors.h"

typedef struct vnet_info {
    uint32_t   abi_version;
    uint32_t   features;
    uint16_t   mtu;
    int16_t    rx_irq;
    vnet_mac_t default_mac;
    bool       mac_set;
} vnet_info_t;

typedef struct vnet_rx_meta {
    uint16_t token_slot;
    uint16_t token_gen;
    uint16_t len;
    uint16_t flags;
    uint32_t src_vm;
} vnet_rx_meta_t;

/* SERVICE_VNET over FF-M (WT-FFM-0056): the SID the vnet manifest assigns
 * (manifest-vnet.json) and the operations, carried as the psa_call type.
 * Vector layout: OPEN outvec[0]=vnet_info_t; SET_MAC invec[0]=6-byte MAC;
 * TX invec[0]=one frame; RX_FETCH outvec[0]=vnet_rx_meta_t,
 * outvec[1]=payload; IRQ_ACK no vectors. */
#define WT_VNET_SERVICE_SID      4103U
#define WT_VNET_SERVICE_VERSION  1U

/* Mediated link MTU: one frame plus the RX metadata must fit a single
 * psa_call's copied-transfer budget (WT_SPM_TRANSFER_BYTES). OPEN reports
 * this value and the relay refuses larger frames. */
#define WT_VNET_PSA_MTU          1000U

#define WT_VNET_OP_OPEN       1
#define WT_VNET_OP_SET_MAC    2
#define WT_VNET_OP_TX         3
#define WT_VNET_OP_RX_FETCH   4
#define WT_VNET_OP_IRQ_ACK    5

#endif
