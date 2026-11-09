/* vnet_service.h
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

#ifndef WOLFTRUST_SERVICES_VNET_SERVICE_H
#define WOLFTRUST_SERVICES_VNET_SERVICE_H

#ifdef CONFIG_VNET

#include <stdint.h>
#include "wolftrust/types.h"
#include "wolftrust/vnet/vnet_switch.h"

/* Initialise the monitor-owned VNET subsystem. Called once at boot
 * from wt_monitor_init() when CONFIG_VNET is on. Wires the static
 * frame pool, FDB, per-vnic rings, and switch state; programs the
 * synthetic RX IRQ as NS-targeted in the NVIC's ITNS register
 * (enable bit comes from the per-guest partition irq_mask). */
void wt_vnet_service_init(void);
/* Band-local state rebuild (no privileged IRQ programming): safe from the
 * confined partition, so the restarted entry re-initializes the scrubbed
 * RESTART_CLEAR data band before serving (WT-FFM-0051). */
void wt_vnet_service_init_state(void);

/* Reflect the switch's per-vnic rx_irq_pending bit into the NS NVIC
 * for the guest about to resume. Called from wt_dispatch_guest just
 * before the BXNS. Level semantics: pending while the queue is
 * non-empty (and the queue empties only via vnet_rx_release). Guests
 * that don't enable the IRQ in their partition irq_mask still see
 * the underlying state via vnet_rx_poll and can poll. */
void wt_vnet_service_refresh_irq(wt_guest_id_t guest_id);

/* A restarted or quarantined guest never closes its port: drop its queued
 * frames, FDB entries and MAC binding so the next instance starts clean. */
void wt_vnet_service_reset_guest(wt_guest_id_t guest_id);

/* The monitor-owned switch instance for the SERVICE_VNET relay; NULL until
 * wt_vnet_service_init succeeds, which keeps the relay fail-closed. */
vnet_switch_t* wt_vnet_service_switch(void);

#endif /* CONFIG_VNET */

#endif
