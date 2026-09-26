/* vnet_relay.h
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

#ifndef WOLFTRUST_SERVICES_VNET_RELAY_H
#define WOLFTRUST_SERVICES_VNET_RELAY_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/vnet/vnet_switch.h"

/* SERVICE_VNET: the mediated door to the secure virtual Ethernet switch
 * (WT-FFM-0056). A non-secure guest reaches its switch port only through
 * psa_connect/psa_call; the operation rides the FF-M call type and the SPM
 * stamps the caller identity, which selects the port. Frame bytes cross as
 * copied FF-M vectors. RX_FETCH returns the slot/generation metadata only
 * after the relay has consumed and released the corresponding token. */

/* The WT_VNET_OP_* operation codes and SID live in vnet_abi.h, shared with
 * the non-secure client transport.
 *
 * Vector layout per operation:
 *   OPEN:     outvec[0] = vnet_info_t
 *   SET_MAC:  invec[0]  = 6-byte MAC
 *   TX:       invec[0]  = one Ethernet frame
 *   RX_FETCH: outvec[0] = vnet_rx_meta_t, outvec[1] = frame payload
 *   IRQ_ACK:  no vectors
 * On success psa_call returns PSA_SUCCESS; switch-level refusals return the
 * WT_VNET_E_* code unchanged (their range does not collide with PSA_ERROR_*).
 * RX_FETCH dequeues, copies, and releases one frame in a single call; an
 * empty queue returns WT_VNET_E_EMPTY. */

/* Install the switch instance the relay drives. NULL restores the
 * fail-closed default, which refuses every operation. */
void wt_vnet_relay_set_switch(vnet_switch_t* sw);

/* Monotonic tick source for switch aging. NULL means tick 0. */
void wt_vnet_relay_set_tick(uint32_t (*tick_fn)(void));

/* Transport seam, mirroring the other services: direct gate calls on the
 * host, the SVC transport when scheduled on target. NULL restores default. */
void wt_vnet_relay_set_transport(wt_spm_transport_fn fn);

/* SERVICE_VNET's dispatch loop: wait, get, run one operation, reply.
 * Architecture-neutral so the same code is host-tested through a real
 * psa_connect/psa_call round trip and scheduled on target. */
int wt_vnet_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                           int32_t partition_id);

#endif /* WOLFTRUST_SERVICES_VNET_RELAY_H */
