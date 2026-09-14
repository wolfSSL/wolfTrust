/* ffa_msg.c
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

/* FF-A direct messaging register encodings and relayer checks (DEN0077A
 * 15.2/15.3, 7.4.2). The SPMD applies the NS-physical checks before forwarding
 * a Normal-world request to the SPMC; the SPMC applies the secure-virtual
 * checks before it enters a partition or forwards a response. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"

#include <stddef.h>

void wt_ffa_direct_build(uint64_t* x, uint32_t fid, uint16_t sender,
                         uint16_t receiver, const uint32_t* payload)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        x[i] = 0u;
    }
    x[0] = fid;
    x[1] = ((uint64_t)sender << 16) | (uint64_t)receiver;
    x[2] = 0u;
    for (i = 0u; i < WT_FFA_DIRECT_PAYLOAD_WORDS; i++) {
        x[3u + i] = (payload != NULL) ? (uint64_t)payload[i] : 0u;
    }
}

int wt_ffa_direct_req_check(const uint64_t* x, wt_ffa_instance_t inst)
{
    uint32_t fid = (uint32_t)x[0];
    uint16_t sender = wt_ffa_direct_sender(x[1]);
    uint16_t receiver = wt_ffa_direct_receiver(x[1]);

    if ((fid != WT_FFA_MSG_SEND_DIRECT_REQ32) &&
        (fid != WT_FFA_MSG_SEND_DIRECT_REQ64)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* w2 carries the framework bit and reserved fields; a partition message
     * requires it zero. */
    if ((uint32_t)x[2] != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (sender == receiver) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (inst == WT_FFA_INSTANCE_NS_PHYSICAL) {
        /* The SPMD relays only Normal world to a Secure partition. */
        if (wt_ffa_id_is_secure(sender) || !wt_ffa_id_is_secure(receiver)) {
            return WT_FFA_DENIED;
        }
    }
    else {
        /* The SPMC relays a request only between Secure partitions. */
        if (!wt_ffa_id_is_secure(sender) || !wt_ffa_id_is_secure(receiver)) {
            return WT_FFA_DENIED;
        }
    }
    return 0;
}

int wt_ffa_direct_resp_check(const uint64_t* x, wt_ffa_instance_t inst)
{
    uint32_t fid = (uint32_t)x[0];
    uint16_t sender = wt_ffa_direct_sender(x[1]);
    uint16_t receiver = wt_ffa_direct_receiver(x[1]);

    if ((fid != WT_FFA_MSG_SEND_DIRECT_RESP32) &&
        (fid != WT_FFA_MSG_SEND_DIRECT_RESP64)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((uint32_t)x[2] != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (sender == receiver) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* A response is emitted by the endpoint that received the request, so its
     * sender is always Secure; the receiver is whoever sent the request, which
     * at the NS-physical instance is the Normal world the SPMD returns to. */
    if (!wt_ffa_id_is_secure(sender)) {
        return WT_FFA_DENIED;
    }
    if ((inst == WT_FFA_INSTANCE_NS_PHYSICAL) && wt_ffa_id_is_secure(receiver)) {
        return WT_FFA_DENIED;
    }
    return 0;
}
