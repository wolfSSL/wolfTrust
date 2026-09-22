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
        (fid != WT_FFA_MSG_SEND_DIRECT_REQ64) &&
        (fid != WT_FFA_MSG_SEND_DIRECT_REQ2)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* w2 carries the framework bit and reserved fields; a partition message
     * requires it zero. REQ2 carries the service UUID in x2/x3 instead. */
    if ((fid != WT_FFA_MSG_SEND_DIRECT_REQ2) && ((uint32_t)x[2] != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (sender == receiver) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (inst == WT_FFA_INSTANCE_NS_PHYSICAL) {
        /* The SPMD relays only Normal world to a Secure partition. */
        if (wt_ffa_id_is_secure(sender) || !wt_ffa_id_is_secure(receiver)) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }
    else {
        /* The SPMC relays a request only between Secure partitions. */
        if (!wt_ffa_id_is_secure(sender) || !wt_ffa_id_is_secure(receiver)) {
            return WT_FFA_INVALID_PARAMETERS;
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
        (fid != WT_FFA_MSG_SEND_DIRECT_RESP64) &&
        (fid != WT_FFA_MSG_SEND_DIRECT_RESP2)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((uint32_t)x[2] != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((fid == WT_FFA_MSG_SEND_DIRECT_RESP2) && ((x[2] != 0u) || (x[3] != 0u))) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (sender == receiver) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* A response is emitted by the endpoint that received the request, so its
     * sender is always Secure; the receiver is whoever sent the request, which
     * at the NS-physical instance is the Normal world the SPMD returns to. */
    if (!wt_ffa_id_is_secure(sender)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((inst == WT_FFA_INSTANCE_NS_PHYSICAL) && wt_ffa_id_is_secure(receiver)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    return 0;
}

static uint32_t msg2_read32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int wt_ffa_msg2_parse(const uint8_t* tx, uint32_t tx_size, uint16_t caller,
                      uint32_t w1, uint32_t w2, wt_ffa_msg2_t* out)
{
    uint32_t flags;
    uint32_t sender_receiver;
    uint16_t sender;

    if ((tx == NULL) || (out == NULL) ||
        (tx_size < WT_FFA_MSG2_HEADER_SIZE)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (((w1 & 0xFFFFu) != 0u) ||
        ((w2 & ~(uint32_t)WT_FFA_MSG2_FLAG_DELAY_SRI) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    flags = msg2_read32(&tx[0]);
    out->offset = msg2_read32(&tx[8]);
    sender_receiver = msg2_read32(&tx[12]);
    out->size = msg2_read32(&tx[16]);
    out->uuid = &tx[24];
    sender = (uint16_t)(sender_receiver >> 16);
    out->receiver = (uint16_t)(sender_receiver & 0xFFFFu);
    if ((flags != 0u) || (msg2_read32(&tx[4]) != 0u) ||
        (msg2_read32(&tx[20]) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* The header names the caller as sender; w1 repeats it at the physical
     * instance and is zero at the secure virtual one (16.4). */
    if ((sender != caller) ||
        (((w1 >> 16) != 0u) && ((uint16_t)(w1 >> 16) != caller))) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (sender == out->receiver) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((out->offset < WT_FFA_MSG2_HEADER_SIZE) ||
        ((uint64_t)out->offset + (uint64_t)out->size > (uint64_t)tx_size)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    return 0;
}

int wt_ffa_msg2_uuid_ok(const uint8_t* header_uuid, const uint8_t* ep_uuid)
{
    unsigned int i;
    unsigned int nil = 1u;

    if ((header_uuid == NULL) || (ep_uuid == NULL)) {
        return 0;
    }
    for (i = 0u; i < 16u; i++) {
        if (header_uuid[i] != 0u) {
            nil = 0u;
        }
    }
    if (nil != 0u) {
        return 1;
    }
    for (i = 0u; i < 16u; i++) {
        if (header_uuid[i] != ep_uuid[i]) {
            return 0;
        }
    }
    return 1;
}
