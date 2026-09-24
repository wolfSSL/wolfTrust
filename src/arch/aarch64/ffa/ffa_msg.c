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
    /* REQ2 carries the service UUID in x2/x3 instead of flags. */
    if ((fid != WT_FFA_MSG_SEND_DIRECT_REQ2) &&
        (((uint32_t)x[2] & WT_FFA_DIRECT_FLAGS_MBZ) != 0u)) {
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
    /* RESP2's x2/x3 are SBZ (Table 15.19). */
    if ((fid != WT_FFA_MSG_SEND_DIRECT_RESP2) &&
        (((uint32_t)x[2] & WT_FFA_DIRECT_FLAGS_MBZ) != 0u)) {
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

void wt_ffa_direct_clear_sbz(uint64_t* x)
{
    uint32_t fid = (uint32_t)x[0];

    if (fid == WT_FFA_MSG_SEND_DIRECT_REQ2) {
        return;
    }
    x[2] = 0u;
    if (fid == WT_FFA_MSG_SEND_DIRECT_RESP2) {
        x[3] = 0u;
    }
}

int wt_ffa_run_target(uint32_t w1, uint16_t* id)
{
    *id = (uint16_t)(w1 >> 16);
    return ((w1 & 0xFFFFu) == 0u) ? 0 : WT_FFA_INVALID_PARAMETERS;
}

int wt_ffa_run_busy_check(uint16_t requester, uint16_t caller,
                          unsigned int yielded, unsigned int preempted)
{
    if ((requester != caller) || ((yielded == 0u) && (preempted == 0u))) {
        return WT_FFA_DENIED;
    }
    return 0;
}

void wt_ffa_msg_deliver(uint64_t* x, const uint64_t* msg)
{
    uint32_t call = (uint32_t)x[0];
    unsigned int count = wt_ffa_msg_reg_count(msg[0]);
    unsigned int i;

    for (i = 0u; i < count; i++) {
        x[i] = msg[i];
    }
    if (count == WT_FFA_MSG_REGS) {
        wt_ffa_reply_clear_ext(call, x);
    }
}

#define WT_FFA_FWK_SPMD_TO_SPMC \
    (((uint32_t)WT_FFA_ID_SPMD << 16) | (uint32_t)WT_FFA_ID_SPMC)
#define WT_FFA_FWK_SPMC_TO_SPMD \
    (((uint32_t)WT_FFA_ID_SPMC << 16) | (uint32_t)WT_FFA_ID_SPMD)

void wt_ffa_fwk_version_req(uint64_t* x, uint32_t version)
{
    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_SPMD,
                        WT_FFA_ID_SPMC, NULL);
    x[2] = WT_FFA_FWK_VERSION_REQ;
    x[3] = version;
}

int wt_ffa_fwk_version_is_req(const uint64_t* x)
{
    return ((uint32_t)x[0] == WT_FFA_MSG_SEND_DIRECT_REQ32) &&
           ((uint32_t)x[1] == WT_FFA_FWK_SPMD_TO_SPMC) &&
           ((uint32_t)x[2] == WT_FFA_FWK_VERSION_REQ);
}

void wt_ffa_fwk_version_resp(uint64_t* x, int32_t result)
{
    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_RESP32, WT_FFA_ID_SPMC,
                        WT_FFA_ID_SPMD, NULL);
    x[2] = WT_FFA_FWK_VERSION_RESP;
    x[3] = (uint64_t)(uint32_t)result;
}

int32_t wt_ffa_fwk_version_result(const uint64_t* x)
{
    if (((uint32_t)x[0] != WT_FFA_MSG_SEND_DIRECT_RESP32) ||
        ((uint32_t)x[1] != WT_FFA_FWK_SPMC_TO_SPMD) ||
        ((uint32_t)x[2] != WT_FFA_FWK_VERSION_RESP)) {
        return (int32_t)WT_FFA_NOT_SUPPORTED;
    }
    return (int32_t)(uint32_t)x[3];
}

static uint32_t msg2_read32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void msg2_write32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

uint32_t wt_ffa_msg2_header_size(uint32_t version)
{
    return (version >= WT_FFA_VERSION_1_2) ? WT_FFA_MSG2_HEADER_SIZE :
                                             WT_FFA_MSG2_HEADER_SIZE_V1_1;
}

int wt_ffa_msg2_parse(const uint8_t* tx, uint32_t tx_size, uint16_t caller,
                      uint32_t version, wt_ffa_instance_t inst, uint32_t w1,
                      uint32_t w2, wt_ffa_msg2_t* out)
{
    uint32_t hdr = wt_ffa_msg2_header_size(version);
    uint32_t sender_receiver;
    unsigned int i;

    if ((tx == NULL) || (out == NULL) || (tx_size < hdr)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* Table 15.3: w1 bits 15:0 and the w2 flags other than the delay-SRI hint
     * are SBZ; the w1 sender is MBZ and w2 is ignored at the SVC conduit; the
     * hint is MBZ outside the Secure virtual instance (16.5.1). */
    if (inst == WT_FFA_INSTANCE_NS_PHYSICAL) {
        if (((w2 & WT_FFA_MSG2_FLAG_DELAY_SRI) != 0u) ||
            (((w1 >> 16) != 0u) && ((uint16_t)(w1 >> 16) != caller))) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }
    else if ((w1 >> 16) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    out->offset = msg2_read32(&tx[8]);
    sender_receiver = msg2_read32(&tx[12]);
    out->size = msg2_read32(&tx[16]);
    for (i = 0u; i < 16u; i++) {
        out->uuid[i] = (hdr == WT_FFA_MSG2_HEADER_SIZE) ? tx[24u + i] : 0u;
    }
    out->sender = (uint16_t)(sender_receiver >> 16);
    out->receiver = (uint16_t)(sender_receiver & 0xFFFFu);
    if (out->sender != caller) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (out->sender == out->receiver) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((out->offset < hdr) ||
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

uint32_t wt_ffa_msg2_rx_offset(const wt_ffa_msg2_t* msg, uint32_t version)
{
    uint32_t hdr = wt_ffa_msg2_header_size(version);

    return (msg->offset < hdr) ? hdr : msg->offset;
}

void wt_ffa_msg2_copy(uint8_t* rx, uint32_t rx_size, uint32_t version,
                      const uint8_t* tx, const wt_ffa_msg2_t* msg)
{
    uint32_t hdr = wt_ffa_msg2_header_size(version);
    uint32_t off = wt_ffa_msg2_rx_offset(msg, version);
    uint32_t i;

    for (i = 0u; i < rx_size; i++) {
        if ((i >= off) && ((i - off) < msg->size)) {
            rx[i] = tx[msg->offset + (i - off)];
        }
        else {
            rx[i] = 0u;
        }
    }
    if (rx_size >= hdr) {
        msg2_write32(&rx[8], off);
        msg2_write32(&rx[12], ((uint32_t)msg->sender << 16) |
                              (uint32_t)msg->receiver);
        msg2_write32(&rx[16], msg->size);
        if (hdr == WT_FFA_MSG2_HEADER_SIZE) {
            for (i = 0u; i < 16u; i++) {
                rx[24u + i] = msg->uuid[i];
            }
        }
    }
}
