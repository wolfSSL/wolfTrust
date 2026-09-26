/* ffa_msg.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_MSG_H
#define WOLFTRUST_ARCH_AARCH64_FFA_MSG_H

#include <stdint.h>

/* FF-A direct messaging (DEN0077A 15.2/15.3) and the relayer checks of 7.4.2.
 * A partition-message direct request/response carries its endpoint ids in w1
 * (sender in bits 31:16, receiver in 15:0), w2 SBZ (the framework bit in 31 is
 * clear for a partition message), and up to five implementation-defined
 * payload words in w3-w7 (SMC32) or x3-x7 (SMC64). */

#define WT_FFA_DIRECT_FRAMEWORK_BIT 0x80000000u
#define WT_FFA_DIRECT_PAYLOAD_WORDS 5u
/* Tables 15.7/15.11: a partition message clears the framework bit and the MBZ
 * bits 7:0 of w2; bits 30:8 are SBZ, ignored by the relayer. */
#define WT_FFA_DIRECT_FLAGS_MBZ (WT_FFA_DIRECT_FRAMEWORK_BIT | 0xFFu)

/* The instance a message is relayed at decides which world each endpoint is:
 * the SPMD relays Normal world to Secure, the SPMC relays partition to
 * partition. */
typedef enum wt_ffa_instance {
    WT_FFA_INSTANCE_NS_PHYSICAL = 0,
    WT_FFA_INSTANCE_SECURE_VIRTUAL
} wt_ffa_instance_t;

static inline uint16_t wt_ffa_direct_sender(uint64_t w1)
{
    return (uint16_t)(w1 >> 16);
}

static inline uint16_t wt_ffa_direct_receiver(uint64_t w1)
{
    return (uint16_t)(w1 & 0xFFFFu);
}

static inline int wt_ffa_id_is_secure(uint16_t id)
{
    return (id & 0x8000u) != 0u;
}

/* Build a 32-bit direct request or response into x[0..7]: x[0] = fid, w1 packs
 * the ids, w2 = 0, x[3..7] carry the five payload words (NULL clears them). */
void wt_ffa_direct_build(uint64_t* x, uint32_t fid, uint16_t sender,
                         uint16_t receiver, const uint32_t* payload);

/* Relayer validation (7.4.2): 0 if the message may be forwarded, else a
 * INVALID_PARAMETERS (15.2.1: a malformed frame or an endpoint id the instance
 * does not relay for). */
int wt_ffa_direct_req_check(const uint64_t* x, wt_ffa_instance_t inst);
int wt_ffa_direct_resp_check(const uint64_t* x, wt_ffa_instance_t inst);

/* Clear the SBZ fields of a checked partition message before it is handed to
 * its receiver: w2 of a REQ/RESP, x2/x3 of a RESP2 (a REQ2's are its UUID). */
void wt_ffa_direct_clear_sbz(uint64_t* x);

/* FFA_RUN target (14.3, Table 14.13): w1 bits 31:16 name the endpoint and bits
 * 15:0 its vCPU. Every endpoint here is UP with the single execution context 0
 * (4.7), so another vCPU id is INVALID_PARAMETERS (Table 14.14). */
int wt_ffa_run_target(uint32_t w1, uint16_t* id);

/* FFA_RUN of an endpoint busy with a direct request from requester: only that
 * requester may resume it, once it yielded (8.2) or a Non-secure interrupt
 * preempted it (9.3.1.1). Returns 0, else DENIED. */
int wt_ffa_run_busy_check(uint16_t requester, uint16_t caller,
                          unsigned int yielded, unsigned int preempted);

/* Write msg (x0-x7, or x0-x17 for REQ2/RESP2) into the saved registers x of
 * the call it answers, x[0] naming that call; an SMC64 caller's x8-x17 the
 * message does not fill come back zero (11.2). */
void wt_ffa_msg_deliver(uint64_t* x, const uint64_t* msg);

/* 13.2.3.2: the SPMD hands a Normal-world FFA_VERSION to an S-EL1 SPMC as a
 * framework direct request from the SPMD (Table 13.7, w3 = the version asked)
 * and the SPMC answers with a framework direct response (Table 13.8, w3 = the
 * FFA_VERSION result the Normal world is given). */
#define WT_FFA_FWK_VERSION_REQ  (WT_FFA_DIRECT_FRAMEWORK_BIT | 0x08u)
#define WT_FFA_FWK_VERSION_RESP (WT_FFA_DIRECT_FRAMEWORK_BIT | 0x09u)

void wt_ffa_fwk_version_req(uint64_t* x, uint32_t version);
int wt_ffa_fwk_version_is_req(const uint64_t* x);
void wt_ffa_fwk_version_resp(uint64_t* x, int32_t result);
/* The result a Table 13.8 response carries, or NOT_SUPPORTED for any other
 * message. */
int32_t wt_ffa_fwk_version_result(const uint64_t* x);

/* FFA_MSG_SEND2 (15.1): the partition message header at the start of the
 * sender's TX buffer. Table 7.2 lays out flags, a reserved word, the payload
 * offset, sender and receiver ids (sender bits 31:16), and the payload size;
 * that 20-byte form is the header of an endpoint that negotiated v1.0 or v1.1,
 * and a v1.2 endpoint's 40-byte header adds a reserved word and the
 * receiver's UUID. The flags and reserved words are SBZ: ignored here and
 * cleared in the receiver's copy. w1 bits 15:0 are SBZ. At the NS physical
 * instance w1 bits 31:16 name the sender and the delay-SRI hint in w2 bit 1
 * is MBZ (Secure virtual only, 16.5.1); at the secure virtual instance (the
 * SVC conduit) w1 bits 31:16 are MBZ and w2 is ignored (Table 15.3). */
#define WT_FFA_MSG2_HEADER_SIZE      40u
#define WT_FFA_MSG2_HEADER_SIZE_V1_1 20u
#define WT_FFA_MSG2_FLAG_DELAY_SRI (1u << 1)

/* The header as parsed: each field is read from the TX buffer once, so what
 * is validated is what is delivered even if the sender rewrites its TX. A
 * header without a UUID field parses as the Nil UUID. */
typedef struct wt_ffa_msg2 {
    uint32_t offset;
    uint32_t size;
    uint16_t sender;
    uint16_t receiver;
    uint8_t uuid[16];
} wt_ffa_msg2_t;

/* The header size of an endpoint at a negotiated FF-A version. */
uint32_t wt_ffa_msg2_header_size(uint32_t version);

/* Validate the header, in the layout of the version the caller negotiated,
 * against the caller and the TX bounds; the receiver's UUID is the caller's
 * to compare once the receiver is known. */
int wt_ffa_msg2_parse(const uint8_t* tx, uint32_t tx_size, uint16_t caller,
                      uint32_t version, wt_ffa_instance_t inst, uint32_t w1,
                      uint32_t w2, wt_ffa_msg2_t* out);

/* A header either names the receiver's UUID or leaves it Nil. */
int wt_ffa_msg2_uuid_ok(const uint8_t* header_uuid, const uint8_t* ep_uuid);

/* Where the payload lands in an RX whose owner negotiated version: the
 * sender's offset, moved past the receiver's header when it is shorter. The
 * relayer checks the result plus the size against the RX before the copy. */
uint32_t wt_ffa_msg2_rx_offset(const wt_ffa_msg2_t* msg, uint32_t version);

/* Produce a parsed message in the receiver's RX of rx_size bytes, in the
 * header layout of the version the receiver negotiated: the header is
 * written from msg (the sender being the caller the SPMC identified), the
 * payload is copied from tx to wt_ffa_msg2_rx_offset, every other byte is
 * cleared (7.2.2.3.2). */
void wt_ffa_msg2_copy(uint8_t* rx, uint32_t rx_size, uint32_t version,
                      const uint8_t* tx, const wt_ffa_msg2_t* msg);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_MSG_H */
