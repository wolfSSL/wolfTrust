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
 * negative FF-A status (INVALID_PARAMETERS for a malformed frame, DENIED for a
 * direction the instance does not relay). */
int wt_ffa_direct_req_check(const uint64_t* x, wt_ffa_instance_t inst);
int wt_ffa_direct_resp_check(const uint64_t* x, wt_ffa_instance_t inst);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_MSG_H */
