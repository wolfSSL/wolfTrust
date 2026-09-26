/* psa_ffa_transport.h
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

#ifndef WOLFTRUST_PSA_FFA_TRANSPORT_H
#define WOLFTRUST_PSA_FFA_TRANSPORT_H

#include <stdint.h>

/* Architecture-neutral wire contract of the PSA client transport over FF-A.
 * The operating-system-neutral client is src/client/psa_ffm_client.c (the same
 * one every Armv8-M guest links); the FF-A/SMC binding in src/arch/<arch>/
 * provides its WolfTrust_FFM_* entry points by marshalling each operation into
 * (op, arg0, arg1) for wt_psa_ffa_op, and the SPMC front-ends the neutral FF-M
 * gateway with them. */

#define WT_PSA_FFA_OP_FRAMEWORK_VERSION 1u
#define WT_PSA_FFA_OP_SERVICE_VERSION   2u
#define WT_PSA_FFA_OP_CONNECT           3u
#define WT_PSA_FFA_OP_CLOSE             4u
/* Call: arg0 = the Non-secure address of the client's wt_ffm_veneer_iovec_t,
 * arg1 = the handle in bits 31:0 and the call type in bits 63:32. */
#define WT_PSA_FFA_OP_CALL              5u

/* Bound on the preemption resume loop the transport hides. */
#define WT_PSA_FFA_MAX_RESUME           16u

/* Carry one PSA framework operation to the SPMC and return its result. The
 * arguments are 64-bit so a Call can pass the address of its vector block.
 * Returns 0 with *result set, or -1 on a transport error. */
int wt_psa_ffa_op(uint32_t op, uint64_t a0, uint64_t a1, uint32_t* result);

#endif /* WOLFTRUST_PSA_FFA_TRANSPORT_H */
