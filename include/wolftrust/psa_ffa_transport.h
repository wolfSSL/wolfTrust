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

/* Architecture-neutral contract for the register-only PSA client transport.
 * The client (src/client/psa_ffa_transport.c) marshals each PSA framework
 * operation into (op, arg0, arg1) and hands it to the architecture primitive
 * wt_psa_ffa_op; the FF-A/SMC binding lives in src/arch/<arch>/. */

#define WT_PSA_FFA_OP_FRAMEWORK_VERSION 1u
#define WT_PSA_FFA_OP_SERVICE_VERSION   2u
#define WT_PSA_FFA_OP_CONNECT           3u
#define WT_PSA_FFA_OP_CLOSE             4u

/* A register-only service the transport proof connects to; the SPMC answers
 * ServiceVersion/Connect/Close for it with no backing partition. */
#define WT_PSA_FFA_SID_TEST             0x1005u
#define WT_PSA_FFA_SID_TEST_VERSION     1u

/* Fixed connection table in the SPMC (no allocation) and a bound on the
 * preemption resume loop the transport hides. */
#define WT_PSA_FFA_MAX_CONN             8u
#define WT_PSA_FFA_MAX_RESUME           16u

/* Carry one register-only PSA framework operation to the SPMC and return its
 * result. Returns 0 with *result set, or -1 on a transport error. */
int wt_psa_ffa_op(uint32_t op, uint32_t a0, uint32_t a1, uint32_t* result);

#endif /* WOLFTRUST_PSA_FFA_TRANSPORT_H */
