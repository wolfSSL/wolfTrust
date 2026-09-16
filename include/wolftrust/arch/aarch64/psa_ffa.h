/* psa_ffa.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_PSA_FFA_H
#define WOLFTRUST_ARCH_AARCH64_PSA_FFA_H

#include <stdint.h>

#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/psa_ffa_transport.h"

/* AArch64 binding for the register-only PSA transport: the client op is carried
 * in the payload words of an FF-A direct request to WT_FFA_ID_PSA (op in w3,
 * arguments in w4/w5), and the SPMC answers with the result in w3 of the direct
 * response. Data-carrying psa_call arrives with memory sharing (B4). */

/* SPMC-side register-only handler: r holds the client's direct request on
 * entry and the direct response (or FFA_ERROR) on return. Returns 0 when it
 * answered, -1 on a malformed request. */
int wt_spm_psa_framework(wt_ffa_regs_t* r);

/* Record the Non-secure window [ns_lo, ns_hi) the SPMC may read a guest's
 * psa_call buffers from; every iovec must fall entirely inside it. */
void wt_spm_psa_init(uint64_t ns_lo, uint64_t ns_hi);

/* Run one psa_call by SPMC-mediated copy: read the parameter block at
 * desc_addr, validate every iovec lies inside [ns_lo, ns_hi), copy the in-vecs
 * to the service, transform, copy the out-vecs back, and update their lengths.
 * Returns a psa_status_t. Split out so a host suite drives it with fixture
 * bounds. */
int32_t wt_psa_call_run(uint64_t desc_addr, uint64_t ns_lo, uint64_t ns_hi);

#if !defined(__aarch64__)
/* Host-test SMC seam: the fixture drives one client transaction to the SPMC. */
void wt_ffa_transport_smc(wt_ffa_regs_t* r);
#endif

#endif /* WOLFTRUST_ARCH_AARCH64_PSA_FFA_H */
