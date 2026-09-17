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

#include <stddef.h>
#include <stdint.h>

#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/psa_ffa_transport.h"

/* AArch64 binding of the PSA client transport: the client op rides the payload
 * words of an FF-A direct request to WT_FFA_ID_PSA (op in w3, arguments in
 * x4/x5), and the SPMC answers with the result in w3 of the direct response.
 * The SPMC side is the AArch64 twin of the Armv8-M CMSE veneers: it hands each
 * operation to the neutral FF-M gateway (src/arch/common/ffm_gateway.c), whose
 * core copies a call's vectors itself (psa_read/psa_write) after the NS-window
 * checks below. */

/* SPMC-side handler: r holds the client's direct request on entry and the
 * direct response (or FFA_ERROR) on return. Returns 0 when it answered, -1 on
 * a malformed request. */
int wt_spm_psa_framework(wt_ffa_regs_t* r);

/* Record the Non-secure window [ns_lo, ns_hi) the SPMC may read a guest's
 * vectors from. Nothing is inside an unset window (fail closed). */
void wt_spm_psa_init(uint64_t ns_lo, uint64_t ns_hi);

/* 1 when [base, base+len) lies entirely inside the Non-secure window (an empty
 * span always does), else 0. The wt_arch_ns_check_* operations use it. */
int wt_spm_ns_window_ok(uintptr_t base, size_t len);

#if !defined(__aarch64__)
/* Host-test SMC seam: the fixture drives one client transaction to the SPMC. */
void wt_ffa_transport_smc(wt_ffa_regs_t* r);
#endif

#endif /* WOLFTRUST_ARCH_AARCH64_PSA_FFA_H */
