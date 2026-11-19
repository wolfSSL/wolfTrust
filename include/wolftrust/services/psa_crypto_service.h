/* psa_crypto_service.h
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

#ifndef WOLFTRUST_SERVICES_PSA_CRYPTO_SERVICE_H
#define WOLFTRUST_SERVICES_PSA_CRYPTO_SERVICE_H

#include <stdint.h>
#include <stddef.h>

#include "wolftrust/services/psa_crypto_wire.h"

/* Initialise wolfPSA and the slot tables in the crypto partition's band.
 * Privileged bootstrap only: boot and every partition restart. */
int wt_psa_service_init(void);

/* Serve one WT_CRYPTO_OP_PSA packet for client. owner is the crypto
 * partition's vault namespace; out receives [wt_psa_wire_ret_t][outputs]. */
psa_status_t wt_psa_service_call(int32_t owner, int32_t client,
                                 const wt_crypto_wire_req_t* hdr,
                                 const uint8_t* payload, size_t payload_len,
                                 uint8_t* out, size_t out_cap,
                                 size_t* out_len);

#ifdef WT_PSA_POOL_STATS
/* Host measurement only: bytes held, one arena's peak since the last mark,
 * the top offset in any arena, and one client arena's bytes held. */
void wt_psa_pool_stats(size_t* in_use, size_t* peak, size_t* hwm);
void wt_psa_pool_stats_mark(void);
size_t wt_psa_pool_arena_in_use(size_t arena);
#endif

#endif /* WOLFTRUST_SERVICES_PSA_CRYPTO_SERVICE_H */
