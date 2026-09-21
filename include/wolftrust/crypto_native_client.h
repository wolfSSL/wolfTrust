/* crypto_native_client.h
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

#ifndef WOLFTRUST_CRYPTO_NATIVE_CLIENT_H
#define WOLFTRUST_CRYPTO_NATIVE_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#include "psa/error.h"
#include "wolftrust/services/crypto_native.h"

/* Non-secure client for the native crypto wire (WT_ENGINE=native): each
 * request is one synchronous psa_call to the SERVICE_HSM door carrying
 * [wt_crypto_wire_req_t][payload]; the response is [int32_t status][payload].
 * The connection is made lazily and healed on demand, mirroring the wolfHSM
 * client glue's restart tolerance. */

/* One native wire round trip. out may be NULL when the op returns no
 * payload. Returns the secure-side psa_status_t, or a client-side
 * PSA_ERROR_* when the door is unreachable. */
psa_status_t wt_crypto_native_call(const wt_crypto_wire_req_t* hdr,
                                   const uint8_t* payload,
                                   size_t payload_len, uint8_t* out,
                                   size_t out_cap, size_t* out_len);

/* Vault-domain randomness over the wire, chunked to WT_CRYPTO_RANDOM_MAX. */
psa_status_t wt_crypto_native_random(uint8_t* out, size_t len);

/* wolfCrypt CUSTOM_RAND_GENERATE_BLOCK hook: NS DRBG seeds come from the
 * secure vault RNG, never a local entropy source. Returns 0 on success. */
int wolftrust_guest_rng_stub(unsigned char* output, unsigned int sz);

#endif /* WOLFTRUST_CRYPTO_NATIVE_CLIENT_H */
