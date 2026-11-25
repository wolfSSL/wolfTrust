/* initial_attestation.h
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

#ifndef WOLFTRUST_SERVICES_INITIAL_ATTESTATION_H
#define WOLFTRUST_SERVICES_INITIAL_ATTESTATION_H

#include <stddef.h>
#include <stdint.h>

#include "wolftrust/boot_handoff.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/types.h"

#define WT_ATTEST_SUCCESS                 0
#define WT_ATTEST_ERROR_INVALID_ARGUMENT -3300
#define WT_ATTEST_ERROR_BUFFER_TOO_SMALL -3301
#define WT_ATTEST_ERROR_NOT_READY        -3302
#define WT_ATTEST_ERROR_CRYPTO           -3303

#define WT_ATTEST_CHALLENGE_SIZE_32 32u
#define WT_ATTEST_CHALLENGE_SIZE_48 48u
#define WT_ATTEST_CHALLENGE_SIZE_64 64u
#define WT_ATTEST_IAK_PUBLIC_KEY_SIZE 65u
#define WT_ATTEST_HMAC_KEY_SIZE 32u
#define WT_ATTEST_MAX_TOKEN_SIZE 640u

int wt_initial_attest_init(const wt_boot_handoff_t* handoff);

int wt_initial_attest_get_token_size(size_t challengeSize,
    size_t* tokenSize);

int wt_initial_attest_get_token(wt_guest_id_t guestId,
    const uint8_t* challenge, size_t challengeSize, uint8_t* token,
    size_t tokenCapacity, size_t* tokenSize);

#ifdef WT_ATTEST_KEY_hmac
/* WT_ATTEST_KEY=hmac: the port supplies the device's HMAC-SHA256 attestation
 * key, the one its verifier holds. Called with a privileged thread at boot
 * and on a partition restart; 0 fills key, anything else leaves no key. */
int wt_port_attest_hmac_key(uint8_t* key, size_t keySize);
#else
int wt_initial_attest_get_iak_public_key(uint8_t* publicKey,
    size_t publicKeyCapacity, size_t* publicKeySize);

/* Bind the token signer to SERVICE_HSM over FF-M IPC (isolation level 3):
 * the attestation partition holds no key material, so every signature and
 * the IAK public key come from the crypto partition's attestation door
 * (WT_HSM_OP_ATTEST_*). Until bound, the engine's local signer is used
 * (host suites, privileged bootstrap). The connection opens lazily. */
int wt_initial_attest_bind_hsm(wt_spm_transport_fn transport,
                               wt_ffm_runtime_t* runtime,
                               int32_t partition_id, uint32_t hsm_sid);

/* The SPM's recovery path reports a SERVICE_HSM restart here: the cached
 * connection is in the error state (WT-FFM-0017), so the next signature or
 * public-key request closes it and reconnects instead of calling a dead
 * handle, a PROGRAMMER ERROR the SPM would panic this partition for. */
void wt_initial_attest_hsm_restarted(void);
#endif /* WT_ATTEST_KEY_hmac */

#endif /* WOLFTRUST_SERVICES_INITIAL_ATTESTATION_H */
