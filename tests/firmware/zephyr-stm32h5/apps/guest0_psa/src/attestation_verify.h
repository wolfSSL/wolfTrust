/* attestation_verify.h
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

#ifndef WOLFTRUST_ATTESTATION_VERIFY_H
#define WOLFTRUST_ATTESTATION_VERIFY_H

#include <stddef.h>
#include <stdint.h>

int wt_attestation_verify(const uint8_t* token, size_t tokenSize,
    const uint8_t* publicKey, size_t publicKeySize,
    const uint8_t* challenge, size_t challengeSize,
    const char* expectedMeasurementHex, uint32_t expectedLifecycle,
    uint32_t* verifiedLifecycle);

/* As wt_attestation_verify, plus: a NULL or empty expectedMeasurementHex
 * skips the component-zero comparison (report-only mode), and a non-NULL
 * tokenMeasurement receives the 32-byte component-zero digest so the harness
 * can compare it against a reference held outside the image under test. */
int wt_attestation_verify_ex(const uint8_t* token, size_t tokenSize,
    const uint8_t* publicKey, size_t publicKeySize,
    const uint8_t* challenge, size_t challengeSize,
    const char* expectedMeasurementHex, uint32_t expectedLifecycle,
    uint32_t* verifiedLifecycle, uint8_t* tokenMeasurement);

#if defined(WT_GUEST_ATTEST_HMAC)
/* As wt_attestation_verify_ex for a COSE_Mac0 HMAC 256/256 token under a
 * 32-byte key, which must also derive the token's Instance ID. */
int wt_attestation_verify_mac0_ex(const uint8_t* token, size_t tokenSize,
    const uint8_t* key, size_t keySize,
    const uint8_t* challenge, size_t challengeSize,
    const char* expectedMeasurementHex, uint32_t expectedLifecycle,
    uint32_t* verifiedLifecycle, uint8_t* tokenMeasurement);
#endif

#endif /* WOLFTRUST_ATTESTATION_VERIFY_H */
