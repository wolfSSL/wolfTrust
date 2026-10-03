/* pal_attestation_config.h
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

/* Attestation PAL configuration for the unmodified Arm psa-arch-tests
 * dev_apis/initial_attestation suite. PLATFORM_OVERRIDE_ATTEST_PK stays
 * undefined: the wolfTrust IAK is generated inside the wolfHSM vault per
 * device, so the verify key must be fetched at runtime through
 * tfm_initial_attest_get_public_key (conformance_pal.c) rather than
 * baked in as upstream's well-known TF-M test key. */

#ifndef _PAL_ATTESTATION_CONFIG_H_
#define _PAL_ATTESTATION_CONFIG_H_

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_VERSION_BETA3

#define COSE_ALGORITHM_ES256             -7
#define COSE_ALG_SHA256_PROPRIETARY      -72000

#define USEFUL_BUF_MAKE_STACK_UB UsefulBuf_MAKE_STACK_UB

#define COSE_SIG_CONTEXT_STRING_SIGNATURE1 "Signature1"

#define T_COSE_SIGN1_MAX_PROT_HEADER (1 + 1 + 5 + 9)

#define T_COSE_SIZE_OF_TBS \
    (1 + sizeof(COSE_SIG_CONTEXT_STRING_SIGNATURE1) + 2 + \
     T_COSE_SIGN1_MAX_PROT_HEADER + 3)

#define NULL_USEFUL_BUF_C  NULLUsefulBufC

#define ECC_CURVE_SECP256R1_PULBIC_KEY_LENGTH   (1 + 2 * 32)

int32_t tfm_initial_attest_get_public_key(uint8_t *public_key_buff,
                                          size_t public_key_buf_size,
                                          size_t *public_key_len,
                                          psa_ecc_family_t *elliptic_family_type);

#endif /* _PAL_ATTESTATION_CONFIG_H_ */
