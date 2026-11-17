/* want_check.c
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

/* Compile-time check that each WT_SECURE_PSA_PROFILE advertises exactly the
 * PSA_WANT_* surface its service implements. */
#include "psa/crypto.h"

#if !defined(PSA_WANT_ALG_GCM) || !defined(PSA_WANT_ALG_HKDF) || \
    !defined(PSA_WANT_ALG_HMAC) || !defined(PSA_WANT_ALG_SHA_256)
#error "every profile advertises GCM, HKDF, HMAC and SHA-256"
#endif

#ifdef WT_SECURE_PSA_symmetric
#if defined(PSA_WANT_ALG_ECDSA) || defined(PSA_WANT_ALG_ECDH) || \
    defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA) || \
    defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC) || \
    defined(PSA_WANT_ECC_SECP_R1_256)
#error "symmetric advertises ECC"
#endif
#elif !defined(PSA_WANT_ALG_ECDSA) || !defined(PSA_WANT_ALG_ECDH) || \
    !defined(PSA_WANT_ECC_SECP_R1_256)
#error "the ECC profiles advertise P-256 ECDSA and ECDH"
#endif

#if defined(WT_SECURE_PSA_lean) || defined(WT_SECURE_PSA_symmetric)
#ifdef PSA_WANT_ALG_CCM
#error "lean and symmetric advertise CCM"
#endif
#elif !defined(PSA_WANT_ALG_CCM)
#error "compat and standard advertise CCM"
#endif

#ifdef WT_SECURE_PSA_compat
#if !defined(PSA_WANT_ALG_PBKDF2_HMAC) || !defined(PSA_WANT_ALG_CBC_NO_PADDING) || \
    !defined(PSA_WANT_ALG_TLS12_PRF) || \
    !defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#error "compat advertises PBKDF2, CBC, TLS 1.2 PRF and deterministic ECDSA"
#endif
#elif defined(PSA_WANT_ALG_PBKDF2_HMAC) || defined(PSA_WANT_ALG_CBC_NO_PADDING) || \
    defined(PSA_WANT_ALG_TLS12_PRF)
#error "only compat advertises PBKDF2, CBC and TLS 1.2 PRF"
#endif

typedef int wt_want_check_t;
