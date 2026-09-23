/* user_settings.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Minimal wolfCrypt configuration for the attestation COSE_Sign1 host test:
 * ECC P-256 + SHA-256 + HashDRBG + ASN, no TLS, matching what wolfCOSE ES256
 * sign/verify needs.
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* wc_ecc_get_curve_idx_from_name() calls strcasecmp(); under strict -std=c99
 * glibc only declares it from <strings.h>, so pull it in for this host build. */
#include <strings.h>

#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ASN_TEMPLATE

#define WOLFCRYPT_ONLY
#define WOLFSSL_USER_IO
#define NO_TLS

#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define FP_MAX_BITS 4096

#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define TFM_ECC256
#define ECC_SHAMIR

#define WOLFSSL_SHA256
#define HAVE_HASHDRBG
#define NO_SHA

#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
#define NO_PKCS7

#define WOLFSSL_USE_ALIGN
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_MAIN_DRIVER
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME
#define NO_ERROR_QUEUE
#define NO_INLINE

#endif /* USER_SETTINGS_H */
