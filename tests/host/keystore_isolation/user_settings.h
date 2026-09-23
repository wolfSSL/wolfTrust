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
 * Minimal wolfSSL/wolfCrypt configuration for the wolfHSM host loopback test.
 * ECC P-256 only, SHA-256, HashDRBG, no TLS, no RSA, no DH, no AES.
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* wc_ecc_get_curve_idx_from_name() calls strcasecmp(); under strict -std=c99
 * glibc only declares it from <strings.h>, so pull it in for this host build. */
#include <strings.h>


/* -------------------------------------------------------------------------
 * wolfHSM mandatory wolfCrypt settings
 * ---------------------------------------------------------------------- */

/* CryptoCb framework required by wolfHSM */
#define WOLF_CRYPTO_CB

/* wolfHSM needs anonymous inline aggregates in wc_CryptoInfo */
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

/* Key generation support (needed for ECC keygen on server) */
#define WOLFSSL_KEY_GEN

/* ASN template required for wh_Client_EccMakeExportKey etc. */
#define WOLFSSL_ASN_TEMPLATE

/* -------------------------------------------------------------------------
 * wolfCrypt only — no TLS/SSL layer
 * ---------------------------------------------------------------------- */
#define WOLFCRYPT_ONLY
#define WOLFSSL_USER_IO
#define NO_TLS

/* Prevent functions from falling back to client cryptoCb when using
 * non-devId APIs on the server side */
#define WC_NO_DEFAULT_DEVID

/* -------------------------------------------------------------------------
 * Math library
 * ---------------------------------------------------------------------- */
#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define FP_MAX_BITS 4096

/* -------------------------------------------------------------------------
 * ECC — P-256 only
 * ---------------------------------------------------------------------- */
#define HAVE_ECC
#define ECC_USER_CURVES
/* Include only the P-256 (secp256r1) curve */
#define HAVE_ECC256
#define TFM_ECC256
#define ECC_SHAMIR

/* -------------------------------------------------------------------------
 * Hash / RNG
 * ---------------------------------------------------------------------- */
#define WOLFSSL_SHA256
/* HashDRBG (uses SHA-256 internally) */
#define HAVE_HASHDRBG
/* No extra SHA variants needed for this smoke test */
#define NO_SHA

/* -------------------------------------------------------------------------
 * Algorithms to disable
 * ---------------------------------------------------------------------- */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_AES
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED

/* PKCS#7 not needed for the smoke test */
#define NO_PKCS7
/* NOTE: NO_CERTS and NO_ASN cannot be set because wolfHSM uses DER key
 * serialisation internally (wc_EccPublicKeyToDer, wc_EccPrivateKeyDecode
 * etc. declared in asn_public.h and implemented in asn.c). */

/* -------------------------------------------------------------------------
 * Miscellaneous / footprint
 * ---------------------------------------------------------------------- */
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_MAIN_DRIVER
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME
#define NO_ERROR_STRINGS
#define NO_ERROR_QUEUE
#define NO_INLINE

/* Host has a real heap; do NOT use static memory */
/* (do not define WOLFSSL_STATIC_MEMORY) */

/* Entropy: wolfCrypt will use /dev/urandom automatically on Linux */

#endif /* USER_SETTINGS_H */
