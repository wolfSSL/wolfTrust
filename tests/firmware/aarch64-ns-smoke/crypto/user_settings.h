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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* wolfCrypt for the bare-metal Normal-world conformance guest: the algorithm
 * set wolfPSA needs for the Arm dev_apis crypto and attestation suites. */

#ifndef WT_NS_GUEST_USER_SETTINGS_H
#define WT_NS_GUEST_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define NO_ASN_TIME
#define NO_ERROR_STRINGS
#define WOLFSSL_IGNORE_FILE_WARN
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_PSA_ENGINE
#define WOLFPSA_CUSTOM_STORE

/* C-only 64-bit SP math: the guest builds with -mgeneral-regs-only. */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_384
#define HAVE_SP_ECC
#define SP_WORD_SIZE 64
#define HAVE___UINT128_T 1
#define WOLFSSL_SP_NO_DYN_STACK

#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_SEED wt_ns_generate_seed
int wt_ns_generate_seed(unsigned char* output, unsigned int sz);

#define RSA_MIN_SIZE 1024
#define WOLFSSL_KEY_GEN
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_RSA_OAEP

#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT
#define WOLFSSL_ECDSA_DETERMINISTIC_K

#define WOLFSSL_HAVE_PRF
#define HAVE_HKDF
#define HAVE_PBKDF2
#define WOLFSSL_MD5
#define WOLFSSL_RIPEMD
#define WOLFSSL_SHA224
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#undef NO_MD5
#undef NO_DES3
#define WOLFSSL_DES3
#define WOLFSSL_DES_ECB

#define HAVE_AESGCM
#define GCM_SMALL
#define HAVE_AESCCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_OFB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC
#define HAVE_CHACHA
#define HAVE_POLY1305

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DH
#define NO_PKCS12

#endif /* WT_NS_GUEST_USER_SETTINGS_H */
