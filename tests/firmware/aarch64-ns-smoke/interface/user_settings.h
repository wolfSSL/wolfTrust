/* user_settings.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 */

#ifndef WOLFTRUST_AARCH64_INTERFACE_USER_SETTINGS_H
#define WOLFTRUST_AARCH64_INTERFACE_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define NO_ASN_TIME
#define NO_ERROR_STRINGS
#define SIZEOF_LONG_LONG 8
#define USE_WOLF_STRCASECMP
#define WC_RESEED_INTERVAL 1000000
#define XSLEEP_MS(ms) do { (void)(ms); } while (0)

#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define HAVE_SP_ECC
#define SP_WORD_SIZE 64
#define HAVE___UINT128_T 1
#define WOLFSSL_SP_NO_DYN_STACK
#define ECC_TIMING_RESISTANT

#define HAVE_ECC
#define ECC_USER_CURVES
#define NO_ECC192
#define NO_ECC224
#define NO_ECC384
#define NO_ECC521

#define NO_SHA
#define WOLFSSL_AES_COUNTER
#define HAVE_AESCTR
#define WOLFSSL_AES_CFB
#define HAVE_AESGCM
#define HAVE_AESCCM
#define HAVE_HKDF
#define HAVE_PBKDF2
#define WOLFSSL_HAVE_PRF
#define WOLFSSL_ECDSA_DETERMINISTIC_K

#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wolftrust_guest_rng_stub
int wolftrust_guest_rng_stub(unsigned char* output, unsigned int size);

#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define NO_PKCS12
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

#endif /* WOLFTRUST_AARCH64_INTERFACE_USER_SETTINGS_H */
