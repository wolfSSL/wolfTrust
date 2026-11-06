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

#ifndef WOLFTRUST_FREERTOS_PKCS11_USER_SETTINGS_H
#define WOLFTRUST_FREERTOS_PKCS11_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define SIZEOF_LONG_LONG 8
#define USE_WOLF_STRCASECMP
#define FREERTOS

/* Route wolfCrypt and wolfPKCS11 allocations through the FreeRTOS heap.
 * The application supplies realloc because heap_4 only exposes malloc/free. */
#define XMALLOC_USER

/* __ARM_EABI__ otherwise selects wolfTPM's POSIX sleep fallback before its
 * FreeRTOS case. Keep all waits on the guest scheduler. */
void wt_pkcs11_sleep_ms(unsigned int ms);
#define XSLEEP_MS(ms) wt_pkcs11_sleep_ms(ms)

#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
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
#define WOLFPKCS11_PBKDF2
#define WOLFSSL_HAVE_PRF
#define WOLFSSL_ECDSA_DETERMINISTIC_K

#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wolftrust_guest_rng_stub
#ifndef WOLFTRUST_GUEST_RNG_STUB_DECLARED
#define WOLFTRUST_GUEST_RNG_STUB_DECLARED
int wolftrust_guest_rng_stub(unsigned char *output, unsigned int sz);
#endif

#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define NO_PKCS12
#define NO_ASN_TIME

#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

#endif /* WOLFTRUST_FREERTOS_PKCS11_USER_SETTINGS_H */
