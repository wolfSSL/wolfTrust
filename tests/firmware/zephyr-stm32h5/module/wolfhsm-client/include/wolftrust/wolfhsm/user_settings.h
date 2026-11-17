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

/* wolfCrypt settings for the wolfTrust Zephyr non-secure guest.
 *
 * Compiled in via -DWOLFSSL_USER_SETTINGS. wolfPSA pulls in its own
 * user_settings (wolfPSA's wolfpsa/user_settings.h is loaded by the
 * wolfPSA module on the same compile path) — both must agree on the
 * primitive set wolfCrypt compiles in. Mirror tests/firmware/stm32h563/
 * nonsecure/user_settings.h with the heap-related guest-isms removed
 * (Zephyr's libc owns malloc/free; we don't pull in any local heap). */

#ifndef WOLFTRUST_ZEPHYR_USER_SETTINGS_H
#define WOLFTRUST_ZEPHYR_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define SIZEOF_LONG_LONG 8

/* SP math layer matching the secure side. */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_DYN_STACK
#define ECC_TIMING_RESISTANT

/* ECC P-256 only — secure side accepts no other curves. */
#define HAVE_ECC
#define ECC_USER_CURVES
#define NO_ECC192
#define NO_ECC224
#define NO_ECC384
#define NO_ECC521

/* AES-CTR counter mode (needed by wolfPSA's PSA_ALG_CTR path). The
 * secure-side wolfHSM crypto_cb already serves CTR via the same
 * wc_AesCtrEncrypt code path it uses for CBC. */
#define WOLFSSL_AES_COUNTER
/* wolfPSA requires constant-time AES; the Thumb-2 assembly is T-table. */
#define WOLFSSL_AES_TOUCH_LINES
#define WC_ALLOW_ECC_ZERO_HASH

/* AEAD for the PSA aead_* surface (dev_apis crypto); same GCM code the
 * secure-side vault sealer already runs on this core. */
#define HAVE_AESGCM
/* wolfPSA's multipart GCM runs on the wolfCrypt GCM streaming calls. */
#define WOLFSSL_AESGCM_STREAM
#define HAVE_AESCCM
/* wolfPSA's multipart CCM runs on the direct AES block calls. */
#define WOLFSSL_AES_DIRECT

/* SHA-256 only. */
#define NO_SHA

/* HMAC enabled (NO_HMAC absent); HKDF too. HAVE_PBKDF2 is wolfPSA's KDF
 * gate — wc_PBKDF2 itself is already in via pwdbased.c. WOLFSSL_HAVE_PRF
 * backs wolfPSA's TLS-1.2 PRF KDF, whose wc_PRF_TLS call is unguarded. */
#define HAVE_HKDF
#define HAVE_PBKDF2
#define WOLFSSL_HAVE_PRF

/* HashDRBG with secure-side entropy. The wolfHSM client crypto_cb routes
 * RNG requests to the secure HSM; for the CUSTOM_RAND_GENERATE_BLOCK
 * hook wolfCrypt may also call into, see wolfhsm_client_glue.c. */
#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wolftrust_guest_rng_stub

#ifndef WOLFTRUST_GUEST_RNG_STUB_DECLARED
#define WOLFTRUST_GUEST_RNG_STUB_DECLARED
#ifdef __cplusplus
extern "C" {
#endif
int wolftrust_guest_rng_stub(unsigned char *output, unsigned int sz);
#ifdef __cplusplus
}
#endif
#endif /* WOLFTRUST_GUEST_RNG_STUB_DECLARED */

#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define NO_PKCS12
#define NO_ASN_TIME

#endif /* WOLFTRUST_ZEPHYR_USER_SETTINGS_H */
