/* secure_psa_profile.h
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

/* wolfCrypt set for each WT_SECURE_PSA_PROFILE, shared by the Secure runner
 * and the host Secure PSA suite so both build the same algorithms. */

#ifndef WOLFTRUST_SECURE_PSA_PROFILE_H
#define WOLFTRUST_SECURE_PSA_PROFILE_H

/* The vault's AES AEAD, and the one PSA AEAD of lean and symmetric */
#if defined(WT_AEAD_GCM) && defined(WT_AEAD_CCM)
#error "WT_AEAD_GCM and WT_AEAD_CCM are exclusive"
#endif
#if defined(WT_SECURE_PSA_lean) || defined(WT_SECURE_PSA_symmetric)
#define WT_PSA_ONE_AEAD
#if !defined(WT_AEAD_GCM) && !defined(WT_AEAD_CCM)
#define WT_AEAD_CCM
#endif
#endif

#ifdef WT_SECURE_PSA
#if defined(WT_PSA_WANT_PROBE) && defined(WT_SECURE_PSA_symmetric)
/* The vault keeps ECC; the PSA_WANT_* surface of this profile does not. */
#undef HAVE_ECC
#endif
#define WC_ALLOW_ECC_ZERO_HASH
/* One copy of wolfCrypt's misc.c helpers, built by wolfPSA's misc_impl.c */
#define NO_INLINE
/* wolfPSA refuses T-table AES and a GHASH that branches on the hash key. */
#define WOLFSSL_AES_TOUCH_LINES
#undef GCM_SMALL
#define WOLFSSL_AES_COUNTER
#if !defined(WT_PSA_ONE_AEAD) || !defined(WT_AEAD_CCM)
/* wolfPSA's multipart GCM runs on the wolfCrypt GCM streaming calls. */
#define WOLFSSL_AESGCM_STREAM
#endif
#if !defined(WT_PSA_ONE_AEAD) || defined(WT_AEAD_CCM)
#define HAVE_AESCCM
/* wolfPSA's multipart CCM runs on the direct AES block calls. */
#define WOLFSSL_AES_DIRECT
#endif
#define HAVE_ECC_DHE
/* wolfPSA's direct P-256 path is randomized ECDSA only, so compat keeps ecc.c */
#ifndef WT_SECURE_PSA_compat
#define WOLFPSA_ECC_SP_DIRECT
#endif
#if defined(WT_SECURE_PSA_compat) || defined(WT_SECURE_PSA_standard)
#undef NO_AES_DECRYPT
#endif
#ifdef WT_SECURE_PSA_compat
#define HAVE_AES_ECB
#define WOLFSSL_ECDSA_DETERMINISTIC_K
#undef NO_PWDBASED
#define HAVE_PBKDF2
#define WOLFSSL_HAVE_PRF
#else
#define NO_AES_CBC
#define NO_PBKDF2
#define NO_KDF
#endif
#ifdef WT_PSA_POOL_TU
#define XMALLOC_OVERRIDE
void* wt_psa_pool_alloc(unsigned int sz);
void wt_psa_pool_free(void* p);
void* wt_psa_pool_realloc(void* p, unsigned int sz);
#define XMALLOC(s, h, t)     ((void)(h), (void)(t), wt_psa_pool_alloc((unsigned int)(s)))
#define XFREE(p, h, t)       do { (void)(h); (void)(t); wt_psa_pool_free(p); } while (0)
#define XREALLOC(p, n, h, t) ((void)(h), (void)(t), wt_psa_pool_realloc((p), (unsigned int)(n)))
#endif
#endif

#if defined(WT_AEAD_CCM) && !defined(HAVE_AESCCM)
#define HAVE_AESCCM
#endif
#ifdef WT_AEAD_CCM
/* wolfCrypt builds CCM decrypt only with HAVE_AES_DECRYPT; it runs AES forward */
#undef NO_AES_DECRYPT
#endif

#endif /* WOLFTRUST_SECURE_PSA_PROFILE_H */
