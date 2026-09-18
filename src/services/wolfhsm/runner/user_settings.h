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

#ifndef WOLFTRUST_SECURE_USER_SETTINGS_H
#define WOLFTRUST_SECURE_USER_SETTINGS_H

/*
 * wolfTrust secure-side wolfCrypt configuration.
 *
 * Compiled with -DWOLFSSL_USER_SETTINGS so wolfSSL headers pick up this file
 * in place of the auto-detected options.  Targets the STM32H563 Cortex-M33
 * secure world; built with -mgeneral-regs-only (no FPU/SIMD in compiler
 * output), no OS, no dynamic allocator, single-threaded execution model.
 *
 * Supported primitives:
 *   - ECC P-256  (keygen, sign, verify, ECDH)
 *   - AES-CBC
 *   - SHA-256
 *   - HMAC-SHA-256  (required by wolfHSM HKDF paths)
 *   - HKDF          (required by wolfHSM key-derivation paths)
 *   - HashDRBG RNG  (seeded from the STM32H5 hardware RNG via wolfHAL)
 */

/* -------------------------------------------------------------------------
 * Disable the TLS/SSL layer — wolfCrypt primitives only.
 * ---------------------------------------------------------------------- */
#define WOLFCRYPT_ONLY
#define NO_CRYPT_BENCHMARK

/* -------------------------------------------------------------------------
 * No heap.
 *
 * The secure wolfHSM profile keeps server, NVM and crypto working state in
 * static or stack-owned objects. NO_WOLFSSL_MEMORY avoids wolfSSL's allocator
 * layer entirely, while WOLFSSL_NO_MALLOC makes any accidental XMALLOC path
 * fail closed instead of requiring malloc/sbrk or a static heap arena.
 * NO_STDLIB_H and NO_STRING_H keep the freestanding Cortex-M build
 * independent of libc headers; the linked local stubs provide these calls.
 * ---------------------------------------------------------------------- */
#define NO_WOLFSSL_MEMORY
#define WOLFSSL_NO_MALLOC
#define NO_STDLIB_H
#define NO_STRING_H
#define NO_CTYPE_H
#define WOLFSSL_NO_ASSERT_H

#include "libc_stubs.h"

/* -------------------------------------------------------------------------
 * Threading model: single-threaded from wolfCrypt's perspective.
 * Each per-guest server context is touched only by its own coroutine;
 * wolfCrypt operations on one context never race with another.
 * ---------------------------------------------------------------------- */
#define SINGLE_THREADED

/* -------------------------------------------------------------------------
 * No OS services.
 * ---------------------------------------------------------------------- */
#define NO_FILESYSTEM
#define NO_STDIO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO     /* no BSD socket I/O callbacks needed          */
#define NO_WRITEV

/* -------------------------------------------------------------------------
 * Compiler / ABI hints for ARM Cortex-M (32-bit, no FPU in use).
 * sizeof(long long) == 8 on all ARM-M targets; spell it out explicitly so
 * wolfCrypt's MP math layers don't have to probe the compiler.
 * ARMASM is a separate set of Thumb2 AES/SHA software assembly routines; it is
 * selected by the architecture build flags, not here.
 * ---------------------------------------------------------------------- */
#define SIZEOF_LONG_LONG 8

/* -------------------------------------------------------------------------
 * Math backend: SP Cortex-M.
 *
 * ARMv8-M builds link wolfCrypt's sp_cortexm.c and define
 * WOLFSSL_SP_ARM_CORTEX_M_ASM from the Makefile. WOLFSSL_SP_SMALL avoids the
 * larger generic MP temporaries that TFM needed on coroutine stacks.
 * ---------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_DYN_STACK
#define ECC_TIMING_RESISTANT

/* -------------------------------------------------------------------------
 * ECC P-256 only.
 *
 * ECC_USER_CURVES switches off "all curves enabled by default" mode and
 * lets us opt in per-curve.  With ECC_USER_CURVES active, every curve is
 * disabled unless its NO_ECCxxx macro is absent — P-256 (NO_ECC256) is
 * absent here, so it remains enabled.  All other standard sizes are
 * explicitly suppressed.
 *
 * HAVE_ECC_SIGN / HAVE_ECC_VERIFY / HAVE_ECC_KEY_IMPORT /
 * HAVE_ECC_KEY_EXPORT are set automatically by settings.h when HAVE_ECC
 * is defined; we do not need to re-declare them here.
 * ---------------------------------------------------------------------- */
#define HAVE_ECC
#define ECC_USER_CURVES
/* P-256 (NO_ECC256 absent)  — enabled */
#define NO_ECC192
#define NO_ECC224
#define NO_ECC384
#define NO_ECC521

/* -------------------------------------------------------------------------
 * AES-GCM for the vault sealer (WT-FFM-0048). GCM_SMALL keeps the GHASH
 * tables out of flash; sealed-storage writes are rare, so speed is moot.
 * ---------------------------------------------------------------------- */
#define HAVE_AESGCM
#define GCM_SMALL

/* -------------------------------------------------------------------------
 * Hash: SHA-256.
 * SHA-256 is compiled in by default; we only need to ensure we do NOT
 * define NO_SHA256.  Legacy SHA-1 is explicitly disabled.
 * ---------------------------------------------------------------------- */
#define NO_SHA          /* disable legacy SHA-1 */
/* SHA-256 enabled (NO_SHA256 absent)  */

/* -------------------------------------------------------------------------
 * HMAC and HKDF.
 *
 * wolfHSM's wh_server_crypto.c includes <wolfssl/wolfcrypt/hmac.h>
 * unconditionally and calls wc_HKDF() inside #ifdef HAVE_HKDF blocks.
 * wc_HKDF() is declared inside #ifndef NO_HMAC / #ifdef HAVE_HKDF in
 * hmac.h, so both macros must be satisfied.  Leave NO_HMAC undefined.
 * ---------------------------------------------------------------------- */
#define HAVE_HKDF

/* -------------------------------------------------------------------------
 * RNG: HashDRBG backend.
 *
 * HAVE_HASHDRBG selects the wolfCrypt HashDRBG engine.  The DRBG requires
 * an entropy source supplied via CUSTOM_RAND_GENERATE_BLOCK.
 * ---------------------------------------------------------------------- */
#define HAVE_HASHDRBG

/*
 * Map wolfCrypt's entropy hook to the port TRNG.  The actual symbol must be
 * defined (with external linkage) in exactly one .c file before any call
 * to wc_InitRng() or wc_RNG_GenerateBlock().
 */
#define CUSTOM_RAND_GENERATE_BLOCK  wolftrust_rng_generate_block

/*
 * Forward declaration so translation units that include this header can
 * see the prototype without needing a separate header.
 */
#ifndef WOLFTRUST_RNG_GENERATE_BLOCK_DECLARED
#define WOLFTRUST_RNG_GENERATE_BLOCK_DECLARED
#ifdef __cplusplus
extern "C" {
#endif
int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
#ifdef __cplusplus
}
#endif
#endif /* WOLFTRUST_RNG_GENERATE_BLOCK_DECLARED */

/* -------------------------------------------------------------------------
 * Disabled algorithms — keep the binary small and the attack surface
 * minimal.  wolfHSM server_crypto.c gates each algorithm on its own
 * HAVE_xxx / NO_xxx guard so unused paths drop out cleanly.
 * ---------------------------------------------------------------------- */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define NO_PWDBASED
#define NO_PKCS12
#define NO_CODING       /* base-64 encode/decode not needed                */
#define NO_ASN_TIME     /* no RTC on secure side                           */

/* -------------------------------------------------------------------------
 * Explicitly keep side-channel hardening ON (WC_NO_HARDEN is left
 * undefined).  The constant-time ECC ladder costs a few extra cycles but
 * is mandatory for a hardware security module.
 * ---------------------------------------------------------------------- */

#endif /* WOLFTRUST_SECURE_USER_SETTINGS_H */
