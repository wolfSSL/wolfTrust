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

#ifndef WOLFTRUST_NS_USER_SETTINGS_H
#define WOLFTRUST_NS_USER_SETTINGS_H

/*
 * wolfTrust guest-side (non-secure) wolfCrypt configuration.
 *
 * Compiled with -DWOLFSSL_USER_SETTINGS so wolfSSL headers pick up this file
 * in place of the auto-detected options.  Targets the STM32H563 Cortex-M33
 * non-secure world; built with -mgeneral-regs-only (no FPU/SIMD in compiler
 * output), no OS, single-threaded execution model.
 *
 * The guest does NOT execute crypto locally.  Every wc_* call is routed
 * through the crypto-callback device registered via:
 *
 *   wc_CryptoCb_RegisterDevice(WH_DEV_ID, wh_Client_CryptoCb, ctx)
 *
 * to the secure-side wolfHSM server over the CMSE transport.  The wolfCrypt
 * API on the guest side is present only to provide type-compatible call sites;
 * actual computation happens in the secure world.
 *
 * Supported primitives (API level — execution is on the secure side):
 *   - ECC P-256  (keygen, sign, verify, ECDH)
 *   - AES-CBC
 *   - SHA-256
 *   - HMAC-SHA-256
 *   - HKDF
 *   - HashDRBG RNG  (delegated to HSM via crypto-cb; see RNG section below)
 *
 * RNG note: CUSTOM_RAND_GENERATE_BLOCK is mapped to wolftrust_guest_rng_stub,
 * defined in wolfhsm_client_glue.c.  After wolfhsm_guest_init() completes, the
 * hook delegates to the secure-side HSM client so benchmark and seed paths use
 * the same entropy source as crypto-cb RNG calls.  Before init it fails closed.
 */

/* -------------------------------------------------------------------------
 * Disable the TLS/SSL layer — wolfCrypt primitives only.
 * ---------------------------------------------------------------------- */
#define WOLFCRYPT_ONLY

/* -------------------------------------------------------------------------
 * Crypto callback device: every wc_* call is dispatched to the secure-side
 * HSM server through wh_Client_CryptoCb.  WOLF_CRYPTO_CB is passed on the
 * command line because wolfSSL only includes this file when compiler-side
 * user settings are enabled.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Memory model: the guest has a normal heap (malloc/free available through
 * the C runtime shim).  WOLFSSL_STATIC_MEMORY and WOLFSSL_NO_MALLOC are
 * intentionally left UNDEFINED.  If Wave 5C footprint measurements show the
 * heap footprint is too large we can revisit and add a bounded pool here.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Threading model: single-threaded from wolfCrypt's perspective.
 * ---------------------------------------------------------------------- */
#define SINGLE_THREADED

/* -------------------------------------------------------------------------
 * No OS services.
 * ---------------------------------------------------------------------- */
#define NO_FILESYSTEM
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

/* wolfHSM's pinned wolfCrypt callback ABI uses anonymous aggregates. Keep
 * that required dependency extension explicit when wolfTrust builds as C99. */
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

/* The guest links without a libc and strict C99 hides strcasecmp(). */
#define USE_WOLF_STRCASECMP

/* -------------------------------------------------------------------------
 * Math backend: SP Cortex-M.
 *
 * Must match the secure-side selection exactly so that the wolfCrypt API call
 * signatures (fp_int sizes, function prototypes) are identical on both sides.
 * ARMv8-M builds link wolfCrypt's sp_cortexm.c and define
 * WOLFSSL_SP_ARM_CORTEX_M_ASM from the Makefile.
 * ---------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_DYN_STACK
#define ECC_TIMING_RESISTANT

/* -------------------------------------------------------------------------
 * ECC P-256 only.
 *
 * ECC_USER_CURVES switches off "all curves enabled by default" mode.
 * P-256 (NO_ECC256 absent) remains enabled; all other standard sizes are
 * explicitly suppressed.  Must mirror the secure side so key handle types
 * and wire formats are compatible across the CMSE boundary.
 * ---------------------------------------------------------------------- */
#define HAVE_ECC
#define ECC_USER_CURVES
/* P-256 (NO_ECC256 absent)  — enabled */
#define NO_ECC192
#define NO_ECC224
#define NO_ECC384
#define NO_ECC521

/* -------------------------------------------------------------------------
 * Hash: SHA-256.
 * SHA-256 is compiled in by default; legacy SHA-1 is explicitly disabled.
 * ---------------------------------------------------------------------- */
#define NO_SHA          /* disable legacy SHA-1 */
/* SHA-256 enabled (NO_SHA256 absent) */

/* -------------------------------------------------------------------------
 * HMAC and HKDF.
 * Leave NO_HMAC undefined so HMAC-SHA-256 is available.
 * ---------------------------------------------------------------------- */
#define HAVE_HKDF

/* -------------------------------------------------------------------------
 * RNG: HashDRBG backend.
 *
 * HAVE_HASHDRBG selects the wolfCrypt HashDRBG engine.  The DRBG requires
 * an entropy source supplied via CUSTOM_RAND_GENERATE_BLOCK.
 *
 * On the guest side, RNG calls normally travel through the crypto-cb device to
 * the secure-side HSM.  wolfCrypt can also invoke CUSTOM_RAND_GENERATE_BLOCK
 * directly from benchmark/seed paths; the implementation in
 * wolfhsm_client_glue.c forwards those requests to wolfHSM once the client is
 * ready.
 * ---------------------------------------------------------------------- */
#define HAVE_HASHDRBG

/*
 * Map wolfCrypt's entropy hook to the guest stub.  A different name from the
 * secure side (wolftrust_rng_generate_block) is used deliberately to prevent
 * accidental cross-linking and to make the operational distinction clear.
 */
#define CUSTOM_RAND_GENERATE_BLOCK  wolftrust_guest_rng_stub

/*
 * Forward declaration so translation units that include this header can
 * see the prototype without needing a separate header.
 */
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

/* -------------------------------------------------------------------------
 * Disabled algorithms — keep the binary small and the attack surface
 * minimal.  Mirrors the secure-side selection so the HSM protocol does not
 * need to handle primitives the guest cannot request.
 * ---------------------------------------------------------------------- */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define NO_PWDBASED
#define NO_PKCS12
/* NO_CODING is intentionally NOT defined: the Makefile passes -UNO_CODING   */
/* to compile coding.c; base-64 support is retained for wolfHSM wire encoding */
#define NO_ASN_TIME     /* no RTC dependency on guest side                   */

/* -------------------------------------------------------------------------
 * Explicitly keep side-channel hardening ON (WC_NO_HARDEN is left
 * undefined).
 * ---------------------------------------------------------------------- */

#endif /* WOLFTRUST_NS_USER_SETTINGS_H */
