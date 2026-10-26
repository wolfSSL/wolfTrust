/* wolfCrypt + wolfPSA user_settings for the FreeRTOS NS guest (P7-S3).
 *
 * Satisfies WOLFSSL_USER_SETTINGS (wolfCrypt's compile-time config
 * trampoline) for the SPM-mediated guest: wolfPSA front-end, FF-M
 * entropy hook, no raw HSM transport. Mirrors the Zephyr
 * guest user_settings but with FREERTOS heap / port hooks turned on. */

#ifndef WOLFTRUST_FREERTOS_NS_USER_SETTINGS_H
#define WOLFTRUST_FREERTOS_NS_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define SIZEOF_LONG_LONG 8

/* FreeRTOS port hook — XMALLOC / XFREE etc. resolve to FreeRTOS heap_4
 * counterparts where applicable. */
#define FREERTOS

/* SP math layer matching the secure side. */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_DYN_STACK
#define ECC_TIMING_RESISTANT

/* ECC P-256 only — secure side speaks no other curve. */
#define HAVE_ECC
#define ECC_USER_CURVES
#define NO_ECC192
#define NO_ECC224
#define NO_ECC384
#define NO_ECC521

/* SHA-256 only; the mediated PSA crypto path has no SHA-1 caller. */
#define NO_SHA

/* AES-CBC + AES-CTR for the mediated PSA crypto path. */
#define WOLFSSL_AES_COUNTER

/* HMAC + HKDF kept on. */
#define HAVE_HKDF

/* DRBG + entropy hook. The wolfHSM client glue exports the RNG stub, which
 * draws entropy from the secure side over the SERVICE_HSM relay (WT-FFM-0054);
 * no raw NS-to-HSM transport. */
#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wolftrust_guest_rng_stub
#ifndef WOLFTRUST_GUEST_RNG_STUB_DECLARED
#define WOLFTRUST_GUEST_RNG_STUB_DECLARED
int wolftrust_guest_rng_stub(unsigned char *output, unsigned int sz);
#endif

/* Trim. */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define HAVE_PBKDF2
#define NO_PKCS12
#define NO_ASN_TIME

/* gcc supports anonymous unions/structs even under -std=c99 — wolfHSM
 * needs HAVE_ANONYMOUS_INLINE_AGGREGATES=1 explicitly because the
 * wolfCrypt auto-detect in types.h defaults it off for C99. */
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

#endif /* WOLFTRUST_FREERTOS_NS_USER_SETTINGS_H */
