#ifndef WOLFTRUST_FREERTOS_TPM_USER_SETTINGS_H
#define WOLFTRUST_FREERTOS_TPM_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define SIZEOF_LONG_LONG 8
#define USE_WOLF_STRCASECMP
#define FREERTOS
#define XMALLOC_USER

void wt_tpm_sleep_ms(unsigned int ms);
#define XSLEEP_MS(ms) wt_tpm_sleep_ms(ms)

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
#define WOLFSSL_AES_CFB
#define HAVE_AESGCM
#define HAVE_AESCCM
#define HAVE_HKDF
#define HAVE_PBKDF2
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

#endif /* WOLFTRUST_FREERTOS_TPM_USER_SETTINGS_H */
