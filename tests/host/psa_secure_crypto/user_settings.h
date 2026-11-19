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

/* Host mirror of the native Secure wolfCrypt base on portable C math; the
 * profile block is the runner's own. */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define WOLFSSL_USER_IO
#define NO_TLS
#define SINGLE_THREADED
#define HAVE_ECC
#define ECC_USER_CURVES
#define ECC_TIMING_RESISTANT
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_NO_DYN_STACK
#define HAVE_STRINGS_H
#define HAVE_AESGCM
#define HAVE_HKDF
#define WOLFSSL_SHA256
#define HAVE_HASHDRBG
#define NO_SHA
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PKCS7
#define NO_ASN_TIME
#define NO_ASN
#define NO_PWDBASED
#define NO_AES_DECRYPT
#define HAVE_AESGCM_DECRYPT
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_MAIN_DRIVER
#define NO_ERROR_STRINGS

#include "../../../src/services/wolfhsm/runner/secure_psa_profile.h"

#endif /* USER_SETTINGS_H */
