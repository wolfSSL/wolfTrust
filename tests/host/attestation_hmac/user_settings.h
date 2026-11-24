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

/* wolfCrypt for the HMAC attestation host test: SHA-256 and HMAC only, with
 * no curve and no big-number code, as the tiny Secure image links it. */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

#define WOLFCRYPT_ONLY
#define WOLFSSL_USER_IO
#define NO_TLS

#define NO_BIG_INT
#define WC_NO_RNG
#define NO_ASN
#define NO_CODING
#define NO_AES

#define NO_SHA
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
#define NO_PKCS7

#define WOLFSSL_USE_ALIGN
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_MAIN_DRIVER
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME
#define NO_ERROR_QUEUE
#define NO_INLINE

#endif /* USER_SETTINGS_H */
