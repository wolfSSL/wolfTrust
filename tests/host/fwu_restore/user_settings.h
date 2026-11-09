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

/*
 * Minimal wolfCrypt configuration for the FWU restart-hook host test:
 * AES-256-GCM + SHA-256 + HashDRBG, no TLS, no ECC, no RSA.
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define WOLFSSL_USER_IO
#define NO_TLS

#define HAVE_AESGCM

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
#define NO_ERROR_STRINGS
#define NO_ERROR_QUEUE
#define NO_INLINE

/* Entropy: wolfCrypt uses /dev/urandom automatically on the host. */

#endif /* USER_SETTINGS_H */
