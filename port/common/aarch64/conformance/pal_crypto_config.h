/** @file
 * Copyright (c) 2019-2025, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

/* Crypto test configuration for the wolfTrust STM32H563 guest, derived from
 * the Arm pal_crypto_config.h template. The enabled set mirrors exactly what
 * the guest wolfPSA/wolfCrypt build compiles in (module/wolfhsm-client
 * user_settings.h): SHA-256, HMAC, HKDF, PBKDF2, TLS-1.2 PRF, AES
 * CBC/CTR/GCM/CCM, ECC P-256 ECDSA/ECDH incl. RFC 6979. Everything absent
 * from that build (RSA, DES, ChaCha20, CMAC, SHA-1/224/384/512, PAKE) stays
 * off so the suite skips those vectors instead of failing on honest
 * NOT_SUPPORTED. */

#ifndef _PAL_CRYPTO_CONFIG_H_
#define _PAL_CRYPTO_CONFIG_H_

#define ARCH_TEST_RAW

#define ARCH_TEST_AES
#define ARCH_TEST_AES_128
#define ARCH_TEST_AES_192
#define ARCH_TEST_AES_256
#define ARCH_TEST_AES_512

#define ARCH_TEST_CIPHER
#define ARCH_TEST_CIPHER_MODE_CTR
#define ARCH_TEST_CIPHER_MODE_CBC
#define ARCH_TEST_CTR_AES
#define ARCH_TEST_CBC_AES
#define ARCH_TEST_CBC_AES_NO_PADDING
#define ARCH_TEST_CBC_NO_PADDING
#define ARCH_TEST_CBC_PKCS7

#define ARCH_TEST_HASH
#define ARCH_TEST_SHA256

#define ARCH_TEST_CCM
#define ARCH_TEST_GCM

#define ARCH_TEST_HMAC
#define ARCH_TEST_HKDF
#define ARCH_TEST_HKDF_EXTRACT
#define ARCH_TEST_HKDF_EXPAND
#define ARCH_TEST_PBKDF2
#define ARCH_TEST_TLS12_PRF
#define ARCH_TEST_TLS12_PSK_TO_MS
#define ARCH_TEST_TRUNCATED_MAC

#define ARCH_TEST_ECC
#define ARCH_TEST_ECC_CURVE_SECP256R1
#define ARCH_TEST_ECDH
#define ARCH_TEST_ECDSA
#define ARCH_TEST_DETERMINISTIC_ECDSA

#include "pal_crypto_config_check.h"

#endif /* _PAL_CRYPTO_CONFIG_H_ */
