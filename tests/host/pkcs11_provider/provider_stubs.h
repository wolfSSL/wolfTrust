/* provider_stubs.h
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

#ifndef WOLFTRUST_HOST_PKCS11_PROVIDER_STUBS_H
#define WOLFTRUST_HOST_PKCS11_PROVIDER_STUBS_H

#include "wolfpkcs11/pkcs11.h"

extern CK_FUNCTION_LIST g_provider_test_functions;
extern unsigned int g_provider_test_aligned;

#define C_Initialize           g_provider_test_functions.C_Initialize
#define C_Finalize             g_provider_test_functions.C_Finalize
#define C_GetInfo              g_provider_test_functions.C_GetInfo
#define C_GetSlotList          g_provider_test_functions.C_GetSlotList
#define C_GetSlotInfo          g_provider_test_functions.C_GetSlotInfo
#define C_GetTokenInfo         g_provider_test_functions.C_GetTokenInfo
#define C_GetMechanismList     g_provider_test_functions.C_GetMechanismList
#define C_GetMechanismInfo     g_provider_test_functions.C_GetMechanismInfo
#define C_InitToken            g_provider_test_functions.C_InitToken
#define C_InitPIN              g_provider_test_functions.C_InitPIN
#define C_SetPIN               g_provider_test_functions.C_SetPIN
#define C_OpenSession          g_provider_test_functions.C_OpenSession
#define C_CloseSession         g_provider_test_functions.C_CloseSession
#define C_CloseAllSessions     g_provider_test_functions.C_CloseAllSessions
#define C_GetSessionInfo       g_provider_test_functions.C_GetSessionInfo
#define C_Login                g_provider_test_functions.C_Login
#define C_Logout               g_provider_test_functions.C_Logout
#define C_CreateObject         g_provider_test_functions.C_CreateObject
#define C_CopyObject           g_provider_test_functions.C_CopyObject
#define C_DestroyObject        g_provider_test_functions.C_DestroyObject
#define C_GetObjectSize        g_provider_test_functions.C_GetObjectSize
#define C_GetAttributeValue    g_provider_test_functions.C_GetAttributeValue
#define C_SetAttributeValue    g_provider_test_functions.C_SetAttributeValue
#define C_FindObjectsInit      g_provider_test_functions.C_FindObjectsInit
#define C_FindObjects          g_provider_test_functions.C_FindObjects
#define C_FindObjectsFinal     g_provider_test_functions.C_FindObjectsFinal
#define C_EncryptInit          g_provider_test_functions.C_EncryptInit
#define C_Encrypt              g_provider_test_functions.C_Encrypt
#define C_EncryptUpdate        g_provider_test_functions.C_EncryptUpdate
#define C_EncryptFinal         g_provider_test_functions.C_EncryptFinal
#define C_DecryptInit          g_provider_test_functions.C_DecryptInit
#define C_Decrypt              g_provider_test_functions.C_Decrypt
#define C_DecryptUpdate        g_provider_test_functions.C_DecryptUpdate
#define C_DecryptFinal         g_provider_test_functions.C_DecryptFinal
#define C_DigestInit           g_provider_test_functions.C_DigestInit
#define C_Digest               g_provider_test_functions.C_Digest
#define C_DigestUpdate         g_provider_test_functions.C_DigestUpdate
#define C_DigestKey            g_provider_test_functions.C_DigestKey
#define C_DigestFinal          g_provider_test_functions.C_DigestFinal
#define C_SignInit             g_provider_test_functions.C_SignInit
#define C_Sign                 g_provider_test_functions.C_Sign
#define C_SignUpdate           g_provider_test_functions.C_SignUpdate
#define C_SignFinal            g_provider_test_functions.C_SignFinal
#define C_VerifyInit           g_provider_test_functions.C_VerifyInit
#define C_Verify               g_provider_test_functions.C_Verify
#define C_VerifyUpdate         g_provider_test_functions.C_VerifyUpdate
#define C_VerifyFinal          g_provider_test_functions.C_VerifyFinal
#define C_GenerateKey          g_provider_test_functions.C_GenerateKey
#define C_GenerateKeyPair      g_provider_test_functions.C_GenerateKeyPair
#define C_DeriveKey            g_provider_test_functions.C_DeriveKey
#define C_SeedRandom           g_provider_test_functions.C_SeedRandom
#define C_GenerateRandom       g_provider_test_functions.C_GenerateRandom

#endif /* WOLFTRUST_HOST_PKCS11_PROVIDER_STUBS_H */
