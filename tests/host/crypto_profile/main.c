/* main.c
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

#include "wolfpkcs11/pkcs11.h"
#include "wolftrust/pkcs11_provider.h"
#include "wolftrust/pkcs11/pkcs11_wire.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/pkcs11_psa_transport.h"

#include <stdio.h>
#include <string.h>

extern CK_FUNCTION_LIST g_provider_test_functions;
extern unsigned int g_provider_test_calls;
static unsigned int transport_calls;
static unsigned int failures;

static void check(int condition, const char* name)
{
    printf("%s: WT-FFM-0059 %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) {
        failures++;
    }
}

int wt_pkcs11_psa_call(const uint8_t* request, size_t request_len,
    uint8_t* response, size_t response_cap, size_t* response_len)
{
    uint8_t copy[WT_PKCS11_MESSAGE_MAX];

    if (request_len > sizeof(copy)) {
        return -1;
    }
    transport_calls++;
    memcpy(copy, request, request_len);
    return wt_pkcs11_provider_dispatch(copy, request_len, response,
        response_cap, response_len, NULL);
}

static CK_RV mechanism_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism,
    CK_MECHANISM_INFO_PTR info)
{
    (void)slot;
    info->ulMinKeySize = 1;
    info->ulMaxKeySize = 256;
    info->flags = mechanism == CKM_ECDSA ? CKF_SIGN | CKF_VERIFY | CKF_WRAP :
                  CKF_DIGEST | CKF_ENCRYPT;
    return CKR_OK;
}

static CK_RV object_size(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
    CK_ULONG_PTR size)
{
    (void)session;
    (void)object;
    g_provider_test_calls++;
    *size = 17;
    return CKR_OK;
}

int main(void)
{
    CK_FUNCTION_LIST_PTR functions = NULL;
    CK_OBJECT_HANDLE object;
    CK_MECHANISM_INFO info;
    CK_MECHANISM_TYPE mechanisms[16];
    CK_MECHANISM mechanism = { CKM_SHA256_HMAC, NULL, 0 };
    CK_ULONG count = 16;
    CK_ULONG size = 0;
    CK_BYTE random[8];
    uint8_t request[12];
    uint8_t response[12];
    size_t response_len = 0;
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    unsigned int before;

    g_provider_test_functions.C_GetMechanismInfo = mechanism_info;
    g_provider_test_functions.C_GetObjectSize = object_size;
    check(C_GetFunctionList(&functions) == CKR_OK && functions != NULL,
          "function list preserves the PKCS11 ABI");
    if (functions == NULL) {
        return 1;
    }
    check(functions->C_Initialize(NULL) == CKR_OK,
          "selected initialization reaches the provider");
    check(functions->C_GenerateRandom(1, random, sizeof(random)) == CKR_OK,
          "selected RNG completes a proxy/provider round trip");
    before = transport_calls;
    check(functions->C_CopyObject(1, 1, NULL, 0, &object) ==
          CKR_FUNCTION_NOT_SUPPORTED && transport_calls == before,
          "disabled entry point makes no transport call");
    wt_pkcs11_writer_init(&writer, request, sizeof(request));
    wt_pkcs11_put_u32(&writer, WT_PKCS11_WIRE_MAGIC);
    wt_pkcs11_put_u32(&writer, WT_PKCS11_WIRE_VERSION);
    wt_pkcs11_put_u32(&writer, WT_P11_COPY_OBJECT);
    before = g_provider_test_calls;
    check(wt_pkcs11_psa_call(request, writer.used, response,
          sizeof(response), &response_len) == 0,
          "forged disabled request returns a response");
    wt_pkcs11_reader_init(&reader, response, response_len);
    (void)wt_pkcs11_get_u32(&reader);
    (void)wt_pkcs11_get_u32(&reader);
    check(wt_pkcs11_get_u32(&reader) == CKR_FUNCTION_NOT_SUPPORTED &&
          reader.error == 0 && reader.used == reader.length &&
          g_provider_test_calls == before,
          "provider refuses disabled operation before decoding/backend");
    check(functions->C_GetMechanismList(1, mechanisms, &count) == CKR_OK &&
          count == 2 && mechanisms[0] == CKM_SHA256 &&
          mechanisms[1] == CKM_ECDSA,
          "capability list excludes removed mechanisms");
#if WT_PROFILE_PKCS11_C_GetMechanismInfo
    check(functions->C_GetMechanismInfo(1, CKM_ECDSA, &info) == CKR_OK &&
          info.flags == (CKF_SIGN | CKF_VERIFY),
          "capability flags exclude disabled actions");
    check(functions->C_GetMechanismInfo(1, CKM_PKCS5_PBKD2, &info) ==
          CKR_MECHANISM_INVALID,
          "disabled mechanism information is refused");
#else
    check(functions->C_GetMechanismInfo(1, CKM_ECDSA, &info) ==
          CKR_FUNCTION_NOT_SUPPORTED,
          "removing public mechanism info preserves internal enumeration");
#endif
#if WT_PROFILE_PKCS11_C_GetObjectSize
    before = g_provider_test_calls;
    check(functions->C_GetObjectSize(1, 1, &size) == CKR_OK && size == 17 &&
          g_provider_test_calls == before + 1,
          "added operation reaches the backend");
#else
    before = transport_calls;
    check(functions->C_GetObjectSize(1, 1, &size) == CKR_FUNCTION_NOT_SUPPORTED &&
          transport_calls == before,
          "unselected operation keeps its typed stub");
#endif
    before = g_provider_test_calls;
    check(functions->C_SignInit(1, &mechanism, 1) == CKR_MECHANISM_INVALID &&
          g_provider_test_calls == before,
          "allowed operation cannot use a disabled mechanism");
    return failures != 0;
}
