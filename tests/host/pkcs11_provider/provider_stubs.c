/* provider_stubs.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 */

#include "wolfpkcs11/pkcs11.h"

#include <stdint.h>
#include <string.h>

unsigned int g_provider_test_calls;
unsigned int g_provider_test_aligned;
unsigned int g_provider_test_get_attribute_calls;
unsigned int g_provider_test_ecdh_valid;

static CK_RV test_init_pin(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin,
                           CK_ULONG pin_len)
{
    (void)session;
    (void)pin;
    (void)pin_len;
    g_provider_test_calls++;
    return CKR_FUNCTION_FAILED;
}

static CK_RV test_create_object(CK_SESSION_HANDLE session,
                                CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                                CK_OBJECT_HANDLE_PTR object)
{
    (void)session;
    g_provider_test_calls++;
    g_provider_test_aligned = count == 1U && attributes != NULL &&
        attributes[0].type == CKA_CLASS && attributes[0].pValue != NULL &&
        attributes[0].ulValueLen == sizeof(CK_OBJECT_CLASS) &&
        ((uintptr_t)attributes[0].pValue % sizeof(CK_ULONG)) == 0U;
    if (g_provider_test_aligned != 0U && object != NULL) {
        *object = 7U;
        return CKR_OK;
    }
    return CKR_ARGUMENTS_BAD;
}

static CK_RV test_encrypt_init(CK_SESSION_HANDLE session,
                               CK_MECHANISM_PTR mechanism,
                               CK_OBJECT_HANDLE key)
{
    (void)session;
    (void)mechanism;
    (void)key;
    g_provider_test_calls++;
    return CKR_FUNCTION_FAILED;
}

static CK_RV test_derive_key(CK_SESSION_HANDLE session,
                             CK_MECHANISM_PTR mechanism,
                             CK_OBJECT_HANDLE base_key,
                             CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                             CK_OBJECT_HANDLE_PTR key)
{
    static const uint8_t point[] = { 0x04U, 0x11U, 0x22U };
    CK_ECDH1_DERIVE_PARAMS* params = NULL;

    g_provider_test_calls++;
    if (mechanism != NULL && mechanism->mechanism == CKM_ECDH1_DERIVE &&
            mechanism->pParameter != NULL &&
            mechanism->ulParameterLen == sizeof(*params)) {
        params = (CK_ECDH1_DERIVE_PARAMS*)mechanism->pParameter;
    }
    g_provider_test_ecdh_valid = session == 1U && base_key == 12U &&
        attributes != NULL && count == 0U && key != NULL && params != NULL &&
        params->kdf == CKD_NULL && params->pSharedData == NULL &&
        params->ulSharedDataLen == 0U &&
        params->ulPublicDataLen == sizeof(point) &&
        params->pPublicData != NULL &&
        memcmp(params->pPublicData, point, sizeof(point)) == 0;
    if (g_provider_test_ecdh_valid == 0U) {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    *key = 7U;
    return CKR_OK;
}

static CK_RV test_get_attribute_value(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object,
                                      CK_ATTRIBUTE_PTR attributes,
                                      CK_ULONG count)
{
    static const uint8_t label[] = { 'k', 'e', 'y' };
    CK_ULONG i;
    CK_RV rv = CKR_OK;

    (void)session;
    (void)object;
    g_provider_test_get_attribute_calls++;
    for (i = 0U; i < count; i++) {
        if (attributes[i].type == CKA_PRIVATE_EXPONENT) {
            attributes[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            if (rv == CKR_OK) {
                rv = CKR_ATTRIBUTE_SENSITIVE;
            }
        }
        else if (attributes[i].type != CKA_LABEL) {
            attributes[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            if (rv == CKR_OK) {
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
            }
        }
        else if (attributes[i].pValue == NULL) {
            attributes[i].ulValueLen = sizeof(label);
        }
        else if (attributes[i].ulValueLen < sizeof(label)) {
            attributes[i].ulValueLen = sizeof(label);
            if (rv == CKR_OK) {
                rv = CKR_BUFFER_TOO_SMALL;
            }
        }
        else {
            (void)memcpy(attributes[i].pValue, label, sizeof(label));
            attributes[i].ulValueLen = sizeof(label);
        }
    }
    return rv;
}

CK_FUNCTION_LIST g_provider_test_functions = {
    .C_InitPIN = test_init_pin,
    .C_CreateObject = test_create_object,
    .C_GetAttributeValue = test_get_attribute_value,
    .C_EncryptInit = test_encrypt_init,
    .C_DeriveKey = test_derive_key
};
