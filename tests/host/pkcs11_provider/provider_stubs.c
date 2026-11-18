/* provider_stubs.c
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

#include <stdint.h>
#include <string.h>

#define TEST_SLOT 1U
#define TEST_PIN_MAX 16U
#define TEST_PIN_MIN 4U
#define TEST_RO_SESSION 3U

unsigned int g_provider_test_calls;
unsigned int g_provider_test_aligned;
unsigned int g_provider_test_get_attribute_calls;
unsigned int g_provider_test_ecdh_valid;
unsigned int g_provider_test_pin_checks;
unsigned int g_provider_test_token_initialized = 1U;
unsigned int g_provider_test_open_output;
unsigned int g_provider_test_open_callbacks;
unsigned int g_provider_test_null_seen;
unsigned int g_provider_test_library_count = 1U;
CK_RV g_provider_test_after_pin_rv = CKR_OK;

/* Models wolfPKCS11 built with WOLFPKCS11_NO_TIME: no lockout of its own. */
static char g_so_pin[TEST_PIN_MAX] = "so-pin";
static char g_user_pin[TEST_PIN_MAX] = "user-pin";
static CK_ULONG g_state = CKS_RW_PUBLIC_SESSION;

static CK_RV test_initialize(CK_VOID_PTR args)
{
    (void)args;
    g_provider_test_library_count++;
    return CKR_OK;
}

static CK_RV test_finalize(CK_VOID_PTR reserved)
{
    if (g_provider_test_library_count == 0U) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (reserved != NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    g_provider_test_library_count--;
    if (g_provider_test_library_count == 0U) {
        g_provider_test_token_initialized = 0U;
    }
    return CKR_OK;
}

static CK_RV test_get_info(CK_INFO_PTR info)
{
    if (g_provider_test_library_count == 0U) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (info == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    (void)memset(info, 0, sizeof(*info));
    return CKR_OK;
}

static int test_session_valid(CK_SESSION_HANDLE session)
{
    return session == 1U || session == 2U || session == TEST_RO_SESSION;
}

static int test_pin_len_valid(CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
    return pin != NULL && pin_len >= TEST_PIN_MIN && pin_len < TEST_PIN_MAX;
}

static int test_logged_in(void)
{
    return g_state != CKS_RW_PUBLIC_SESSION;
}

static int test_pin_matches(const char* expected, CK_UTF8CHAR_PTR pin,
                            CK_ULONG pin_len)
{
    g_provider_test_pin_checks++;
    return pin != NULL && pin_len == (CK_ULONG)strlen(expected) &&
           memcmp(expected, pin, (size_t)pin_len) == 0;
}

static CK_RV test_store_pin(char* target, CK_UTF8CHAR_PTR pin,
                            CK_ULONG pin_len)
{
    if (pin == NULL || pin_len == 0U || pin_len >= TEST_PIN_MAX) {
        return CKR_PIN_LEN_RANGE;
    }
    (void)memcpy(target, pin, (size_t)pin_len);
    target[pin_len] = '\0';
    return CKR_OK;
}

static CK_RV test_get_mechanism_list(CK_SLOT_ID slot,
                                     CK_MECHANISM_TYPE_PTR mechanisms,
                                     CK_ULONG_PTR count)
{
    static const CK_MECHANISM_TYPE list[] = {
        CKM_SHA256, CKM_PKCS5_PBKD2, CKM_HKDF_DERIVE, CKM_ECDSA,
        CKM_TLS12_KEY_AND_MAC_DERIVE
    };
    CK_ULONG total = (CK_ULONG)(sizeof(list) / sizeof(list[0]));

    if (slot != TEST_SLOT) {
        return CKR_SLOT_ID_INVALID;
    }
    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (mechanisms != NULL && *count < total) {
        *count = total;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (mechanisms != NULL) {
        (void)memcpy(mechanisms, list, sizeof(list));
    }
    *count = total;
    return CKR_OK;
}

static CK_RV test_get_mechanism_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE type,
                                     CK_MECHANISM_INFO_PTR info)
{
    (void)type;
    if (slot != TEST_SLOT) {
        return CKR_SLOT_ID_INVALID;
    }
    if (info == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    info->ulMinKeySize = 1U;
    info->ulMaxKeySize = 2U;
    info->flags = CKF_DIGEST;
    return CKR_OK;
}

static CK_RV test_get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
    if (slot != TEST_SLOT) {
        return CKR_SLOT_ID_INVALID;
    }
    if (info == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    (void)memset(info, 0, sizeof(*info));
    info->flags = CKF_LOGIN_REQUIRED;
    if (g_user_pin[0] != '\0') {
        info->flags |= CKF_USER_PIN_INITIALIZED;
    }
    if (g_provider_test_token_initialized != 0U) {
        info->flags |= CKF_TOKEN_INITIALIZED;
    }
    info->ulMinPinLen = TEST_PIN_MIN;
    info->ulMaxPinLen = TEST_PIN_MAX - 1U;
    return CKR_OK;
}

static CK_RV test_init_token(CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin,
                             CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
    CK_RV rv;

    if (slot != TEST_SLOT) {
        return CKR_SLOT_ID_INVALID;
    }
    if (pin == NULL || label == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!test_pin_len_valid(pin, pin_len)) {
        return CKR_PIN_LEN_RANGE;
    }
    if (g_provider_test_token_initialized != 0U &&
            !test_pin_matches(g_so_pin, pin, pin_len)) {
        return CKR_PIN_INCORRECT;
    }
    rv = test_store_pin(g_so_pin, pin, pin_len);
    if (rv == CKR_OK) {
        g_provider_test_token_initialized = 1U;
        g_state = CKS_RW_PUBLIC_SESSION;
    }
    return rv;
}

static CK_RV test_init_pin(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin,
                           CK_ULONG pin_len)
{
    g_provider_test_calls++;
    if (!test_session_valid(session)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (g_state != CKS_RW_SO_FUNCTIONS) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    return test_store_pin(g_user_pin, pin, pin_len);
}

static CK_RV test_set_pin(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR old_pin,
                          CK_ULONG old_len, CK_UTF8CHAR_PTR new_pin,
                          CK_ULONG new_len)
{
    char* target = g_state == CKS_RW_SO_FUNCTIONS ? g_so_pin : g_user_pin;

    if (!test_session_valid(session)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (old_pin == NULL || new_pin == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!test_pin_len_valid(old_pin, old_len)) {
        return CKR_PIN_INCORRECT;
    }
    if (!test_pin_len_valid(new_pin, new_len)) {
        return CKR_PIN_LEN_RANGE;
    }
    if (session == TEST_RO_SESSION) {
        return CKR_SESSION_READ_ONLY;
    }
    if (target[0] == '\0') {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }
    if (!test_pin_matches(target, old_pin, old_len)) {
        return CKR_PIN_INCORRECT;
    }
    if (g_provider_test_after_pin_rv != CKR_OK) {
        return g_provider_test_after_pin_rv;
    }
    return test_store_pin(target, new_pin, new_len);
}

static CK_RV test_open_session(CK_SLOT_ID slot, CK_FLAGS flags,
                               CK_VOID_PTR application, CK_NOTIFY notify,
                               CK_SESSION_HANDLE_PTR session)
{
    g_provider_test_calls++;
    g_provider_test_open_output = session != NULL;
    g_provider_test_open_callbacks = application != NULL || notify != NULL;
    if (slot != TEST_SLOT) {
        return CKR_SLOT_ID_INVALID;
    }
    if ((flags & CKF_SERIAL_SESSION) == 0U) {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    if (session == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *session = 2U;
    return CKR_OK;
}

static CK_RV test_close_session(CK_SESSION_HANDLE session)
{
    return test_session_valid(session) ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

static CK_RV test_get_session_info(CK_SESSION_HANDLE session,
                                   CK_SESSION_INFO_PTR info)
{
    if (!test_session_valid(session)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (info == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    (void)memset(info, 0, sizeof(*info));
    info->slotID = TEST_SLOT;
    info->state = g_state;
    info->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    if (session == TEST_RO_SESSION) {
        info->state = g_state == CKS_RW_USER_FUNCTIONS ?
                      CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
        info->flags = CKF_SERIAL_SESSION;
    }
    return CKR_OK;
}

static CK_RV test_login(CK_SESSION_HANDLE session, CK_USER_TYPE user,
                        CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
    if (!test_session_valid(session)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pin == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!test_pin_len_valid(pin, pin_len)) {
        return CKR_PIN_LEN_RANGE;
    }
    if (user == CKU_CONTEXT_SPECIFIC) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (user != CKU_SO && user != CKU_USER) {
        return CKR_USER_TYPE_INVALID;
    }
    if (test_logged_in()) {
        return (g_state == CKS_RW_SO_FUNCTIONS) == (user == CKU_SO) ?
               CKR_USER_ALREADY_LOGGED_IN :
               CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }
    if (user == CKU_SO && session == TEST_RO_SESSION) {
        return CKR_SESSION_READ_ONLY_EXISTS;
    }
    if ((user == CKU_SO ? g_so_pin : g_user_pin)[0] == '\0') {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }
    if (!test_pin_matches(user == CKU_SO ? g_so_pin : g_user_pin, pin,
                          pin_len)) {
        return CKR_PIN_INCORRECT;
    }
    if (g_provider_test_after_pin_rv != CKR_OK) {
        return g_provider_test_after_pin_rv;
    }
    g_state = user == CKU_SO ? CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
    return CKR_OK;
}

static CK_RV test_logout(CK_SESSION_HANDLE session)
{
    if (!test_session_valid(session)) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    g_state = CKS_RW_PUBLIC_SESSION;
    return CKR_OK;
}

static CK_RV test_create_object(CK_SESSION_HANDLE session,
                                CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                                CK_OBJECT_HANDLE_PTR object)
{
    (void)session;
    g_provider_test_calls++;
    g_provider_test_null_seen = attributes == NULL;
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
    (void)key;
    g_provider_test_calls++;
    g_provider_test_null_seen = mechanism == NULL ||
                                mechanism->pParameter == NULL;
    return CKR_FUNCTION_FAILED;
}

static CK_RV test_seed_random(CK_SESSION_HANDLE session, CK_BYTE_PTR seed,
                              CK_ULONG seed_len)
{
    (void)session;
    (void)seed_len;
    g_provider_test_calls++;
    g_provider_test_null_seen = seed == NULL;
    return seed == NULL ? CKR_ARGUMENTS_BAD : CKR_OK;
}

static CK_RV test_generate_random(CK_SESSION_HANDLE session,
                                  CK_BYTE_PTR output, CK_ULONG length)
{
    (void)session;
    g_provider_test_calls++;
    g_provider_test_null_seen = output == NULL;
    if (output == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    (void)memset(output, 0x5a, (size_t)length);
    return CKR_OK;
}

static CK_RV test_find_objects(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE_PTR objects,
                               CK_ULONG maximum, CK_ULONG_PTR count)
{
    (void)session;
    (void)maximum;
    g_provider_test_calls++;
    g_provider_test_null_seen = objects == NULL;
    if (objects == NULL || count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *count = 0U;
    return CKR_OK;
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
    g_provider_test_null_seen = params != NULL &&
                                params->pSharedData == NULL;
    g_provider_test_ecdh_valid = session == 1U && base_key == 12U &&
        attributes != NULL && count == 0U && key != NULL && params != NULL &&
        params->kdf == CKD_NULL && params->ulSharedDataLen == 0U &&
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
    .C_Initialize = test_initialize,
    .C_Finalize = test_finalize,
    .C_GetInfo = test_get_info,
    .C_GetTokenInfo = test_get_token_info,
    .C_GetMechanismList = test_get_mechanism_list,
    .C_GetMechanismInfo = test_get_mechanism_info,
    .C_InitToken = test_init_token,
    .C_InitPIN = test_init_pin,
    .C_SetPIN = test_set_pin,
    .C_OpenSession = test_open_session,
    .C_CloseSession = test_close_session,
    .C_GetSessionInfo = test_get_session_info,
    .C_Login = test_login,
    .C_Logout = test_logout,
    .C_CreateObject = test_create_object,
    .C_GetAttributeValue = test_get_attribute_value,
    .C_FindObjects = test_find_objects,
    .C_EncryptInit = test_encrypt_init,
    .C_SeedRandom = test_seed_random,
    .C_GenerateRandom = test_generate_random,
    .C_DeriveKey = test_derive_key
};
