/* pkcs11_proxy.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include "wolftrust/pkcs11_psa_transport.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/pkcs11/pkcs11_wire.h"
#include "wolftrust/zeroize.h"

#include "wolfpkcs11/pkcs11.h"

#include <limits.h>
#include <string.h>

#define WT_P11_TEMPLATE_MAX 32U

static uint8_t g_request[WT_PKCS11_MESSAGE_MAX];
static uint8_t g_response[WT_PKCS11_MESSAGE_MAX];

static CK_RV proxy_finish(wt_pkcs11_reader_t* reader, CK_RV rv)
{
    wt_forceZero(g_request, sizeof(g_request));
    wt_forceZero(g_response, sizeof(g_response));
    if (reader != NULL) {
        wt_pkcs11_reader_init(reader, g_response, 0U);
    }
    return rv;
}

static void proxy_begin(wt_pkcs11_writer_t* writer, uint32_t function)
{
    wt_forceZero(g_request, sizeof(g_request));
    wt_forceZero(g_response, sizeof(g_response));
    wt_pkcs11_writer_init(writer, g_request, sizeof(g_request));
    wt_pkcs11_put_u32(writer, WT_PKCS11_WIRE_MAGIC);
    wt_pkcs11_put_u32(writer, WT_PKCS11_WIRE_VERSION);
    wt_pkcs11_put_u32(writer, function);
}

static CK_RV proxy_invoke(wt_pkcs11_writer_t* writer,
                          wt_pkcs11_reader_t* reader)
{
    size_t response_len = 0U;
    uint32_t magic;
    uint32_t version;
    CK_RV rv;

    wt_pkcs11_reader_init(reader, g_response, 0U);
    if (writer->error != 0) {
        return proxy_finish(reader, CKR_ARGUMENTS_BAD);
    }
    wt_forceZero(g_response, sizeof(g_response));
    if (wt_pkcs11_psa_call(g_request, writer->used, g_response,
                            sizeof(g_response), &response_len) != 0) {
        return proxy_finish(reader, CKR_DEVICE_ERROR);
    }
    wt_forceZero(g_request, sizeof(g_request));
    wt_pkcs11_reader_init(reader, g_response, response_len);
    magic = wt_pkcs11_get_u32(reader);
    version = wt_pkcs11_get_u32(reader);
    rv = (CK_RV)wt_pkcs11_get_u32(reader);
    if (reader->error != 0 || magic != WT_PKCS11_WIRE_MAGIC ||
            version != WT_PKCS11_WIRE_VERSION) {
        return proxy_finish(reader, CKR_DEVICE_ERROR);
    }
    return rv;
}

static CK_RV proxy_invoke_complete(wt_pkcs11_writer_t* writer,
                                   wt_pkcs11_reader_t* reader)
{
    CK_RV rv = proxy_invoke(writer, reader);

    return proxy_finish(reader, rv);
}

static int proxy_u32_list_valid(const wt_pkcs11_reader_t* reader,
                                uint32_t count)
{
    size_t remaining;

    if (reader->error != 0 || reader->used > reader->length ||
            count > WT_PKCS11_LIST_MAX) {
        return 0;
    }
    remaining = reader->length - reader->used;
    return remaining == (size_t)count * sizeof(uint32_t);
}

static int proxy_put_ulong(wt_pkcs11_writer_t* writer, CK_ULONG value)
{
#if ULONG_MAX > UINT32_MAX
    if (value > UINT32_MAX) {
        writer->error = 1;
        return -1;
    }
#endif
    wt_pkcs11_put_u32(writer, (uint32_t)value);
    return 0;
}

/* wolfPKCS11 rejects some NULL buffers even at length zero, so the provider
 * must see the caller's NULL, not an empty wire buffer. */
static void proxy_put_buffer(wt_pkcs11_writer_t* writer, const void* data,
                             CK_ULONG length)
{
    wt_pkcs11_put_u32(writer, data != NULL ? 1U : 0U);
    wt_pkcs11_put_bytes(writer, data, (size_t)length);
}

static int proxy_put_blob(wt_pkcs11_writer_t* writer, const void* data,
                          CK_ULONG length)
{
    if (proxy_put_ulong(writer, length) != 0) {
        return -1;
    }
    proxy_put_buffer(writer, data, length);
    return writer->error != 0 ? -1 : 0;
}

static int proxy_put_template(wt_pkcs11_writer_t* writer,
                              CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                              int include_values)
{
    CK_ULONG i;

    if (count > WT_P11_TEMPLATE_MAX ||
            (attributes == NULL && count != 0U)) {
        writer->error = 1;
        return -1;
    }
    wt_pkcs11_put_u32(writer, attributes != NULL ? 1U : 0U);
    (void)proxy_put_ulong(writer, count);
    for (i = 0U; i < count; i++) {
        CK_ULONG capacity = attributes[i].pValue != NULL ?
                            attributes[i].ulValueLen : 0U;

        (void)proxy_put_ulong(writer, attributes[i].type);
        (void)proxy_put_ulong(writer,
            include_values != 0 ? attributes[i].ulValueLen : capacity);
        wt_pkcs11_put_u32(writer, attributes[i].pValue != NULL ? 1U : 0U);
        if (include_values != 0) {
            wt_pkcs11_put_bytes(writer, attributes[i].pValue,
                                (size_t)attributes[i].ulValueLen);
        }
        else {
            wt_pkcs11_put_bytes(writer, NULL, 0U);
        }
    }
    return writer->error != 0 ? -1 : 0;
}

static int proxy_get_template(wt_pkcs11_reader_t* reader,
                              CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                              int values_returned)
{
    CK_ULONG i;
    uint32_t returned;
    uint32_t actual;
    uint8_t* value;
    size_t value_len;

    returned = wt_pkcs11_get_u32(reader);
    if (reader->error != 0 || returned != (uint32_t)count) {
        return -1;
    }
    for (i = 0U; i < count; i++) {
        actual = wt_pkcs11_get_u32(reader);
        value = wt_pkcs11_get_bytes(reader, &value_len);
        if (reader->error != 0) {
            return -1;
        }
        if (values_returned == 0) {
            continue;
        }
        if (attributes[i].pValue != NULL && actual <= attributes[i].ulValueLen) {
            if (value_len != actual) {
                return -1;
            }
            (void)memcpy(attributes[i].pValue, value, value_len);
        }
        else if (value_len != 0U) {
            return -1;
        }
        attributes[i].ulValueLen = actual == WT_PKCS11_WIRE_UNAVAILABLE ?
            CK_UNAVAILABLE_INFORMATION : (CK_ULONG)actual;
    }
    return 0;
}

static int proxy_put_mechanism(wt_pkcs11_writer_t* writer,
                               CK_MECHANISM_PTR mechanism)
{
    uint32_t kind = WT_P11_MECH_RAW;

    if (mechanism == NULL) {
        wt_pkcs11_put_u32(writer, 0U);
        return 0;
    }
    wt_pkcs11_put_u32(writer, 1U);
    (void)proxy_put_ulong(writer, mechanism->mechanism);
    switch (mechanism->mechanism) {
        case CKM_AES_CTR:
            kind = WT_P11_MECH_CTR;
            break;
        case CKM_AES_GCM:
            kind = WT_P11_MECH_GCM;
            break;
        case CKM_AES_CCM:
            kind = WT_P11_MECH_CCM;
            break;
        case CKM_ECDH1_DERIVE:
            kind = WT_P11_MECH_ECDH;
            break;
        default:
            break;
    }
    wt_pkcs11_put_u32(writer, kind);
    if (kind == WT_P11_MECH_CTR) {
        CK_AES_CTR_PARAMS* params = (CK_AES_CTR_PARAMS*)mechanism->pParameter;
        if (params == NULL || mechanism->ulParameterLen != sizeof(*params)) {
            writer->error = 1;
        }
        else {
            (void)proxy_put_ulong(writer, params->ulCounterBits);
            wt_pkcs11_put_bytes(writer, params->cb, sizeof(params->cb));
        }
    }
    else if (kind == WT_P11_MECH_GCM) {
        CK_GCM_PARAMS* params = (CK_GCM_PARAMS*)mechanism->pParameter;
        if (params == NULL || mechanism->ulParameterLen != sizeof(*params)) {
            writer->error = 1;
        }
        else {
            proxy_put_buffer(writer, params->pIv, params->ulIvLen);
            (void)proxy_put_ulong(writer, params->ulIvBits);
            proxy_put_buffer(writer, params->pAAD, params->ulAADLen);
            (void)proxy_put_ulong(writer, params->ulTagBits);
        }
    }
    else if (kind == WT_P11_MECH_CCM) {
        CK_CCM_PARAMS* params = (CK_CCM_PARAMS*)mechanism->pParameter;
        if (params == NULL || mechanism->ulParameterLen != sizeof(*params)) {
            writer->error = 1;
        }
        else {
            (void)proxy_put_ulong(writer, params->ulDataLen);
            proxy_put_buffer(writer, params->pIv, params->ulIvLen);
            proxy_put_buffer(writer, params->pAAD, params->ulAADLen);
            (void)proxy_put_ulong(writer, params->ulMacLen);
        }
    }
    else if (kind == WT_P11_MECH_ECDH) {
        CK_ECDH1_DERIVE_PARAMS* params =
            (CK_ECDH1_DERIVE_PARAMS*)mechanism->pParameter;
        if (params == NULL || mechanism->ulParameterLen != sizeof(*params)) {
            writer->error = 1;
        }
        else {
            (void)proxy_put_ulong(writer, params->kdf);
            proxy_put_buffer(writer, params->pSharedData,
                             params->ulSharedDataLen);
            proxy_put_buffer(writer, params->pPublicData,
                             params->ulPublicDataLen);
        }
    }
    else {
        proxy_put_buffer(writer, mechanism->pParameter,
                         mechanism->ulParameterLen);
    }
    return writer->error != 0 ? -1 : 0;
}

static CK_RV proxy_simple(uint32_t function)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, function);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_one(uint32_t function, CK_ULONG value)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, function);
    (void)proxy_put_ulong(&writer, value);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_output(uint32_t function, CK_SESSION_HANDLE session,
                          CK_BYTE_PTR input, CK_ULONG input_len,
                          CK_BYTE_PTR output, CK_ULONG_PTR output_len)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;
    CK_ULONG capacity;
    uint32_t actual;
    uint8_t* data;
    size_t data_len;

    if (output_len == NULL || (input == NULL && input_len != 0U)) {
        return CKR_ARGUMENTS_BAD;
    }
    capacity = output != NULL ? *output_len : 0U;
    proxy_begin(&writer, function);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_blob(&writer, input, input_len);
    wt_pkcs11_put_u32(&writer, output != NULL ? 1U : 0U);
    (void)proxy_put_ulong(&writer, capacity);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    actual = wt_pkcs11_get_u32(&reader);
    data = wt_pkcs11_get_bytes(&reader, &data_len);
    if (reader.error != 0) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    if (rv == CKR_OK && output != NULL) {
        if (actual > capacity || data_len != actual) {
            return proxy_finish(&reader, CKR_DEVICE_ERROR);
        }
        (void)memcpy(output, data, data_len);
    }
    else if (data_len != 0U) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    *output_len = (CK_ULONG)actual;
    return proxy_finish(&reader, rv);
}

static CK_RV proxy_final_output(uint32_t function, CK_SESSION_HANDLE session,
                                CK_BYTE_PTR output, CK_ULONG_PTR output_len)
{
    return proxy_output(function, session, NULL, 0U, output, output_len);
}

static CK_RV proxy_data(uint32_t function, CK_SESSION_HANDLE session,
                        CK_BYTE_PTR data, CK_ULONG length)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    if (data == NULL && length != 0U) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, function);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_blob(&writer, data, length);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_mechanism_init(uint32_t function,
                                  CK_SESSION_HANDLE session,
                                  CK_MECHANISM_PTR mechanism,
                                  CK_OBJECT_HANDLE key, int has_key)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, function);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_mechanism(&writer, mechanism);
    if (has_key != 0) {
        (void)proxy_put_ulong(&writer, key);
    }
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_Initialize(CK_VOID_PTR args)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_C_INITIALIZE_ARGS_PTR init = (CK_C_INITIALIZE_ARGS_PTR)args;
    int callbacks = 0;

    if (init != NULL) {
        callbacks = (init->CreateMutex != NULL) +
                    (init->DestroyMutex != NULL) +
                    (init->LockMutex != NULL) +
                    (init->UnlockMutex != NULL);
        if (init->pReserved != NULL ||
                (callbacks != 0 && callbacks != 4)) {
            return CKR_ARGUMENTS_BAD;
        }
        if (callbacks != 0 || (init->flags & CKF_OS_LOCKING_OK) != 0U) {
            return CKR_CANT_LOCK;
        }
    }

    proxy_begin(&writer, WT_P11_INITIALIZE);
    wt_pkcs11_put_u32(&writer, 0U);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_Finalize(CK_VOID_PTR reserved)
{
    if (reserved != NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    return proxy_simple(WT_P11_FINALIZE);
}

static CK_RV proxy_fixed_info(uint32_t function, CK_ULONG selector,
                              void* info, size_t info_size)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    uint8_t* data;
    size_t length;
    CK_RV rv;

    if (info == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, function);
    if (selector != CK_UNAVAILABLE_INFORMATION) {
        (void)proxy_put_ulong(&writer, selector);
    }
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    data = wt_pkcs11_get_bytes(&reader, &length);
    if (reader.error != 0 || (rv == CKR_OK && length != info_size)) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    if (rv == CKR_OK) {
        (void)memcpy(info, data, length);
    }
    return proxy_finish(&reader, rv);
}

static CK_RV proxy_C_GetInfo(CK_INFO_PTR info)
{
    return proxy_fixed_info(WT_P11_GET_INFO, CK_UNAVAILABLE_INFORMATION,
                            info, sizeof(*info));
}

static CK_RV proxy_C_GetSlotList(CK_BBOOL present, CK_SLOT_ID_PTR slots,
                                 CK_ULONG_PTR count)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_ULONG capacity;
    CK_ULONG i;
    uint32_t returned;
    uint32_t sent;
    CK_RV rv;

    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    capacity = slots != NULL ? *count : 0U;
    proxy_begin(&writer, WT_P11_GET_SLOT_LIST);
    wt_pkcs11_put_u32(&writer, present);
    wt_pkcs11_put_u32(&writer, slots != NULL ? 1U : 0U);
    (void)proxy_put_ulong(&writer, capacity);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    returned = wt_pkcs11_get_u32(&reader);
    sent = wt_pkcs11_get_u32(&reader);
    if (!proxy_u32_list_valid(&reader, sent) || sent > returned ||
            (CK_ULONG)sent > capacity) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    for (i = 0U; i < sent; i++) {
        uint32_t value = wt_pkcs11_get_u32(&reader);
        if (slots != NULL && i < capacity) {
            slots[i] = (CK_SLOT_ID)value;
        }
    }
    if (reader.error != 0) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    *count = returned;
    return proxy_finish(&reader, rv);
}

static CK_RV proxy_C_GetSlotInfo(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
    return proxy_fixed_info(WT_P11_GET_SLOT_INFO, slot, info, sizeof(*info));
}

static CK_RV proxy_C_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
    return proxy_fixed_info(WT_P11_GET_TOKEN_INFO, slot, info, sizeof(*info));
}

static CK_RV proxy_C_GetMechanismList(CK_SLOT_ID slot,
                                      CK_MECHANISM_TYPE_PTR mechanisms,
                                      CK_ULONG_PTR count)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_ULONG capacity;
    CK_ULONG i;
    uint32_t returned;
    uint32_t sent;
    CK_RV rv;

    if (count == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    capacity = mechanisms != NULL ? *count : 0U;
    proxy_begin(&writer, WT_P11_GET_MECHANISM_LIST);
    (void)proxy_put_ulong(&writer, slot);
    wt_pkcs11_put_u32(&writer, mechanisms != NULL ? 1U : 0U);
    (void)proxy_put_ulong(&writer, capacity);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    returned = wt_pkcs11_get_u32(&reader);
    sent = wt_pkcs11_get_u32(&reader);
    if (!proxy_u32_list_valid(&reader, sent) || sent > returned ||
            (CK_ULONG)sent > capacity) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    for (i = 0U; i < sent; i++) {
        uint32_t value = wt_pkcs11_get_u32(&reader);
        if (mechanisms != NULL && i < capacity) {
            mechanisms[i] = (CK_MECHANISM_TYPE)value;
        }
    }
    if (reader.error != 0) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    *count = returned;
    return proxy_finish(&reader, rv);
}

static CK_RV proxy_C_GetMechanismInfo(CK_SLOT_ID slot,
                                      CK_MECHANISM_TYPE type,
                                      CK_MECHANISM_INFO_PTR info)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;

    if (info == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_GET_MECHANISM_INFO);
    (void)proxy_put_ulong(&writer, slot);
    (void)proxy_put_ulong(&writer, type);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    info->ulMinKeySize = wt_pkcs11_get_u32(&reader);
    info->ulMaxKeySize = wt_pkcs11_get_u32(&reader);
    info->flags = wt_pkcs11_get_u32(&reader);
    return proxy_finish(&reader,
        reader.error != 0 ? CKR_DEVICE_ERROR : rv);
}

static CK_RV proxy_C_InitToken(CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin,
                               CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    if (label == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_INIT_TOKEN);
    (void)proxy_put_ulong(&writer, slot);
    (void)proxy_put_blob(&writer, pin, pin_len);
    wt_pkcs11_put_bytes(&writer, label, 32U);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_InitPIN(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin,
                             CK_ULONG pin_len)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_INIT_PIN);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_blob(&writer, pin, pin_len);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_SetPIN(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR old_pin,
                            CK_ULONG old_len, CK_UTF8CHAR_PTR new_pin,
                            CK_ULONG new_len)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_SET_PIN);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_blob(&writer, old_pin, old_len);
    (void)proxy_put_blob(&writer, new_pin, new_len);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags,
                                 CK_VOID_PTR application, CK_NOTIFY notify,
                                 CK_SESSION_HANDLE_PTR session)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    uint32_t opened;
    CK_RV rv;

    /* wolfPKCS11 ignores both, so neither pointer crosses into the provider;
     * a NULL session is forwarded so wolfPKCS11 orders its own checks. */
    (void)application;
    (void)notify;
    proxy_begin(&writer, WT_P11_OPEN_SESSION);
    (void)proxy_put_ulong(&writer, slot);
    (void)proxy_put_ulong(&writer, flags);
    wt_pkcs11_put_u32(&writer, session != NULL ? 1U : 0U);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    opened = wt_pkcs11_get_u32(&reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    if (session != NULL) {
        *session = (CK_SESSION_HANDLE)opened;
    }
    return proxy_finish(&reader, rv);
}

static CK_RV proxy_C_CloseSession(CK_SESSION_HANDLE session)
{
    return proxy_one(WT_P11_CLOSE_SESSION, session);
}

static CK_RV proxy_C_CloseAllSessions(CK_SLOT_ID slot)
{
    return proxy_one(WT_P11_CLOSE_ALL_SESSIONS, slot);
}

static CK_RV proxy_C_GetSessionInfo(CK_SESSION_HANDLE session,
                                    CK_SESSION_INFO_PTR info)
{
    return proxy_fixed_info(WT_P11_GET_SESSION_INFO, session, info,
                            sizeof(*info));
}

static CK_RV proxy_C_Login(CK_SESSION_HANDLE session, CK_USER_TYPE type,
                           CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_LOGIN);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_ulong(&writer, type);
    (void)proxy_put_blob(&writer, pin, pin_len);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_Logout(CK_SESSION_HANDLE session)
{
    return proxy_one(WT_P11_LOGOUT, session);
}

static CK_RV proxy_template_object(uint32_t function,
                                   CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE source,
                                   int has_source,
                                   CK_ATTRIBUTE_PTR attributes,
                                   CK_ULONG count,
                                   CK_OBJECT_HANDLE_PTR object)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;

    if (object == NULL || count > WT_P11_TEMPLATE_MAX ||
            (attributes == NULL && count != 0U)) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, function);
    (void)proxy_put_ulong(&writer, session);
    if (has_source != 0) {
        (void)proxy_put_ulong(&writer, source);
    }
    (void)proxy_put_template(&writer, attributes, count, 1);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    *object = (CK_OBJECT_HANDLE)wt_pkcs11_get_u32(&reader);
    return proxy_finish(&reader,
        reader.error != 0 ? CKR_DEVICE_ERROR : rv);
}

static CK_RV proxy_C_CreateObject(CK_SESSION_HANDLE session,
                                  CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                                  CK_OBJECT_HANDLE_PTR object)
{
    return proxy_template_object(WT_P11_CREATE_OBJECT, session, 0U, 0,
                                 attributes, count, object);
}

static CK_RV proxy_C_CopyObject(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE source,
                                CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                                CK_OBJECT_HANDLE_PTR object)
{
    return proxy_template_object(WT_P11_COPY_OBJECT, session, source, 1,
                                 attributes, count, object);
}

static CK_RV proxy_C_DestroyObject(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE object)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_DESTROY_OBJECT);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_ulong(&writer, object);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_GetObjectSize(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE object, CK_ULONG_PTR size)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;
    uint32_t encoded_size;

    if (size == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_GET_OBJECT_SIZE);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_ulong(&writer, object);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    encoded_size = wt_pkcs11_get_u32(&reader);
    *size = encoded_size == WT_PKCS11_WIRE_UNAVAILABLE ?
        CK_UNAVAILABLE_INFORMATION : (CK_ULONG)encoded_size;
    return proxy_finish(&reader,
        reader.error != 0 ? CKR_DEVICE_ERROR : rv);
}

static CK_RV proxy_C_GetAttributeValue(CK_SESSION_HANDLE session,
                                       CK_OBJECT_HANDLE object,
                                       CK_ATTRIBUTE_PTR attributes,
                                       CK_ULONG count)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;

    proxy_begin(&writer, WT_P11_GET_ATTRIBUTE_VALUE);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_ulong(&writer, object);
    (void)proxy_put_template(&writer, attributes, count, 0);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    if (proxy_get_template(&reader, attributes, count,
            rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE ||
            rv == CKR_ATTRIBUTE_TYPE_INVALID ||
            rv == CKR_BUFFER_TOO_SMALL) != 0) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    return proxy_finish(&reader, rv);
}

static CK_RV proxy_C_SetAttributeValue(CK_SESSION_HANDLE session,
                                       CK_OBJECT_HANDLE object,
                                       CK_ATTRIBUTE_PTR attributes,
                                       CK_ULONG count)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_SET_ATTRIBUTE_VALUE);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_ulong(&writer, object);
    (void)proxy_put_template(&writer, attributes, count, 1);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_FindObjectsInit(CK_SESSION_HANDLE session,
                                     CK_ATTRIBUTE_PTR attributes,
                                     CK_ULONG count)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_FIND_OBJECTS_INIT);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_template(&writer, attributes, count, 1);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_FindObjects(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE_PTR objects,
                                 CK_ULONG maximum, CK_ULONG_PTR count)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    uint32_t returned;
    CK_ULONG i;
    CK_RV rv;

    if (count == NULL || (objects == NULL && maximum != 0U)) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_FIND_OBJECTS);
    (void)proxy_put_ulong(&writer, session);
    wt_pkcs11_put_u32(&writer, objects != NULL ? 1U : 0U);
    (void)proxy_put_ulong(&writer, maximum);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    returned = wt_pkcs11_get_u32(&reader);
    if (!proxy_u32_list_valid(&reader, returned) ||
            (CK_ULONG)returned > maximum) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    for (i = 0U; i < returned; i++) {
        uint32_t object = wt_pkcs11_get_u32(&reader);
        if (i < maximum) {
            objects[i] = (CK_OBJECT_HANDLE)object;
        }
    }
    if (reader.error != 0) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    *count = returned;
    return proxy_finish(&reader, rv);
}

static CK_RV proxy_C_FindObjectsFinal(CK_SESSION_HANDLE session)
{
    return proxy_one(WT_P11_FIND_OBJECTS_FINAL, session);
}

static CK_RV proxy_C_EncryptInit(CK_SESSION_HANDLE session,
                                 CK_MECHANISM_PTR mechanism,
                                 CK_OBJECT_HANDLE key)
{
    return proxy_mechanism_init(WT_P11_ENCRYPT_INIT, session, mechanism,
                                key, 1);
}

static CK_RV proxy_C_Encrypt(CK_SESSION_HANDLE session, CK_BYTE_PTR input,
                             CK_ULONG input_len, CK_BYTE_PTR output,
                             CK_ULONG_PTR output_len)
{
    return proxy_output(WT_P11_ENCRYPT, session, input, input_len, output,
                        output_len);
}

static CK_RV proxy_C_EncryptUpdate(CK_SESSION_HANDLE session,
                                   CK_BYTE_PTR input, CK_ULONG input_len,
                                   CK_BYTE_PTR output,
                                   CK_ULONG_PTR output_len)
{
    return proxy_output(WT_P11_ENCRYPT_UPDATE, session, input, input_len,
                        output, output_len);
}

static CK_RV proxy_C_EncryptFinal(CK_SESSION_HANDLE session,
                                  CK_BYTE_PTR output,
                                  CK_ULONG_PTR output_len)
{
    return proxy_final_output(WT_P11_ENCRYPT_FINAL, session, output,
                              output_len);
}

static CK_RV proxy_C_DecryptInit(CK_SESSION_HANDLE session,
                                 CK_MECHANISM_PTR mechanism,
                                 CK_OBJECT_HANDLE key)
{
    return proxy_mechanism_init(WT_P11_DECRYPT_INIT, session, mechanism,
                                key, 1);
}

static CK_RV proxy_C_Decrypt(CK_SESSION_HANDLE session, CK_BYTE_PTR input,
                             CK_ULONG input_len, CK_BYTE_PTR output,
                             CK_ULONG_PTR output_len)
{
    return proxy_output(WT_P11_DECRYPT, session, input, input_len, output,
                        output_len);
}

static CK_RV proxy_C_DecryptUpdate(CK_SESSION_HANDLE session,
                                   CK_BYTE_PTR input, CK_ULONG input_len,
                                   CK_BYTE_PTR output,
                                   CK_ULONG_PTR output_len)
{
    return proxy_output(WT_P11_DECRYPT_UPDATE, session, input, input_len,
                        output, output_len);
}

static CK_RV proxy_C_DecryptFinal(CK_SESSION_HANDLE session,
                                  CK_BYTE_PTR output,
                                  CK_ULONG_PTR output_len)
{
    return proxy_final_output(WT_P11_DECRYPT_FINAL, session, output,
                              output_len);
}

static CK_RV proxy_C_DigestInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM_PTR mechanism)
{
    return proxy_mechanism_init(WT_P11_DIGEST_INIT, session, mechanism, 0U, 0);
}

static CK_RV proxy_C_Digest(CK_SESSION_HANDLE session, CK_BYTE_PTR input,
                            CK_ULONG input_len, CK_BYTE_PTR output,
                            CK_ULONG_PTR output_len)
{
    return proxy_output(WT_P11_DIGEST, session, input, input_len, output,
                        output_len);
}

static CK_RV proxy_C_DigestUpdate(CK_SESSION_HANDLE session,
                                  CK_BYTE_PTR input, CK_ULONG input_len)
{
    return proxy_data(WT_P11_DIGEST_UPDATE, session, input, input_len);
}

static CK_RV proxy_C_DigestKey(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE key)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_DIGEST_KEY);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_ulong(&writer, key);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_DigestFinal(CK_SESSION_HANDLE session,
                                 CK_BYTE_PTR output, CK_ULONG_PTR output_len)
{
    return proxy_final_output(WT_P11_DIGEST_FINAL, session, output, output_len);
}

static CK_RV proxy_C_SignInit(CK_SESSION_HANDLE session,
                              CK_MECHANISM_PTR mechanism,
                              CK_OBJECT_HANDLE key)
{
    return proxy_mechanism_init(WT_P11_SIGN_INIT, session, mechanism, key, 1);
}

static CK_RV proxy_C_Sign(CK_SESSION_HANDLE session, CK_BYTE_PTR input,
                          CK_ULONG input_len, CK_BYTE_PTR output,
                          CK_ULONG_PTR output_len)
{
    return proxy_output(WT_P11_SIGN, session, input, input_len, output,
                        output_len);
}

static CK_RV proxy_C_SignUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR input,
                                CK_ULONG input_len)
{
    return proxy_data(WT_P11_SIGN_UPDATE, session, input, input_len);
}

static CK_RV proxy_C_SignFinal(CK_SESSION_HANDLE session, CK_BYTE_PTR output,
                               CK_ULONG_PTR output_len)
{
    return proxy_final_output(WT_P11_SIGN_FINAL, session, output, output_len);
}

static CK_RV proxy_C_VerifyInit(CK_SESSION_HANDLE session,
                                CK_MECHANISM_PTR mechanism,
                                CK_OBJECT_HANDLE key)
{
    return proxy_mechanism_init(WT_P11_VERIFY_INIT, session, mechanism, key, 1);
}

static CK_RV proxy_C_Verify(CK_SESSION_HANDLE session, CK_BYTE_PTR data,
                            CK_ULONG data_len, CK_BYTE_PTR signature,
                            CK_ULONG signature_len)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;

    proxy_begin(&writer, WT_P11_VERIFY);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_blob(&writer, data, data_len);
    (void)proxy_put_blob(&writer, signature, signature_len);
    return proxy_invoke_complete(&writer, &reader);
}

static CK_RV proxy_C_VerifyUpdate(CK_SESSION_HANDLE session,
                                  CK_BYTE_PTR input, CK_ULONG input_len)
{
    return proxy_data(WT_P11_VERIFY_UPDATE, session, input, input_len);
}

static CK_RV proxy_C_VerifyFinal(CK_SESSION_HANDLE session,
                                 CK_BYTE_PTR signature,
                                 CK_ULONG signature_len)
{
    return proxy_data(WT_P11_VERIFY_FINAL, session, signature, signature_len);
}

static CK_RV proxy_C_GenerateKey(CK_SESSION_HANDLE session,
                                 CK_MECHANISM_PTR mechanism,
                                 CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                                 CK_OBJECT_HANDLE_PTR key)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;

    if (key == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_GENERATE_KEY);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_mechanism(&writer, mechanism);
    (void)proxy_put_template(&writer, attributes, count, 1);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    *key = (CK_OBJECT_HANDLE)wt_pkcs11_get_u32(&reader);
    return proxy_finish(&reader,
        reader.error != 0 ? CKR_DEVICE_ERROR : rv);
}

static CK_RV proxy_C_GenerateKeyPair(CK_SESSION_HANDLE session,
                                     CK_MECHANISM_PTR mechanism,
                                     CK_ATTRIBUTE_PTR public_attributes,
                                     CK_ULONG public_count,
                                     CK_ATTRIBUTE_PTR private_attributes,
                                     CK_ULONG private_count,
                                     CK_OBJECT_HANDLE_PTR public_key,
                                     CK_OBJECT_HANDLE_PTR private_key)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;

    if (public_key == NULL || private_key == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_GENERATE_KEY_PAIR);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_mechanism(&writer, mechanism);
    (void)proxy_put_template(&writer, public_attributes, public_count, 1);
    (void)proxy_put_template(&writer, private_attributes, private_count, 1);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    *public_key = (CK_OBJECT_HANDLE)wt_pkcs11_get_u32(&reader);
    *private_key = (CK_OBJECT_HANDLE)wt_pkcs11_get_u32(&reader);
    return proxy_finish(&reader,
        reader.error != 0 ? CKR_DEVICE_ERROR : rv);
}

static CK_RV proxy_C_DeriveKey(CK_SESSION_HANDLE session,
                               CK_MECHANISM_PTR mechanism,
                               CK_OBJECT_HANDLE base_key,
                               CK_ATTRIBUTE_PTR attributes, CK_ULONG count,
                               CK_OBJECT_HANDLE_PTR key)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_RV rv;

    if (key == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_DERIVE_KEY);
    (void)proxy_put_ulong(&writer, session);
    (void)proxy_put_mechanism(&writer, mechanism);
    (void)proxy_put_ulong(&writer, base_key);
    (void)proxy_put_template(&writer, attributes, count, 1);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    *key = (CK_OBJECT_HANDLE)wt_pkcs11_get_u32(&reader);
    return proxy_finish(&reader,
        reader.error != 0 ? CKR_DEVICE_ERROR : rv);
}

static CK_RV proxy_C_SeedRandom(CK_SESSION_HANDLE session, CK_BYTE_PTR seed,
                                CK_ULONG length)
{
    return proxy_data(WT_P11_SEED_RANDOM, session, seed, length);
}

static CK_RV proxy_C_GenerateRandom(CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR output, CK_ULONG length)
{
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    uint8_t* data;
    size_t data_len;
    CK_RV rv;

    if (output == NULL && length != 0U) {
        return CKR_ARGUMENTS_BAD;
    }
    proxy_begin(&writer, WT_P11_GENERATE_RANDOM);
    (void)proxy_put_ulong(&writer, session);
    wt_pkcs11_put_u32(&writer, output != NULL ? 1U : 0U);
    (void)proxy_put_ulong(&writer, length);
    rv = proxy_invoke(&writer, &reader);
    if (reader.error != 0) {
        return proxy_finish(&reader, rv);
    }
    data = wt_pkcs11_get_bytes(&reader, &data_len);
    if (reader.error != 0 || (rv == CKR_OK && data_len != length)) {
        return proxy_finish(&reader, CKR_DEVICE_ERROR);
    }
    if (rv == CKR_OK && length != 0U) {
        (void)memcpy(output, data, data_len);
    }
    return proxy_finish(&reader, rv);
}

/* Operations not implemented by wolfPKCS11 on this target still traverse the
 * secure relay. The provider returns CKR_FUNCTION_NOT_SUPPORTED. */
static CK_RV proxy_unsupported(uint32_t function)
{
    return proxy_simple(function);
}

static CK_RV proxy_C_GetOperationState(CK_SESSION_HANDLE session,
        CK_BYTE_PTR state, CK_ULONG_PTR length)
{
    (void)session; (void)state; (void)length;
    return proxy_unsupported(WT_P11_GET_OPERATION_STATE);
}
static CK_RV proxy_C_SetOperationState(CK_SESSION_HANDLE session,
        CK_BYTE_PTR state, CK_ULONG length, CK_OBJECT_HANDLE encryption_key,
        CK_OBJECT_HANDLE authentication_key)
{
    (void)session; (void)state; (void)length; (void)encryption_key;
    (void)authentication_key;
    return proxy_unsupported(WT_P11_SET_OPERATION_STATE);
}
static CK_RV proxy_C_SignRecoverInit(CK_SESSION_HANDLE session,
        CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)session; (void)mechanism; (void)key;
    return proxy_unsupported(WT_P11_SIGN_RECOVER_INIT);
}
static CK_RV proxy_C_SignRecover(CK_SESSION_HANDLE session, CK_BYTE_PTR data,
        CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
    (void)session; (void)data; (void)data_len; (void)signature;
    (void)signature_len;
    return proxy_unsupported(WT_P11_SIGN_RECOVER);
}
static CK_RV proxy_C_VerifyRecoverInit(CK_SESSION_HANDLE session,
        CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)session; (void)mechanism; (void)key;
    return proxy_unsupported(WT_P11_VERIFY_RECOVER_INIT);
}
static CK_RV proxy_C_VerifyRecover(CK_SESSION_HANDLE session,
        CK_BYTE_PTR signature, CK_ULONG signature_len, CK_BYTE_PTR data,
        CK_ULONG_PTR data_len)
{
    (void)session; (void)signature; (void)signature_len; (void)data;
    (void)data_len;
    return proxy_unsupported(WT_P11_VERIFY_RECOVER);
}

#define WT_PROXY_COMBINED(name, id) \
static CK_RV name(CK_SESSION_HANDLE session, CK_BYTE_PTR input, \
                  CK_ULONG input_len, CK_BYTE_PTR output, \
                  CK_ULONG_PTR output_len) \
{ \
    (void)session; (void)input; (void)input_len; (void)output; \
    (void)output_len; \
    return proxy_unsupported(id); \
}

WT_PROXY_COMBINED(proxy_C_DigestEncryptUpdate, WT_P11_DIGEST_ENCRYPT_UPDATE)
WT_PROXY_COMBINED(proxy_C_DecryptDigestUpdate, WT_P11_DECRYPT_DIGEST_UPDATE)
WT_PROXY_COMBINED(proxy_C_SignEncryptUpdate, WT_P11_SIGN_ENCRYPT_UPDATE)
WT_PROXY_COMBINED(proxy_C_DecryptVerifyUpdate, WT_P11_DECRYPT_VERIFY_UPDATE)

static CK_RV proxy_C_WrapKey(CK_SESSION_HANDLE session,
        CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped, CK_ULONG_PTR wrapped_len)
{
    (void)session; (void)mechanism; (void)wrapping_key; (void)key;
    (void)wrapped; (void)wrapped_len;
    return proxy_unsupported(WT_P11_WRAP_KEY);
}
static CK_RV proxy_C_UnwrapKey(CK_SESSION_HANDLE session,
        CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE unwrapping_key,
        CK_BYTE_PTR wrapped, CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR attributes,
        CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
    (void)session; (void)mechanism; (void)unwrapping_key; (void)wrapped;
    (void)wrapped_len; (void)attributes; (void)count; (void)key;
    return proxy_unsupported(WT_P11_UNWRAP_KEY);
}
static CK_RV proxy_C_GetFunctionStatus(CK_SESSION_HANDLE session)
{
    (void)session;
    return proxy_unsupported(WT_P11_GET_FUNCTION_STATUS);
}
static CK_RV proxy_C_CancelFunction(CK_SESSION_HANDLE session)
{
    (void)session;
    return proxy_unsupported(WT_P11_CANCEL_FUNCTION);
}
static CK_RV proxy_C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR slot,
                                      CK_VOID_PTR reserved)
{
    (void)flags; (void)slot; (void)reserved;
    return proxy_unsupported(WT_P11_WAIT_FOR_SLOT_EVENT);
}

static CK_FUNCTION_LIST g_proxy_functions = {
    { 2, 40 },
    proxy_C_Initialize,
    proxy_C_Finalize,
    proxy_C_GetInfo,
    C_GetFunctionList,
    proxy_C_GetSlotList,
    proxy_C_GetSlotInfo,
    proxy_C_GetTokenInfo,
    proxy_C_GetMechanismList,
    proxy_C_GetMechanismInfo,
    proxy_C_InitToken,
    proxy_C_InitPIN,
    proxy_C_SetPIN,
    proxy_C_OpenSession,
    proxy_C_CloseSession,
    proxy_C_CloseAllSessions,
    proxy_C_GetSessionInfo,
    proxy_C_GetOperationState,
    proxy_C_SetOperationState,
    proxy_C_Login,
    proxy_C_Logout,
    proxy_C_CreateObject,
    proxy_C_CopyObject,
    proxy_C_DestroyObject,
    proxy_C_GetObjectSize,
    proxy_C_GetAttributeValue,
    proxy_C_SetAttributeValue,
    proxy_C_FindObjectsInit,
    proxy_C_FindObjects,
    proxy_C_FindObjectsFinal,
    proxy_C_EncryptInit,
    proxy_C_Encrypt,
    proxy_C_EncryptUpdate,
    proxy_C_EncryptFinal,
    proxy_C_DecryptInit,
    proxy_C_Decrypt,
    proxy_C_DecryptUpdate,
    proxy_C_DecryptFinal,
    proxy_C_DigestInit,
    proxy_C_Digest,
    proxy_C_DigestUpdate,
    proxy_C_DigestKey,
    proxy_C_DigestFinal,
    proxy_C_SignInit,
    proxy_C_Sign,
    proxy_C_SignUpdate,
    proxy_C_SignFinal,
    proxy_C_SignRecoverInit,
    proxy_C_SignRecover,
    proxy_C_VerifyInit,
    proxy_C_Verify,
    proxy_C_VerifyUpdate,
    proxy_C_VerifyFinal,
    proxy_C_VerifyRecoverInit,
    proxy_C_VerifyRecover,
    proxy_C_DigestEncryptUpdate,
    proxy_C_DecryptDigestUpdate,
    proxy_C_SignEncryptUpdate,
    proxy_C_DecryptVerifyUpdate,
    proxy_C_GenerateKey,
    proxy_C_GenerateKeyPair,
    proxy_C_WrapKey,
    proxy_C_UnwrapKey,
    proxy_C_DeriveKey,
    proxy_C_SeedRandom,
    proxy_C_GenerateRandom,
    proxy_C_GetFunctionStatus,
    proxy_C_CancelFunction,
    proxy_C_WaitForSlotEvent
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR functions)
{
    if (functions == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *functions = &g_proxy_functions;
    return CKR_OK;
}
