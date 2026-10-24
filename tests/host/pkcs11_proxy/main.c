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

/* PKCS11 proxy wire suite: a scripted provider validates templates and every
 * supported mechanism encoding, and returns hostile list counts. */

#include "wolfpkcs11/pkcs11.h"

#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/pkcs11/pkcs11_wire.h"
#include "wolftrust/pkcs11_psa_transport.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum reply_kind {
    REPLY_OK,
    REPLY_OBJECT,
    REPLY_SLOT_VALID,
    REPLY_SLOT_HUGE,
    REPLY_SLOT_TRUNCATED,
    REPLY_FIND_HUGE,
    REPLY_SIZE_UNAVAILABLE,
    REPLY_ATTRIBUTE_UNAVAILABLE,
    REPLY_ATTRIBUTE_BUFFER_TOO_SMALL,
    REPLY_ATTRIBUTE_TYPE_INVALID,
    REPLY_ATTRIBUTE_SENSITIVE,
    REPLY_ATTRIBUTE_OBJECT_INVALID,
    REPLY_SESSION_PARALLEL,
    REPLY_ARGUMENTS_BAD
};

static int g_failures;
static enum reply_kind g_reply;
static uint8_t g_request[WT_PKCS11_MESSAGE_MAX];
static size_t g_request_len;
static const uint8_t g_terminal_attribute_value[sizeof(CK_OBJECT_CLASS)] = {
    0xa5U
};

static void check(int ok, const char* what)
{
    if (ok != 0) {
        (void)printf("PASS: %s\n", what);
    }
    else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

int wt_pkcs11_psa_call(const uint8_t* request, size_t request_len,
                       uint8_t* response, size_t response_cap,
                       size_t* response_len)
{
    wt_pkcs11_writer_t writer;
    CK_RV rv = CKR_OK;

    if (request == NULL || request_len > sizeof(g_request) ||
            response == NULL || response_len == NULL) {
        return -1;
    }
    (void)memcpy(g_request, request, request_len);
    g_request_len = request_len;
    wt_pkcs11_writer_init(&writer, response, response_cap);
    wt_pkcs11_put_u32(&writer, WT_PKCS11_WIRE_MAGIC);
    wt_pkcs11_put_u32(&writer, WT_PKCS11_WIRE_VERSION);
    if (g_reply == REPLY_ATTRIBUTE_BUFFER_TOO_SMALL) {
        rv = CKR_BUFFER_TOO_SMALL;
    }
    else if (g_reply == REPLY_ATTRIBUTE_TYPE_INVALID) {
        rv = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    else if (g_reply == REPLY_ATTRIBUTE_SENSITIVE) {
        rv = CKR_ATTRIBUTE_SENSITIVE;
    }
    else if (g_reply == REPLY_ATTRIBUTE_OBJECT_INVALID) {
        rv = CKR_OBJECT_HANDLE_INVALID;
    }
    else if (g_reply == REPLY_SESSION_PARALLEL) {
        rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    else if (g_reply == REPLY_ARGUMENTS_BAD) {
        rv = CKR_ARGUMENTS_BAD;
    }
    wt_pkcs11_put_u32(&writer, rv);
    if (g_reply == REPLY_OBJECT) {
        wt_pkcs11_put_u32(&writer, 77U);
    }
    else if (g_reply == REPLY_SESSION_PARALLEL ||
            g_reply == REPLY_ARGUMENTS_BAD) {
        wt_pkcs11_put_u32(&writer, 0U);
    }
    else if (g_reply == REPLY_SLOT_VALID) {
        wt_pkcs11_put_u32(&writer, 1U);
        wt_pkcs11_put_u32(&writer, 1U);
        wt_pkcs11_put_u32(&writer, 7U);
    }
    else if (g_reply == REPLY_SLOT_HUGE) {
        wt_pkcs11_put_u32(&writer, 1U);
        wt_pkcs11_put_u32(&writer, UINT32_MAX);
    }
    else if (g_reply == REPLY_SLOT_TRUNCATED) {
        wt_pkcs11_put_u32(&writer, 1U);
        wt_pkcs11_put_u32(&writer, 1U);
    }
    else if (g_reply == REPLY_FIND_HUGE) {
        wt_pkcs11_put_u32(&writer, WT_PKCS11_LIST_MAX + 1U);
    }
    else if (g_reply == REPLY_SIZE_UNAVAILABLE) {
        wt_pkcs11_put_u32(&writer, UINT32_MAX);
    }
    else if (g_reply == REPLY_ATTRIBUTE_UNAVAILABLE) {
        wt_pkcs11_put_u32(&writer, 1U);
        wt_pkcs11_put_u32(&writer, UINT32_MAX);
        wt_pkcs11_put_bytes(&writer, NULL, 0U);
    }
    else if (g_reply == REPLY_ATTRIBUTE_BUFFER_TOO_SMALL) {
        wt_pkcs11_put_u32(&writer, 2U);
        wt_pkcs11_put_u32(&writer, 3U);
        wt_pkcs11_put_bytes(&writer, NULL, 0U);
        wt_pkcs11_put_u32(&writer, 3U);
        wt_pkcs11_put_bytes(&writer, (const uint8_t*)"key", 3U);
    }
    else if (g_reply == REPLY_ATTRIBUTE_TYPE_INVALID ||
            g_reply == REPLY_ATTRIBUTE_SENSITIVE) {
        wt_pkcs11_put_u32(&writer, 2U);
        wt_pkcs11_put_u32(&writer, 3U);
        wt_pkcs11_put_bytes(&writer, (const uint8_t*)"key", 3U);
        wt_pkcs11_put_u32(&writer, UINT32_MAX);
        wt_pkcs11_put_bytes(&writer, NULL, 0U);
    }
    else if (g_reply == REPLY_ATTRIBUTE_OBJECT_INVALID) {
        wt_pkcs11_put_u32(&writer, 1U);
        wt_pkcs11_put_u32(&writer, sizeof(CK_OBJECT_CLASS));
        wt_pkcs11_put_bytes(&writer, g_terminal_attribute_value,
                            sizeof(g_terminal_attribute_value));
    }
    if (writer.error != 0) {
        return -1;
    }
    *response_len = writer.used;
    return 0;
}

void wt_pkcs11_psa_close(void)
{
}

static int request_begin(wt_pkcs11_reader_t* reader, uint32_t function)
{
    wt_pkcs11_reader_init(reader, g_request, g_request_len);
    return wt_pkcs11_get_u32(reader) == WT_PKCS11_WIRE_MAGIC &&
           wt_pkcs11_get_u32(reader) == WT_PKCS11_WIRE_VERSION &&
           wt_pkcs11_get_u32(reader) == function && reader->error == 0;
}

static int get_blob(wt_pkcs11_reader_t* reader, const uint8_t* expected,
                    size_t expected_len)
{
    size_t length = 0U;
    uint8_t* data = wt_pkcs11_get_bytes(reader, &length);

    return reader->error == 0 && length == expected_len &&
           (length == 0U || memcmp(data, expected, length) == 0);
}

static int request_done(const wt_pkcs11_reader_t* reader)
{
    return reader->error == 0 && reader->used == reader->length;
}

static void test_lists(CK_FUNCTION_LIST_PTR fn)
{
    CK_SLOT_ID slots[2] = { 0U, 0U };
    CK_MECHANISM_TYPE mechanisms[2] = { 0U, 0U };
    CK_OBJECT_HANDLE objects[2] = { 0U, 0U };
    CK_ULONG count;

    g_reply = REPLY_SLOT_VALID;
    count = 2U;
    check(fn->C_GetSlotList(CK_TRUE, slots, &count) == CKR_OK &&
              count == 1U && slots[0] == 7U,
          "valid provider slot list decodes");

    g_reply = REPLY_SLOT_HUGE;
    count = 2U;
    check(fn->C_GetSlotList(CK_TRUE, slots, &count) == CKR_DEVICE_ERROR,
          "provider list above the protocol maximum fails closed");

    g_reply = REPLY_SLOT_TRUNCATED;
    count = 2U;
    check(fn->C_GetSlotList(CK_TRUE, slots, &count) == CKR_DEVICE_ERROR,
          "provider list count exceeding its frame fails closed");

    g_reply = REPLY_SLOT_HUGE;
    count = 2U;
    check(fn->C_GetMechanismList(1U, mechanisms, &count) == CKR_DEVICE_ERROR,
          "provider mechanism count above the protocol maximum fails closed");

    g_reply = REPLY_FIND_HUGE;
    count = 0U;
    check(fn->C_FindObjects(9U, objects, 2U, &count) == CKR_DEVICE_ERROR,
          "provider object count above the protocol maximum fails closed");
}

static CK_RV test_notify(CK_SESSION_HANDLE session, CK_NOTIFICATION event,
                         CK_VOID_PTR application)
{
    (void)session;
    (void)event;
    (void)application;
    return CKR_OK;
}

static void test_open_session(CK_FUNCTION_LIST_PTR fn)
{
    static int application_data;
    CK_SESSION_HANDLE session = 0U;
    wt_pkcs11_reader_t reader;

    g_reply = REPLY_OBJECT;
    check(fn->C_OpenSession(3U, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            &application_data, test_notify, &session) ==
              CKR_OK && session == 77U &&
              request_begin(&reader, WT_P11_OPEN_SESSION) &&
              wt_pkcs11_get_u32(&reader) == 3U &&
              wt_pkcs11_get_u32(&reader) ==
                  (CKF_SERIAL_SESSION | CKF_RW_SESSION) &&
              wt_pkcs11_get_u32(&reader) == 1U && request_done(&reader),
          "open session accepts and does not forward callback arguments");

    g_reply = REPLY_SESSION_PARALLEL;
    check(fn->C_OpenSession(3U, 0U, NULL, NULL, NULL) ==
              CKR_SESSION_PARALLEL_NOT_SUPPORTED &&
              request_begin(&reader, WT_P11_OPEN_SESSION) &&
              wt_pkcs11_get_u32(&reader) == 3U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 0U && request_done(&reader),
          "NULL session output is left to wolfPKCS11's check order");
}

static void test_template(CK_FUNCTION_LIST_PTR fn)
{
    static const uint8_t label[] = { 'k', 'e', 'y' };
    CK_ATTRIBUTE attribute;
    CK_OBJECT_HANDLE object = 0U;
    wt_pkcs11_reader_t reader;

    attribute.type = CKA_LABEL;
    attribute.pValue = (void*)label;
    attribute.ulValueLen = sizeof(label);
    g_reply = REPLY_OBJECT;
    check(fn->C_CreateObject(9U, &attribute, 1U, &object) == CKR_OK &&
              object == 77U &&
              request_begin(&reader, WT_P11_CREATE_OBJECT) &&
              wt_pkcs11_get_u32(&reader) == 9U &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              wt_pkcs11_get_u32(&reader) == CKA_LABEL &&
              wt_pkcs11_get_u32(&reader) == sizeof(label) &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, label, sizeof(label)) &&
              request_done(&reader),
          "object template serializes byte-exactly");
}

static void test_unavailable_length(CK_FUNCTION_LIST_PTR fn)
{
    CK_ULONG size = 0U;
    CK_ATTRIBUTE attribute;
    CK_OBJECT_CLASS object_class = CKO_DATA;

    g_reply = REPLY_SIZE_UNAVAILABLE;
    check(fn->C_GetObjectSize(9U, 77U, &size) == CKR_OK &&
              size == CK_UNAVAILABLE_INFORMATION,
          "object size preserves the unavailable sentinel");

    attribute.type = CKA_PRIVATE_EXPONENT;
    attribute.pValue = NULL;
    attribute.ulValueLen = 0U;
    g_reply = REPLY_ATTRIBUTE_UNAVAILABLE;
    check(fn->C_GetAttributeValue(9U, 77U, &attribute, 1U) == CKR_OK &&
              attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION,
          "attribute length preserves the unavailable sentinel");

    attribute.type = CKA_CLASS;
    attribute.pValue = &object_class;
    attribute.ulValueLen = sizeof(object_class);
    g_reply = REPLY_ATTRIBUTE_OBJECT_INVALID;
    check(fn->C_GetAttributeValue(9U, 77U, &attribute, 1U) ==
              CKR_OBJECT_HANDLE_INVALID && object_class == CKO_DATA &&
              attribute.ulValueLen == sizeof(object_class),
          "terminal attribute errors discard output and preserve status");
}

static void test_partial_attribute_statuses(CK_FUNCTION_LIST_PTR fn)
{
    CK_ATTRIBUTE attributes[2];
    uint8_t short_value[2] = { 0xa5U, 0xa5U };
    uint8_t valid_value[3] = { 0U, 0U, 0U };
    uint8_t unavailable_value[3] = { 0xa5U, 0xa5U, 0xa5U };

    attributes[0].type = CKA_APPLICATION;
    attributes[0].pValue = short_value;
    attributes[0].ulValueLen = sizeof(short_value);
    attributes[1].type = CKA_LABEL;
    attributes[1].pValue = valid_value;
    attributes[1].ulValueLen = sizeof(valid_value);
    g_reply = REPLY_ATTRIBUTE_BUFFER_TOO_SMALL;
    check(fn->C_GetAttributeValue(9U, 77U, attributes, 2U) ==
              CKR_BUFFER_TOO_SMALL &&
              attributes[0].ulValueLen == 3U &&
              short_value[0] == 0xa5U && short_value[1] == 0xa5U &&
              attributes[1].ulValueLen == 3U &&
              memcmp(valid_value, "key", 3U) == 0,
          "buffer-too-small status preserves valid peer output");

    attributes[0].type = CKA_LABEL;
    attributes[0].pValue = valid_value;
    attributes[0].ulValueLen = sizeof(valid_value);
    attributes[1].type = CKA_APPLICATION;
    attributes[1].pValue = unavailable_value;
    attributes[1].ulValueLen = sizeof(unavailable_value);
    (void)memset(valid_value, 0, sizeof(valid_value));
    g_reply = REPLY_ATTRIBUTE_TYPE_INVALID;
    check(fn->C_GetAttributeValue(9U, 77U, attributes, 2U) ==
              CKR_ATTRIBUTE_TYPE_INVALID &&
              attributes[0].ulValueLen == 3U &&
              memcmp(valid_value, "key", 3U) == 0 &&
              attributes[1].ulValueLen == CK_UNAVAILABLE_INFORMATION &&
              unavailable_value[0] == 0xa5U,
          "invalid-attribute status preserves valid peer output");

    attributes[1].type = CKA_PRIVATE_EXPONENT;
    attributes[1].ulValueLen = sizeof(unavailable_value);
    (void)memset(valid_value, 0, sizeof(valid_value));
    g_reply = REPLY_ATTRIBUTE_SENSITIVE;
    check(fn->C_GetAttributeValue(9U, 77U, attributes, 2U) ==
              CKR_ATTRIBUTE_SENSITIVE &&
              attributes[0].ulValueLen == 3U &&
              memcmp(valid_value, "key", 3U) == 0 &&
              attributes[1].ulValueLen == CK_UNAVAILABLE_INFORMATION &&
              unavailable_value[0] == 0xa5U,
          "sensitive-attribute status preserves valid peer output");
}

static int mechanism_prefix(wt_pkcs11_reader_t* reader, uint32_t function,
                            CK_ULONG mechanism, uint32_t kind)
{
    return request_begin(reader, function) &&
           wt_pkcs11_get_u32(reader) == 9U &&
           wt_pkcs11_get_u32(reader) == 1U &&
           wt_pkcs11_get_u32(reader) == mechanism &&
           wt_pkcs11_get_u32(reader) == kind && reader->error == 0;
}

static void test_mechanisms(CK_FUNCTION_LIST_PTR fn)
{
    uint8_t counter[16];
    uint8_t iv[12];
    uint8_t aad[7];
    uint8_t shared[3];
    uint8_t public_data[5];
    CK_AES_CTR_PARAMS ctr;
    CK_GCM_PARAMS gcm;
    CK_CCM_PARAMS ccm;
    CK_ECDH1_DERIVE_PARAMS ecdh;
    CK_MECHANISM mechanism;
    CK_OBJECT_HANDLE key = 0U;
    wt_pkcs11_reader_t reader;

    (void)memset(counter, 0x11, sizeof(counter));
    (void)memset(iv, 0x22, sizeof(iv));
    (void)memset(aad, 0x33, sizeof(aad));
    (void)memset(shared, 0x44, sizeof(shared));
    (void)memset(public_data, 0x55, sizeof(public_data));
    mechanism.mechanism = CKM_SHA256;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0U;
    g_reply = REPLY_OK;
    check(fn->C_DigestInit(9U, &mechanism) == CKR_OK &&
              mechanism_prefix(&reader, WT_P11_DIGEST_INIT, CKM_SHA256, 0U) &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              get_blob(&reader, NULL, 0U) && request_done(&reader),
          "raw mechanism serializes byte-exactly");

    (void)memset(&ctr, 0, sizeof(ctr));
    ctr.ulCounterBits = 128U;
    (void)memcpy(ctr.cb, counter, sizeof(counter));
    mechanism.mechanism = CKM_AES_CTR;
    mechanism.pParameter = &ctr;
    mechanism.ulParameterLen = sizeof(ctr);
    check(fn->C_EncryptInit(9U, &mechanism, 12U) == CKR_OK &&
              mechanism_prefix(&reader, WT_P11_ENCRYPT_INIT, CKM_AES_CTR,
                               1U) &&
              wt_pkcs11_get_u32(&reader) == 128U &&
              get_blob(&reader, counter, sizeof(counter)) &&
              wt_pkcs11_get_u32(&reader) == 12U && request_done(&reader),
          "AES-CTR mechanism serializes byte-exactly");

    (void)memset(&gcm, 0, sizeof(gcm));
    gcm.pIv = iv;
    gcm.ulIvLen = sizeof(iv);
    gcm.ulIvBits = 96U;
    gcm.pAAD = aad;
    gcm.ulAADLen = sizeof(aad);
    gcm.ulTagBits = 128U;
    mechanism.mechanism = CKM_AES_GCM;
    mechanism.pParameter = &gcm;
    mechanism.ulParameterLen = sizeof(gcm);
    check(fn->C_EncryptInit(9U, &mechanism, 12U) == CKR_OK &&
              mechanism_prefix(&reader, WT_P11_ENCRYPT_INIT, CKM_AES_GCM,
                               2U) &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, iv, sizeof(iv)) &&
              wt_pkcs11_get_u32(&reader) == 96U &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, aad, sizeof(aad)) &&
              wt_pkcs11_get_u32(&reader) == 128U &&
              wt_pkcs11_get_u32(&reader) == 12U && request_done(&reader),
          "AES-GCM mechanism serializes byte-exactly");

    (void)memset(&ccm, 0, sizeof(ccm));
    ccm.ulDataLen = 41U;
    ccm.pIv = iv;
    ccm.ulIvLen = sizeof(iv);
    ccm.pAAD = aad;
    ccm.ulAADLen = sizeof(aad);
    ccm.ulMacLen = 16U;
    mechanism.mechanism = CKM_AES_CCM;
    mechanism.pParameter = &ccm;
    mechanism.ulParameterLen = sizeof(ccm);
    check(fn->C_EncryptInit(9U, &mechanism, 12U) == CKR_OK &&
              mechanism_prefix(&reader, WT_P11_ENCRYPT_INIT, CKM_AES_CCM,
                               3U) &&
              wt_pkcs11_get_u32(&reader) == 41U &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, iv, sizeof(iv)) &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, aad, sizeof(aad)) &&
              wt_pkcs11_get_u32(&reader) == 16U &&
              wt_pkcs11_get_u32(&reader) == 12U && request_done(&reader),
          "AES-CCM mechanism serializes byte-exactly");

    (void)memset(&ecdh, 0, sizeof(ecdh));
    ecdh.kdf = CKD_NULL;
    ecdh.pSharedData = shared;
    ecdh.ulSharedDataLen = sizeof(shared);
    ecdh.pPublicData = public_data;
    ecdh.ulPublicDataLen = sizeof(public_data);
    mechanism.mechanism = CKM_ECDH1_DERIVE;
    mechanism.pParameter = &ecdh;
    mechanism.ulParameterLen = sizeof(ecdh);
    g_reply = REPLY_OBJECT;
    check(fn->C_DeriveKey(9U, &mechanism, 12U, NULL, 0U, &key) == CKR_OK &&
              key == 77U &&
              mechanism_prefix(&reader, WT_P11_DERIVE_KEY,
                               CKM_ECDH1_DERIVE, 4U) &&
              wt_pkcs11_get_u32(&reader) == CKD_NULL &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, shared, sizeof(shared)) &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, public_data, sizeof(public_data)) &&
              wt_pkcs11_get_u32(&reader) == 12U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 0U && request_done(&reader),
          "ECDH mechanism and NULL template serialize byte-exactly");

    ecdh.pSharedData = NULL;
    ecdh.ulSharedDataLen = 0U;
    check(fn->C_DeriveKey(9U, &mechanism, 12U, NULL, 0U, &key) == CKR_OK &&
              mechanism_prefix(&reader, WT_P11_DERIVE_KEY,
                               CKM_ECDH1_DERIVE, 4U) &&
              wt_pkcs11_get_u32(&reader) == CKD_NULL &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              get_blob(&reader, NULL, 0U),
          "NULL empty ECDH shared data is forwarded as NULL");
    ecdh.pSharedData = shared;
    check(fn->C_DeriveKey(9U, &mechanism, 12U, NULL, 0U, &key) == CKR_OK &&
              mechanism_prefix(&reader, WT_P11_DERIVE_KEY,
                               CKM_ECDH1_DERIVE, 4U) &&
              wt_pkcs11_get_u32(&reader) == CKD_NULL &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, NULL, 0U),
          "non-NULL empty ECDH shared data is forwarded as non-NULL");
}

static void test_null_pointers(CK_FUNCTION_LIST_PTR fn)
{
    static CK_BYTE empty[1];
    CK_OBJECT_HANDLE object = 0U;
    CK_ULONG count = 1U;
    CK_MECHANISM mechanism;
    wt_pkcs11_reader_t reader;

    g_reply = REPLY_ARGUMENTS_BAD;
    check(fn->C_GenerateRandom(9U, NULL, 0U) == CKR_ARGUMENTS_BAD &&
              request_begin(&reader, WT_P11_GENERATE_RANDOM) &&
              wt_pkcs11_get_u32(&reader) == 9U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 0U && request_done(&reader),
          "a NULL random output is forwarded as NULL");
    check(fn->C_FindObjects(9U, NULL, 0U, &count) == CKR_ARGUMENTS_BAD &&
              request_begin(&reader, WT_P11_FIND_OBJECTS) &&
              wt_pkcs11_get_u32(&reader) == 9U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 0U && request_done(&reader),
          "a NULL object list is forwarded as NULL");

    g_reply = REPLY_OK;
    check(fn->C_SeedRandom(9U, NULL, 0U) == CKR_OK &&
              request_begin(&reader, WT_P11_SEED_RANDOM) &&
              wt_pkcs11_get_u32(&reader) == 9U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              get_blob(&reader, NULL, 0U) && request_done(&reader),
          "a NULL empty buffer is forwarded as NULL");
    check(fn->C_SeedRandom(9U, empty, 0U) == CKR_OK &&
              request_begin(&reader, WT_P11_SEED_RANDOM) &&
              wt_pkcs11_get_u32(&reader) == 9U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, NULL, 0U) && request_done(&reader),
          "a non-NULL empty buffer is forwarded as non-NULL");
    check(fn->C_Login(9U, CKU_USER, NULL, 0U) == CKR_OK &&
              request_begin(&reader, WT_P11_LOGIN) &&
              wt_pkcs11_get_u32(&reader) == 9U &&
              wt_pkcs11_get_u32(&reader) == CKU_USER &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              get_blob(&reader, NULL, 0U) && request_done(&reader),
          "a NULL PIN is forwarded as NULL");

    mechanism.mechanism = CKM_SHA256;
    mechanism.pParameter = empty;
    mechanism.ulParameterLen = 0U;
    check(fn->C_DigestInit(9U, &mechanism) == CKR_OK &&
              mechanism_prefix(&reader, WT_P11_DIGEST_INIT, CKM_SHA256, 0U) &&
              wt_pkcs11_get_u32(&reader) == 1U &&
              get_blob(&reader, NULL, 0U) && request_done(&reader),
          "an empty non-NULL mechanism parameter is forwarded as non-NULL");

    g_reply = REPLY_OBJECT;
    check(fn->C_CreateObject(9U, NULL, 0U, &object) == CKR_OK &&
              request_begin(&reader, WT_P11_CREATE_OBJECT) &&
              wt_pkcs11_get_u32(&reader) == 9U &&
              wt_pkcs11_get_u32(&reader) == 0U &&
              wt_pkcs11_get_u32(&reader) == 0U && request_done(&reader),
          "a NULL template is forwarded as NULL");
}

int main(void)
{
    CK_FUNCTION_LIST_PTR functions = NULL;

    check(C_GetFunctionList(&functions) == CKR_OK && functions != NULL,
          "proxy exports its PKCS11 function list");
    if (functions != NULL) {
        test_lists(functions);
        test_open_session(functions);
        test_template(functions);
        test_unavailable_length(functions);
        test_partial_attribute_statuses(functions);
        test_mechanisms(functions);
        test_null_pointers(functions);
    }
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: PKCS11 proxy wire bounds, templates, and mechanisms\n");
    return 0;
}
