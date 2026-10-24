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

#include "wolftrust/pkcs11_provider.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/pkcs11/pkcs11_wire.h"

#include "wolfpkcs11/pkcs11.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_BUFFER_SIZE 128U
#define TEST_CANARY      0xa5U
#define TEST_TEMPLATE_MAX 32U

extern unsigned int g_provider_test_calls;
extern unsigned int g_provider_test_aligned;
extern unsigned int g_provider_test_get_attribute_calls;
extern unsigned int g_provider_test_ecdh_valid;
extern unsigned int g_provider_test_pin_checks;
extern unsigned int g_provider_test_token_initialized;
extern unsigned int g_provider_test_open_output;
extern unsigned int g_provider_test_open_callbacks;
extern unsigned int g_provider_test_null_seen;
extern CK_RV g_provider_test_after_pin_rv;

#define TEST_PIN_FLAGS (CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | \
    CKF_USER_PIN_LOCKED | CKF_SO_PIN_COUNT_LOW | CKF_SO_PIN_FINAL_TRY | \
    CKF_SO_PIN_LOCKED)

static int g_failures;

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

static void request_begin(wt_pkcs11_writer_t* writer, uint8_t* request,
                          uint32_t function)
{
    wt_pkcs11_writer_init(writer, request, TEST_BUFFER_SIZE);
    wt_pkcs11_put_u32(writer, WT_PKCS11_WIRE_MAGIC);
    wt_pkcs11_put_u32(writer, WT_PKCS11_WIRE_VERSION);
    wt_pkcs11_put_u32(writer, function);
}

static uint32_t response_rv(uint8_t* response, size_t response_len)
{
    wt_pkcs11_reader_t reader;
    uint32_t rv;

    wt_pkcs11_reader_init(&reader, response, response_len);
    if (wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_MAGIC ||
            wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_VERSION) {
        return UINT32_MAX;
    }
    rv = wt_pkcs11_get_u32(&reader);
    return reader.error == 0 ? rv : UINT32_MAX;
}

static int dispatch_invalid(uint8_t* request, size_t request_len,
                            size_t response_cap, int expected_rc,
                            int expect_response)
{
    uint8_t guarded[TEST_BUFFER_SIZE + 2U];
    size_t response_len = 0U;
    int rc;

    (void)memset(guarded, TEST_CANARY, sizeof(guarded));
    g_provider_test_calls = 0U;
    rc = wt_pkcs11_provider_dispatch(request, request_len, &guarded[1],
                                     response_cap, &response_len, NULL);
    if (rc != expected_rc || g_provider_test_calls != 0U ||
            guarded[0] != TEST_CANARY ||
            guarded[response_cap + 1U] != TEST_CANARY) {
        return 0;
    }
    if (expect_response != 0) {
        return response_rv(&guarded[1], response_len) == CKR_ARGUMENTS_BAD;
    }
    return response_len == 0U;
}

static void test_truncated_header(void)
{
    uint8_t request[4];
    wt_pkcs11_writer_t writer;

    wt_pkcs11_writer_init(&writer, request, sizeof(request));
    wt_pkcs11_put_u32(&writer, WT_PKCS11_WIRE_MAGIC);
    check(dispatch_invalid(request, writer.used, TEST_BUFFER_SIZE, -1, 0),
          "truncated provider header fails before PKCS11 dispatch");
}

static size_t oversized_template_request(uint8_t* request)
{
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_CREATE_OBJECT);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, TEST_TEMPLATE_MAX + 1U);
    return writer.used;
}

static void test_oversized_template(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    size_t request_len = oversized_template_request(request);

    check(dispatch_invalid(request, request_len, TEST_BUFFER_SIZE, 0, 1),
          "oversized provider template fails before C_CreateObject");
}

static void test_oversized_get_attribute_template(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_GET_ATTRIBUTE_VALUE);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 7U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, TEST_TEMPLATE_MAX + 1U);
    g_provider_test_get_attribute_calls = 0U;
    check(dispatch_invalid(request, writer.used, TEST_BUFFER_SIZE, 0, 1) &&
              g_provider_test_get_attribute_calls == 0U,
          "oversized get-attribute template stays within provider bounds");
}

static void test_truncated_blob(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_INIT_PIN);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 4U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 16U);
    check(dispatch_invalid(request, writer.used, TEST_BUFFER_SIZE, 0, 1),
          "blob length beyond provider frame fails before C_InitPIN");
}

static void test_truncated_mechanism(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_ENCRYPT_INIT);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, CKM_AES_CTR);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 128U);
    wt_pkcs11_put_u32(&writer, 16U);
    check(dispatch_invalid(request, writer.used, TEST_BUFFER_SIZE, 0, 1),
          "short mechanism payload fails before C_EncryptInit");
}

static int raw_mechanism_is_rejected(CK_MECHANISM_TYPE mechanism)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t parameter[8] = { 0U };
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_ENCRYPT_INIT);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, (uint32_t)mechanism);
    wt_pkcs11_put_u32(&writer, 0U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, parameter, sizeof(parameter));
    wt_pkcs11_put_u32(&writer, 1U);
    return dispatch_invalid(request, writer.used, TEST_BUFFER_SIZE, 0, 1);
}

static void test_mechanism_kind_mismatch(void)
{
    check(raw_mechanism_is_rejected(CKM_AES_CTR) &&
              raw_mechanism_is_rejected(CKM_AES_GCM) &&
              raw_mechanism_is_rejected(CKM_AES_CCM) &&
              raw_mechanism_is_rejected(CKM_ECDH1_DERIVE),
          "pointer-bearing mechanisms reject a mismatched raw wire tag");
    check(raw_mechanism_is_rejected(CKM_RSA_PKCS_OAEP) &&
              raw_mechanism_is_rejected(CKM_HKDF_DERIVE) &&
              raw_mechanism_is_rejected(CKM_HKDF_DATA) &&
              raw_mechanism_is_rejected(CKM_AES_CBC_ENCRYPT_DATA),
          "unsupported nested-pointer mechanisms fail closed");
}

static int ecdh_shared_data_is_null(uint32_t shared_present)
{
    static const uint8_t point[] = { 0x04U, 0x11U, 0x22U };
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    size_t response_len = 0U;
    int rc;

    request_begin(&writer, request, WT_P11_DERIVE_KEY);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, CKM_ECDH1_DERIVE);
    wt_pkcs11_put_u32(&writer, WT_P11_MECH_ECDH);
    wt_pkcs11_put_u32(&writer, CKD_NULL);
    wt_pkcs11_put_u32(&writer, shared_present);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, point, sizeof(point));
    wt_pkcs11_put_u32(&writer, 12U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 0U);
    g_provider_test_calls = 0U;
    g_provider_test_ecdh_valid = 0U;
    g_provider_test_null_seen = 2U;
    rc = wt_pkcs11_provider_dispatch(request, writer.used, response,
                                     sizeof(response), &response_len, NULL);
    if (rc != 0 || response_rv(response, response_len) != CKR_OK ||
            g_provider_test_calls != 1U || g_provider_test_ecdh_valid == 0U) {
        return -1;
    }
    return g_provider_test_null_seen == 1U ? 1 : 0;
}

static void test_ecdh_shared_data_presence(void)
{
    check(ecdh_shared_data_is_null(0U) == 1,
          "NULL empty ECDH shared data reaches wolfPKCS11 as NULL");
    check(ecdh_shared_data_is_null(1U) == 0,
          "non-NULL empty ECDH shared data reaches wolfPKCS11 as non-NULL");
}

static void test_short_response(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    size_t request_len = oversized_template_request(request);

    check(dispatch_invalid(request, request_len, 12U, -1, 0),
          "short provider response preserves its bounds");
}

static void test_aligned_template_value(void)
{
    uint64_t request_words[TEST_BUFFER_SIZE / sizeof(uint64_t)];
    uint8_t response[TEST_BUFFER_SIZE];
    uint8_t* request = (uint8_t*)request_words;
    wt_pkcs11_writer_t writer;
    CK_OBJECT_CLASS object_class = CKO_DATA;
    size_t response_len = 0U;
    int rc;

    request_begin(&writer, request, WT_P11_CREATE_OBJECT);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, CKA_CLASS);
    wt_pkcs11_put_u32(&writer, sizeof(object_class));
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, &object_class, sizeof(object_class));
    g_provider_test_calls = 0U;
    g_provider_test_aligned = 0U;
    rc = wt_pkcs11_provider_dispatch(request, writer.used, response,
                                     sizeof(response), &response_len, NULL);
    check(rc == 0 && g_provider_test_calls == 1U &&
              g_provider_test_aligned != 0U &&
              response_rv(response, response_len) == CKR_OK,
          "provider passes aligned scalar attribute values to PKCS11");
}

static size_t get_attribute_request(uint8_t* request)
{
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_GET_ATTRIBUTE_VALUE);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 7U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, CKA_LABEL);
    wt_pkcs11_put_u32(&writer, WT_PKCS11_MESSAGE_MAX + 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    return writer.used;
}

static int get_attribute_response(const uint8_t* response,
                                  size_t response_len, uint32_t expected_rv,
                                  size_t expected_value_len)
{
    wt_pkcs11_reader_t reader;
    uint8_t* value;
    size_t value_len;

    wt_pkcs11_reader_init(&reader, (uint8_t*)response, response_len);
    if (wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_MAGIC ||
            wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_VERSION ||
            wt_pkcs11_get_u32(&reader) != expected_rv ||
            wt_pkcs11_get_u32(&reader) != 1U ||
            wt_pkcs11_get_u32(&reader) != 3U) {
        return 0;
    }
    value = wt_pkcs11_get_bytes(&reader, &value_len);
    return reader.error == 0 && reader.used == reader.length &&
           value_len == expected_value_len &&
           (value_len == 0U || memcmp(value, "key", value_len) == 0);
}

static void test_large_attribute_capacity(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    size_t request_len = get_attribute_request(request);
    size_t response_len = 0U;
    int rc;

    g_provider_test_get_attribute_calls = 0U;
    rc = wt_pkcs11_provider_dispatch(request, request_len, response,
                                     sizeof(response), &response_len, NULL);
    check(rc == 0 && g_provider_test_get_attribute_calls == 2U &&
              get_attribute_response(response, response_len, CKR_OK, 3U),
          "large attribute capacity stages only the returned value");
}

static void test_attribute_response_boundary(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    size_t request_len = get_attribute_request(request);
    size_t response_len = 0U;
    int rc;

    g_provider_test_get_attribute_calls = 0U;
    rc = wt_pkcs11_provider_dispatch(request, request_len, response, 24U,
                                     &response_len, NULL);
    check(rc == 0 && g_provider_test_get_attribute_calls == 1U &&
              get_attribute_response(response, response_len,
                                     CKR_DEVICE_MEMORY, 0U),
          "attribute value beyond the response frame fails safely");
}

static void test_attribute_caller_buffer_too_small(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    uint8_t* value;
    size_t value_len;
    size_t response_len = 0U;
    int valid;
    int rc;

    request_begin(&writer, request, WT_P11_GET_ATTRIBUTE_VALUE);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 7U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 2U);
    wt_pkcs11_put_u32(&writer, CKA_LABEL);
    wt_pkcs11_put_u32(&writer, 2U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    wt_pkcs11_put_u32(&writer, CKA_LABEL);
    wt_pkcs11_put_u32(&writer, 3U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);

    g_provider_test_get_attribute_calls = 0U;
    rc = wt_pkcs11_provider_dispatch(request, writer.used, response,
                                     sizeof(response), &response_len, NULL);
    wt_pkcs11_reader_init(&reader, response, response_len);
    valid = wt_pkcs11_get_u32(&reader) == WT_PKCS11_WIRE_MAGIC &&
        wt_pkcs11_get_u32(&reader) == WT_PKCS11_WIRE_VERSION &&
        wt_pkcs11_get_u32(&reader) == CKR_BUFFER_TOO_SMALL &&
        wt_pkcs11_get_u32(&reader) == 2U &&
        wt_pkcs11_get_u32(&reader) == 3U;
    value = wt_pkcs11_get_bytes(&reader, &value_len);
    valid = valid && value_len == 0U;
    valid = valid && wt_pkcs11_get_u32(&reader) == 3U;
    value = wt_pkcs11_get_bytes(&reader, &value_len);
    valid = valid && reader.error == 0 && reader.used == reader.length &&
        value_len == 3U && memcmp(value, "key", 3U) == 0;
    check(rc == 0 && g_provider_test_get_attribute_calls == 2U && valid,
          "mixed attribute capacities preserve buffer-too-small semantics");
}

static void test_attribute_type_invalid_with_valid_peer(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    uint8_t* value;
    size_t value_len;
    size_t response_len = 0U;
    int valid;
    int rc;

    request_begin(&writer, request, WT_P11_GET_ATTRIBUTE_VALUE);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 7U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 2U);
    wt_pkcs11_put_u32(&writer, CKA_LABEL);
    wt_pkcs11_put_u32(&writer, 3U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    wt_pkcs11_put_u32(&writer, CKA_APPLICATION);
    wt_pkcs11_put_u32(&writer, 3U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);

    g_provider_test_get_attribute_calls = 0U;
    rc = wt_pkcs11_provider_dispatch(request, writer.used, response,
                                     sizeof(response), &response_len, NULL);
    wt_pkcs11_reader_init(&reader, response, response_len);
    valid = wt_pkcs11_get_u32(&reader) == WT_PKCS11_WIRE_MAGIC &&
        wt_pkcs11_get_u32(&reader) == WT_PKCS11_WIRE_VERSION &&
        wt_pkcs11_get_u32(&reader) == CKR_ATTRIBUTE_TYPE_INVALID &&
        wt_pkcs11_get_u32(&reader) == 2U &&
        wt_pkcs11_get_u32(&reader) == 3U;
    value = wt_pkcs11_get_bytes(&reader, &value_len);
    valid = valid && value_len == 3U && memcmp(value, "key", 3U) == 0;
    valid = valid &&
        wt_pkcs11_get_u32(&reader) == (uint32_t)CK_UNAVAILABLE_INFORMATION;
    value = wt_pkcs11_get_bytes(&reader, &value_len);
    valid = valid && reader.error == 0 && reader.used == reader.length &&
        value_len == 0U;
    check(rc == 0 && g_provider_test_get_attribute_calls == 2U && valid,
          "invalid attribute preserves valid peer output and status");
}

static void test_sensitive_attribute_with_valid_peer(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    uint8_t* value;
    size_t value_len;
    size_t response_len = 0U;
    int valid;
    int rc;

    request_begin(&writer, request, WT_P11_GET_ATTRIBUTE_VALUE);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 7U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 2U);
    wt_pkcs11_put_u32(&writer, CKA_LABEL);
    wt_pkcs11_put_u32(&writer, 3U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    wt_pkcs11_put_u32(&writer, CKA_PRIVATE_EXPONENT);
    wt_pkcs11_put_u32(&writer, 3U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);

    g_provider_test_get_attribute_calls = 0U;
    rc = wt_pkcs11_provider_dispatch(request, writer.used, response,
                                     sizeof(response), &response_len, NULL);
    wt_pkcs11_reader_init(&reader, response, response_len);
    valid = wt_pkcs11_get_u32(&reader) == WT_PKCS11_WIRE_MAGIC &&
        wt_pkcs11_get_u32(&reader) == WT_PKCS11_WIRE_VERSION &&
        wt_pkcs11_get_u32(&reader) == CKR_ATTRIBUTE_SENSITIVE &&
        wt_pkcs11_get_u32(&reader) == 2U &&
        wt_pkcs11_get_u32(&reader) == 3U;
    value = wt_pkcs11_get_bytes(&reader, &value_len);
    valid = valid && value_len == 3U && memcmp(value, "key", 3U) == 0;
    valid = valid &&
        wt_pkcs11_get_u32(&reader) == (uint32_t)CK_UNAVAILABLE_INFORMATION;
    value = wt_pkcs11_get_bytes(&reader, &value_len);
    valid = valid && reader.error == 0 && reader.used == reader.length &&
        value_len == 0U;
    check(rc == 0 && g_provider_test_get_attribute_calls == 2U && valid,
          "sensitive attribute preserves valid peer output and status");
}

static uint32_t dispatch_rv(uint8_t* request, size_t request_len)
{
    uint8_t response[TEST_BUFFER_SIZE];
    size_t response_len = 0U;

    if (wt_pkcs11_provider_dispatch(request, request_len, response,
                                    sizeof(response), &response_len,
                                    NULL) != 0) {
        return UINT32_MAX;
    }
    return response_rv(response, response_len);
}

static void put_pin(wt_pkcs11_writer_t* writer, const char* pin)
{
    size_t length = strlen(pin);

    wt_pkcs11_put_u32(writer, (uint32_t)length);
    wt_pkcs11_put_u32(writer, 1U);
    wt_pkcs11_put_bytes(writer, pin, length);
}

static uint32_t pin_login(uint32_t session, uint32_t user, const char* pin)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_LOGIN);
    wt_pkcs11_put_u32(&writer, session);
    wt_pkcs11_put_u32(&writer, user);
    put_pin(&writer, pin);
    return dispatch_rv(request, writer.used);
}

static uint32_t pin_login_null(uint32_t session, uint32_t user)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_LOGIN);
    wt_pkcs11_put_u32(&writer, session);
    wt_pkcs11_put_u32(&writer, user);
    wt_pkcs11_put_u32(&writer, 0U);
    wt_pkcs11_put_u32(&writer, 0U);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    return dispatch_rv(request, writer.used);
}

static uint32_t pin_logout(uint32_t session)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_LOGOUT);
    wt_pkcs11_put_u32(&writer, session);
    return dispatch_rv(request, writer.used);
}

static uint32_t pin_set(uint32_t session, const char* old_pin,
                        const char* new_pin)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_SET_PIN);
    wt_pkcs11_put_u32(&writer, session);
    put_pin(&writer, old_pin);
    put_pin(&writer, new_pin);
    return dispatch_rv(request, writer.used);
}

static uint32_t pin_init(uint32_t session, const char* pin)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_INIT_PIN);
    wt_pkcs11_put_u32(&writer, session);
    put_pin(&writer, pin);
    return dispatch_rv(request, writer.used);
}

static uint32_t token_init(const char* so_pin)
{
    static const uint8_t label[32] = { 't', 'o', 'k', 'e', 'n' };
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_INIT_TOKEN);
    wt_pkcs11_put_u32(&writer, 1U);
    put_pin(&writer, so_pin);
    wt_pkcs11_put_bytes(&writer, label, sizeof(label));
    return dispatch_rv(request, writer.used);
}

static CK_FLAGS pin_flags_for(unsigned int failures, CK_FLAGS low,
                              CK_FLAGS final_try, CK_FLAGS locked)
{
    CK_FLAGS flags = failures > 0U ? low : 0U;

    if (failures >= WT_PKCS11_PIN_MAX_FAILURES) {
        flags |= locked;
    }
    else if (failures + 1U == WT_PKCS11_PIN_MAX_FAILURES) {
        flags |= final_try;
    }
    return flags;
}

static int token_pin_counts_are(unsigned int user, unsigned int so)
{
    CK_FLAGS expected = pin_flags_for(user, CKF_USER_PIN_COUNT_LOW,
                                      CKF_USER_PIN_FINAL_TRY,
                                      CKF_USER_PIN_LOCKED) |
                        pin_flags_for(so, CKF_SO_PIN_COUNT_LOW,
                                      CKF_SO_PIN_FINAL_TRY,
                                      CKF_SO_PIN_LOCKED);
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE + sizeof(CK_TOKEN_INFO)];
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    CK_TOKEN_INFO info;
    uint8_t* data;
    size_t length = 0U;
    size_t response_len = 0U;

    request_begin(&writer, request, WT_P11_GET_TOKEN_INFO);
    wt_pkcs11_put_u32(&writer, 1U);
    if (wt_pkcs11_provider_dispatch(request, writer.used, response,
                                    sizeof(response), &response_len,
                                    NULL) != 0 ||
            response_rv(response, response_len) != CKR_OK) {
        return 0;
    }
    wt_pkcs11_reader_init(&reader, response, response_len);
    (void)wt_pkcs11_get_u32(&reader);
    (void)wt_pkcs11_get_u32(&reader);
    (void)wt_pkcs11_get_u32(&reader);
    data = wt_pkcs11_get_bytes(&reader, &length);
    if (reader.error != 0 || length != sizeof(info)) {
        return 0;
    }
    (void)memcpy(&info, data, sizeof(info));
    return (info.flags & TEST_PIN_FLAGS) == expected;
}

static uint32_t session_open(uint32_t flags, uint32_t has_output,
                             uint32_t* handle)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    size_t response_len = 0U;
    uint32_t rv;

    request_begin(&writer, request, WT_P11_OPEN_SESSION);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, flags);
    wt_pkcs11_put_u32(&writer, has_output);
    g_provider_test_calls = 0U;
    if (wt_pkcs11_provider_dispatch(request, writer.used, response,
                                    sizeof(response), &response_len,
                                    NULL) != 0) {
        return UINT32_MAX;
    }
    wt_pkcs11_reader_init(&reader, response, response_len);
    (void)wt_pkcs11_get_u32(&reader);
    (void)wt_pkcs11_get_u32(&reader);
    rv = wt_pkcs11_get_u32(&reader);
    *handle = wt_pkcs11_get_u32(&reader);
    return reader.error == 0 && reader.used == reader.length ? rv :
                                                               UINT32_MAX;
}

static void test_open_session_arguments(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    uint32_t handle = 0U;

    check(session_open(CKF_SERIAL_SESSION | CKF_RW_SESSION, 1U, &handle) ==
              CKR_OK && handle == 2U && g_provider_test_calls == 1U &&
              g_provider_test_open_output != 0U &&
              g_provider_test_open_callbacks == 0U,
          "open session returns the provider handle without callbacks");
    check(session_open(CKF_SERIAL_SESSION, 0U, &handle) ==
              CKR_ARGUMENTS_BAD && handle == CK_INVALID_HANDLE &&
              g_provider_test_calls == 1U &&
              g_provider_test_open_output == 0U,
          "NULL session output reaches wolfPKCS11's own argument check");
    check(session_open(0U, 0U, &handle) ==
              CKR_SESSION_PARALLEL_NOT_SUPPORTED &&
              g_provider_test_calls == 1U,
          "open session keeps wolfPKCS11's flag-before-output check order");

    request_begin(&writer, request, WT_P11_OPEN_SESSION);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, CKF_SERIAL_SESSION);
    wt_pkcs11_put_u32(&writer, 2U);
    check(dispatch_invalid(request, writer.used, TEST_BUFFER_SIZE, 0, 1),
          "malformed session output selector fails before C_OpenSession");
}

static void test_user_pin_lockout(void)
{
    unsigned int checks;
    uint32_t handle = 0U;
    uint32_t i;
    int ok = 1;

    for (i = 0U; i < WT_PKCS11_PIN_MAX_FAILURES; i++) {
        ok = ok && pin_login(1U, CKU_USER, "wrong") == CKR_PIN_INCORRECT;
    }
    checks = g_provider_test_pin_checks;
    check(ok && pin_login(1U, CKU_USER, "user-pin") == CKR_PIN_LOCKED &&
              g_provider_test_pin_checks == checks,
          "user PIN locks after the failure limit before reaching the token");
    check(token_pin_counts_are(WT_PKCS11_PIN_MAX_FAILURES, 0U),
          "token info reports the user PIN lock");
    check(pin_login(1U, CKU_USER, "ab") == CKR_PIN_LEN_RANGE &&
              pin_login_null(1U, CKU_USER) == CKR_ARGUMENTS_BAD &&
              pin_login(1U, CKU_CONTEXT_SPECIFIC, "user-pin") ==
                  CKR_OPERATION_NOT_INITIALIZED &&
              pin_login(1U, 0x99U, "user-pin") == CKR_USER_TYPE_INVALID &&
              g_provider_test_pin_checks == checks,
          "a locked PIN keeps C_Login errors raised before any PIN test");
    check(pin_set(3U, "user-pin", "next-pin") == CKR_SESSION_READ_ONLY &&
              pin_set(1U, "ab", "next-pin") == CKR_PIN_INCORRECT &&
              pin_set(1U, "user-pin", "ab") == CKR_PIN_LEN_RANGE &&
              g_provider_test_pin_checks == checks,
          "a locked PIN keeps C_SetPIN errors raised before any PIN test");
    check(session_open(CKF_SERIAL_SESSION | CKF_RW_SESSION, 1U, &handle) ==
              CKR_OK &&
              pin_login(handle, CKU_USER, "user-pin") == CKR_PIN_LOCKED &&
              g_provider_test_pin_checks == checks,
          "a new session does not reset the user PIN lock");
    check(pin_set(handle, "user-pin", "next-pin") == CKR_PIN_LOCKED &&
              g_provider_test_pin_checks == checks,
          "C_SetPIN cannot verify a locked user PIN");
    check(pin_login(handle, CKU_SO, "so-pin") == CKR_OK &&
              pin_login(handle, CKU_USER, "user-pin") ==
                  CKR_USER_ANOTHER_ALREADY_LOGGED_IN &&
              g_provider_test_pin_checks == checks + 1U,
          "a locked user PIN still reports another user logged in");
    check(pin_init(handle, "user-pin") == CKR_OK &&
              pin_logout(handle) == CKR_OK && token_pin_counts_are(0U, 0U) &&
              pin_login(handle, CKU_USER, "user-pin") == CKR_OK,
          "SO re-initialising the user PIN clears the lock");
    ok = 1;
    for (i = 0U; i < WT_PKCS11_PIN_MAX_FAILURES; i++) {
        ok = ok && pin_set(handle, "wrong", "next-pin") == CKR_PIN_INCORRECT;
    }
    check(ok && pin_logout(handle) == CKR_OK &&
              pin_login(handle, CKU_USER, "user-pin") == CKR_PIN_LOCKED,
          "failed C_SetPIN attempts count toward the user PIN lock");
    check(pin_login(handle, CKU_SO, "so-pin") == CKR_OK &&
              pin_init(handle, "user-pin") == CKR_OK &&
              pin_logout(handle) == CKR_OK,
          "SO recovers the user PIN after a C_SetPIN lock");
}

static void test_success_resets_pin_count(void)
{
    uint32_t round;
    uint32_t i;
    int ok = 1;

    for (round = 0U; round < 2U; round++) {
        for (i = 0U; i + 1U < WT_PKCS11_PIN_MAX_FAILURES; i++) {
            ok = ok && pin_login(1U, CKU_USER, "wrong") == CKR_PIN_INCORRECT;
        }
        ok = ok && token_pin_counts_are(WT_PKCS11_PIN_MAX_FAILURES - 1U, 0U) &&
             pin_login(1U, CKU_USER, "user-pin") == CKR_OK &&
             token_pin_counts_are(0U, 0U) && pin_logout(1U) == CKR_OK;
    }
    check(ok, "a correct PIN before the limit resets the failure count");
}

static void test_backend_failures_keep_count(void)
{
    int ok;

    g_provider_test_after_pin_rv = CKR_HOST_MEMORY;
    check(pin_login(1U, CKU_USER, "user-pin") == CKR_HOST_MEMORY &&
              token_pin_counts_are(0U, 0U),
          "a backend failure after a correct PIN consumes no attempt");
    if (WT_PKCS11_PIN_MAX_FAILURES > 1U) {
        g_provider_test_after_pin_rv = CKR_OK;
        ok = pin_login(1U, CKU_USER, "wrong") == CKR_PIN_INCORRECT;
        g_provider_test_after_pin_rv = CKR_FUNCTION_FAILED;
        ok = ok && pin_login(1U, CKU_USER, "user-pin") ==
                       CKR_FUNCTION_FAILED &&
             pin_set(1U, "user-pin", "next-pin") == CKR_FUNCTION_FAILED &&
             token_pin_counts_are(1U, 0U);
        g_provider_test_after_pin_rv = CKR_OK;
        ok = ok && pin_login(1U, CKU_USER, "user-pin") == CKR_OK &&
             pin_logout(1U) == CKR_OK && token_pin_counts_are(0U, 0U);
        check(ok, "a backend failure neither consumes nor clears an attempt");
    }
    g_provider_test_after_pin_rv = CKR_OK;
}

static void test_so_pin_lockout(void)
{
    unsigned int checks;
    uint32_t i;
    int ok = 1;

    for (i = 0U; i < WT_PKCS11_PIN_MAX_FAILURES; i++) {
        ok = ok && token_init("wrong") == CKR_PIN_INCORRECT;
    }
    checks = g_provider_test_pin_checks;
    check(ok && token_init("so-pin") == CKR_PIN_LOCKED &&
              pin_login(1U, CKU_SO, "so-pin") == CKR_PIN_LOCKED &&
              g_provider_test_pin_checks == checks &&
              token_pin_counts_are(0U, WT_PKCS11_PIN_MAX_FAILURES),
          "C_InitToken failures lock the SO PIN for every SO check");
    check(token_init("ab") == CKR_PIN_LEN_RANGE &&
              pin_login(3U, CKU_SO, "so-pin") ==
                  CKR_SESSION_READ_ONLY_EXISTS &&
              pin_login_null(1U, CKU_SO) == CKR_ARGUMENTS_BAD &&
              g_provider_test_pin_checks == checks,
          "a locked SO PIN keeps errors raised before any PIN test");
    g_provider_test_token_initialized = 0U;
    check(token_init("so-pin") == CKR_OK && token_pin_counts_are(0U, 0U) &&
              pin_login(1U, CKU_SO, "so-pin") == CKR_OK &&
              pin_logout(1U) == CKR_OK,
          "an erased token can be initialised again and clears both locks");
}

static int mechanism_list_is(uint32_t has_output, uint32_t capacity,
                             uint32_t rv, uint32_t total, uint32_t sent)
{
    uint8_t request[TEST_BUFFER_SIZE];
    uint8_t response[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    wt_pkcs11_reader_t reader;
    size_t response_len = 0U;
    uint32_t i;
    int ok;

    request_begin(&writer, request, WT_P11_GET_MECHANISM_LIST);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, has_output);
    wt_pkcs11_put_u32(&writer, capacity);
    if (wt_pkcs11_provider_dispatch(request, writer.used, response,
                                    sizeof(response), &response_len,
                                    NULL) != 0) {
        return 0;
    }
    wt_pkcs11_reader_init(&reader, response, response_len);
    (void)wt_pkcs11_get_u32(&reader);
    (void)wt_pkcs11_get_u32(&reader);
    ok = wt_pkcs11_get_u32(&reader) == rv &&
         wt_pkcs11_get_u32(&reader) == total &&
         wt_pkcs11_get_u32(&reader) == sent;
    for (i = 0U; i < sent; i++) {
        uint32_t mechanism = wt_pkcs11_get_u32(&reader);

        ok = ok && (mechanism == CKM_SHA256 || mechanism == CKM_ECDSA);
    }
    return ok && reader.error == 0 && reader.used == reader.length;
}

static uint32_t mechanism_info_rv(uint32_t mechanism)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_GET_MECHANISM_INFO);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, mechanism);
    return dispatch_rv(request, writer.used);
}

static void test_mechanism_filter(void)
{
    check(mechanism_list_is(0U, 0U, CKR_OK, 2U, 0U),
          "mechanism count omits mechanisms the wire cannot carry");
    check(mechanism_list_is(1U, 1U, CKR_BUFFER_TOO_SMALL, 2U, 0U),
          "short mechanism list reports the filtered count");
    check(mechanism_list_is(1U, 8U, CKR_OK, 2U, 2U),
          "mechanism list returns only transportable mechanisms");
    check(mechanism_info_rv(CKM_SHA256) == CKR_OK &&
              mechanism_info_rv(CKM_PKCS5_PBKD2) == CKR_MECHANISM_INVALID &&
              mechanism_info_rv(CKM_TLS12_KEY_AND_MAC_DERIVE) ==
                  CKR_MECHANISM_INVALID,
          "mechanism info refuses mechanisms the wire cannot carry");
}

static uint32_t library_call(uint32_t function)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, function);
    if (function == WT_P11_INITIALIZE) {
        wt_pkcs11_put_u32(&writer, 0U);
    }
    return dispatch_rv(request, writer.used);
}

static void test_finalize_pin_counts(void)
{
    uint32_t i;
    int ok = 1;

    for (i = 0U; i < WT_PKCS11_PIN_MAX_FAILURES; i++) {
        ok = ok && pin_login(1U, CKU_USER, "wrong") == CKR_PIN_INCORRECT;
    }
    check(ok && library_call(WT_P11_INITIALIZE) == CKR_OK &&
              library_call(WT_P11_FINALIZE) == CKR_OK &&
              pin_login(1U, CKU_USER, "user-pin") == CKR_PIN_LOCKED,
          "a finalize that leaves the library loaded keeps the PIN lock");
    ok = library_call(WT_P11_FINALIZE) == CKR_OK &&
         library_call(WT_P11_INITIALIZE) == CKR_OK;
#ifdef WOLFPKCS11_NO_STORE
    check(ok && token_pin_counts_are(0U, 0U) &&
              token_init("so-pin") == CKR_OK &&
              pin_login(1U, CKU_USER, "user-pin") == CKR_OK &&
              pin_logout(1U) == CKR_OK,
          "finalizing the RAM-only token clears its PIN counts");
#else
    check(ok && token_pin_counts_are(WT_PKCS11_PIN_MAX_FAILURES, 0U),
          "a stored token keeps its PIN counts across finalize");
    check(pin_login(1U, CKU_SO, "so-pin") == CKR_OK &&
              pin_init(1U, "user-pin") == CKR_OK && pin_logout(1U) == CKR_OK,
          "SO recovers the stored token's user PIN");
#endif
}

static int null_case(uint8_t* request, size_t request_len, uint32_t rv,
                     unsigned int null_seen)
{
    g_provider_test_calls = 0U;
    g_provider_test_null_seen = 2U;
    return dispatch_rv(request, request_len) == rv &&
           g_provider_test_calls == 1U &&
           g_provider_test_null_seen == null_seen;
}

static size_t seed_request(uint8_t* request, uint32_t present,
                           uint32_t length)
{
    static const uint8_t seed[1] = { 0x11U };
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_SEED_RANDOM);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, length);
    wt_pkcs11_put_u32(&writer, present);
    wt_pkcs11_put_bytes(&writer, length != 0U ? seed : NULL, length);
    return writer.used;
}

static size_t output_request(uint8_t* request, uint32_t function,
                             uint32_t has_output)
{
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, function);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, has_output);
    wt_pkcs11_put_u32(&writer, 0U);
    return writer.used;
}

static size_t raw_parameter_request(uint8_t* request, uint32_t present)
{
    wt_pkcs11_writer_t writer;

    request_begin(&writer, request, WT_P11_ENCRYPT_INIT);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, CKM_AES_CBC);
    wt_pkcs11_put_u32(&writer, WT_P11_MECH_RAW);
    wt_pkcs11_put_u32(&writer, present);
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    wt_pkcs11_put_u32(&writer, 1U);
    return writer.used;
}

static void test_null_pointers_reach_provider(void)
{
    uint8_t request[TEST_BUFFER_SIZE];
    wt_pkcs11_writer_t writer;
    size_t length;

    length = seed_request(request, 0U, 0U);
    check(null_case(request, length, CKR_ARGUMENTS_BAD, 1U),
          "a NULL empty buffer reaches wolfPKCS11 as NULL");
    length = seed_request(request, 1U, 0U);
    check(null_case(request, length, CKR_OK, 0U),
          "a non-NULL empty buffer reaches wolfPKCS11 as non-NULL");
    length = seed_request(request, 0U, 1U);
    check(dispatch_invalid(request, length, TEST_BUFFER_SIZE, 0, 1),
          "a NULL buffer with data fails before PKCS11 dispatch");

    length = output_request(request, WT_P11_GENERATE_RANDOM, 0U);
    check(null_case(request, length, CKR_ARGUMENTS_BAD, 1U),
          "a NULL random output reaches wolfPKCS11 as NULL");
    length = output_request(request, WT_P11_GENERATE_RANDOM, 1U);
    check(null_case(request, length, CKR_OK, 0U),
          "an empty random output reaches wolfPKCS11 as non-NULL");
    length = output_request(request, WT_P11_FIND_OBJECTS, 0U);
    check(null_case(request, length, CKR_ARGUMENTS_BAD, 1U),
          "a NULL object list reaches wolfPKCS11 as NULL");
    length = output_request(request, WT_P11_FIND_OBJECTS, 1U);
    check(null_case(request, length, CKR_OK, 0U),
          "an empty object list reaches wolfPKCS11 as non-NULL");

    request_begin(&writer, request, WT_P11_CREATE_OBJECT);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 0U);
    wt_pkcs11_put_u32(&writer, 0U);
    check(null_case(request, writer.used, CKR_ARGUMENTS_BAD, 1U),
          "a NULL template reaches wolfPKCS11 as NULL");
    request_begin(&writer, request, WT_P11_CREATE_OBJECT);
    wt_pkcs11_put_u32(&writer, 1U);
    wt_pkcs11_put_u32(&writer, 0U);
    wt_pkcs11_put_u32(&writer, 1U);
    check(dispatch_invalid(request, writer.used, TEST_BUFFER_SIZE, 0, 1),
          "a NULL template with attributes fails before PKCS11 dispatch");

    length = raw_parameter_request(request, 0U);
    check(null_case(request, length, CKR_FUNCTION_FAILED, 1U),
          "a NULL mechanism parameter reaches wolfPKCS11 as NULL");
    length = raw_parameter_request(request, 1U);
    check(null_case(request, length, CKR_FUNCTION_FAILED, 0U),
          "an empty mechanism parameter reaches wolfPKCS11 as non-NULL");
}

int main(void)
{
    test_truncated_header();
    test_oversized_template();
    test_oversized_get_attribute_template();
    test_truncated_blob();
    test_truncated_mechanism();
    test_mechanism_kind_mismatch();
    test_ecdh_shared_data_presence();
    test_short_response();
    test_aligned_template_value();
    test_large_attribute_capacity();
    test_attribute_response_boundary();
    test_attribute_caller_buffer_too_small();
    test_attribute_type_invalid_with_valid_peer();
    test_sensitive_attribute_with_valid_peer();
    test_null_pointers_reach_provider();
    test_mechanism_filter();
    test_open_session_arguments();
    test_user_pin_lockout();
    test_success_resets_pin_count();
    test_backend_failures_keep_count();
    test_so_pin_lockout();
    test_finalize_pin_counts();
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: PKCS11 provider frames, sessions, and PIN lockout\n");
    return 0;
}
