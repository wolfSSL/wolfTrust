/* main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
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

static void test_ecdh_empty_shared_data_is_null(void)
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
    wt_pkcs11_put_bytes(&writer, NULL, 0U);
    wt_pkcs11_put_bytes(&writer, point, sizeof(point));
    wt_pkcs11_put_u32(&writer, 12U);
    wt_pkcs11_put_u32(&writer, 0U);
    g_provider_test_calls = 0U;
    g_provider_test_ecdh_valid = 0U;
    rc = wt_pkcs11_provider_dispatch(request, writer.used, response,
                                     sizeof(response), &response_len, NULL);
    check(rc == 0 && response_rv(response, response_len) == CKR_OK &&
              g_provider_test_calls == 1U &&
              g_provider_test_ecdh_valid != 0U,
          "zero-length ECDH shared data decodes as a NULL pointer");
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

int main(void)
{
    test_truncated_header();
    test_oversized_template();
    test_oversized_get_attribute_template();
    test_truncated_blob();
    test_truncated_mechanism();
    test_mechanism_kind_mismatch();
    test_ecdh_empty_shared_data_is_null();
    test_short_response();
    test_aligned_template_value();
    test_large_attribute_capacity();
    test_attribute_response_boundary();
    test_attribute_caller_buffer_too_small();
    test_attribute_type_invalid_with_valid_peer();
    test_sensitive_attribute_with_valid_peer();
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: PKCS11 provider malformed-frame boundaries\n");
    return 0;
}
