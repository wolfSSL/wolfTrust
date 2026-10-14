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
 */

/* Host proof of the SERVICE_PKCS11 copied-transfer relay. Both roles use
 * real FF-M connect/call/close dispatch, and no caller buffer is shared with
 * the other guest. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolftrust/ffm.h"
#include "wolftrust/pkcs11_psa_transport.h"
#include "wolftrust/services/pkcs11_relay.h"
#include "psa/client.h"

#define TEST_PKCS11_PARTITION 9
#define TEST_APP_CLIENT       (-1)
#define TEST_PROVIDER_CLIENT  (-2)
#define TEST_OTHER_CLIENT     (-3)
#define TEST_SP_CLIENT        3

static int g_failures;
static wt_ffm_runtime_t g_runtime;
static int32_t g_transport_fail_op;
static int32_t g_transport_repeat_fail_op;
static unsigned int g_transport_repeat_failures;
static unsigned int g_provider_dispatches;
static int g_relay_partial_read;
static unsigned int g_chunk_wipes;
static psa_status_t g_chunk_wipe_status;
static int g_chunk_wipe_dirty;

typedef struct test_dispatch_context {
    const uint8_t* response;
    size_t response_len;
    int fail;
} test_dispatch_context_t;

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    if (sid != WT_PKCS11_SERVICE_SID ||
            version != WT_PKCS11_SERVICE_VERSION) {
        return PSA_ERROR_CONNECTION_REFUSED;
    }
    return wt_ffm_connect(&g_runtime, TEST_PROVIDER_CLIENT, sid, version);
}

void psa_close(psa_handle_t handle)
{
    (void)wt_ffm_close(&g_runtime, TEST_PROVIDER_CLIENT, handle);
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    if (type == g_transport_fail_op) {
        g_transport_fail_op = 0;
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (type == g_transport_repeat_fail_op &&
            g_transport_repeat_failures > 0U) {
        g_transport_repeat_failures--;
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    return wt_ffm_call(&g_runtime, TEST_PROVIDER_CLIENT, handle, type,
                       in_vec, in_len, out_vec, out_len);
}

static void check(int ok, const char* what)
{
    if (ok != 0) {
        printf("PASS: %s\n", what);
    }
    else {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

void wt_pkcs11_test_relay_chunk_zeroized(const void* memory, size_t size,
                                         psa_status_t status)
{
    const uint8_t* bytes = (const uint8_t*)memory;
    size_t i;

    g_chunk_wipes++;
    g_chunk_wipe_status = status;
    for (i = 0U; i < size; i++) {
        if (bytes[i] != 0U) {
            g_chunk_wipe_dirty = 1;
            break;
        }
    }
}

static void chunk_wipe_reset(void)
{
    g_chunk_wipes = 0U;
    g_chunk_wipe_status = PSA_SUCCESS;
    g_chunk_wipe_dirty = 0;
}

static int chunk_wipe_matches(psa_status_t status)
{
    return g_chunk_wipes == 1U && g_chunk_wipe_status == status &&
           g_chunk_wipe_dirty == 0;
}

static int test_relay_transport(wt_ffm_runtime_t* runtime,
                                wt_spm_call_t* call)
{
    int rc = wt_spm_transport_direct(runtime, call);

    if (rc == WT_FFM_SUCCESS && g_relay_partial_read != 0 &&
            call->op == WT_SPM_OP_READ && call->ret_size > 0U) {
        call->ret_size--;
        g_relay_partial_read = 0;
    }
    return rc;
}

static int test_check_read(void* context, psa_client_id_t caller,
                           const void* address, size_t size)
{
    (void)context;
    (void)caller;
    return size == 0U || address != NULL;
}

static int test_check_write(void* context, psa_client_id_t caller,
                            void* address, size_t size)
{
    (void)context;
    (void)caller;
    return size == 0U || address != NULL;
}

static void test_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
}

static int test_dispatch(void* context, wt_ffm_runtime_t* runtime,
                         int32_t partition_id)
{
    (void)context;
    return wt_pkcs11_relay_dispatch(NULL, runtime, partition_id);
}

static const wt_ffm_port_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    test_dispatch,
    test_panic
};

static const wt_service_descriptor_t g_services[] = {
    {
        "SERVICE_PKCS11", WT_PKCS11_SERVICE_SID, 1U,
        WT_SERVICE_VERSION_RELAXED, 0x40U, 0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_PKCS11", TEST_PKCS11_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "pkcs11-relay-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static psa_status_t p11_op(int32_t client_id, int32_t op, const void* input,
                           size_t input_len, void* output, size_t output_cap,
                           size_t* output_len)
{
    psa_invec iv[1];
    psa_outvec ov[1];
    psa_handle_t handle;
    psa_status_t status;

    handle = wt_ffm_connect(&g_runtime, client_id, WT_PKCS11_SERVICE_SID,
                            WT_PKCS11_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_CONNECTION_REFUSED;
    }
    iv[0].base = input;
    iv[0].len = input_len;
    ov[0].base = output;
    ov[0].len = output_cap;
    status = wt_ffm_call(&g_runtime, client_id, handle, op,
                         input != NULL ? iv : NULL,
                         input != NULL ? 1U : 0U,
                         output != NULL ? ov : NULL,
                         output != NULL ? 1U : 0U);
    if (output_len != NULL && output != NULL) {
        *output_len = ov[0].len;
    }
    (void)wt_ffm_close(&g_runtime, client_id, handle);
    return status;
}

static psa_status_t begin_message(int32_t client_id, int32_t op,
                                  size_t length)
{
    wt_pkcs11_length_t frame;

    frame.length = (uint32_t)length;
    return p11_op(client_id, op, &frame, sizeof(frame), NULL, 0U, NULL);
}

static psa_status_t write_chunks(int32_t client_id, int32_t op,
                                 const uint8_t* data, size_t length)
{
    wt_pkcs11_chunk_t chunk;
    size_t offset = 0U;
    size_t take;
    psa_status_t status;

    while (offset < length) {
        take = length - offset;
        if (take > WT_PKCS11_CHUNK_MAX) {
            take = WT_PKCS11_CHUNK_MAX;
        }
        chunk.offset = (uint32_t)offset;
        chunk.length = (uint32_t)take;
        (void)memcpy(chunk.data, data + offset, take);
        status = p11_op(client_id, op, &chunk,
                        sizeof(chunk.offset) + sizeof(chunk.length) + take,
                        NULL, 0U, NULL);
        if (status != PSA_SUCCESS) {
            return status;
        }
        offset += take;
    }
    return PSA_SUCCESS;
}

static psa_status_t report_length(int32_t client_id, int32_t op,
                                  size_t* length)
{
    wt_pkcs11_length_t frame;
    size_t output_len = 0U;
    psa_status_t status;

    status = p11_op(client_id, op, NULL, 0U, &frame, sizeof(frame),
                    &output_len);
    if (status == PSA_SUCCESS) {
        if (output_len != sizeof(frame)) {
            return PSA_ERROR_GENERIC_ERROR;
        }
        *length = frame.length;
    }
    return status;
}

static psa_status_t read_chunks(int32_t client_id, int32_t op, uint8_t* data,
                                size_t length)
{
    wt_pkcs11_range_t range;
    size_t offset = 0U;
    size_t take;
    size_t output_len;
    psa_status_t status;

    while (offset < length) {
        take = length - offset;
        if (take > WT_PKCS11_CHUNK_MAX) {
            take = WT_PKCS11_CHUNK_MAX;
        }
        range.offset = (uint32_t)offset;
        range.length = (uint32_t)take;
        status = p11_op(client_id, op, &range, sizeof(range), data + offset,
                        take, &output_len);
        if (status != PSA_SUCCESS || output_len != take) {
            return status != PSA_SUCCESS ? status : PSA_ERROR_GENERIC_ERROR;
        }
        offset += take;
    }
    return PSA_SUCCESS;
}

static int round_trip(const uint8_t* request, size_t request_len,
                      const uint8_t* response, size_t response_len,
                      uint8_t* scratch);

static int queue_request(const uint8_t* request, size_t request_len)
{
    return begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN,
                         request_len) == PSA_SUCCESS &&
           write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
                        request_len) == PSA_SUCCESS &&
           p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL,
                  0U, NULL) == PSA_SUCCESS ? 0 : -1;
}

static int provider_dispatch(uint8_t* request, size_t request_len,
                             uint8_t* response, size_t response_cap,
                             size_t* response_len, void* context)
{
    test_dispatch_context_t* test = (test_dispatch_context_t*)context;

    g_provider_dispatches++;
    if (test->fail != 0 || request == NULL || request_len == 0U ||
            response == NULL || response_len == NULL ||
            test->response_len > response_cap) {
        return -1;
    }
    (void)memcpy(response, test->response, test->response_len);
    *response_len = test->response_len;
    return 0;
}

static int provider_oversize_dispatch(uint8_t* request, size_t request_len,
                                      uint8_t* response,
                                      size_t response_cap,
                                      size_t* response_len, void* context)
{
    (void)context;
    if (request == NULL || request_len == 0U || response == NULL ||
            response_cap == 0U || response_len == NULL) {
        return -1;
    }
    response[0] = 0xA5U;
    *response_len = response_cap + 1U;
    return 0;
}

static int buffer_is_zero(const uint8_t* buffer, size_t length)
{
    size_t i;

    for (i = 0U; i < length; i++) {
        if (buffer[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

static int provider_failure_recovers(const uint8_t* request,
                                     size_t request_len,
                                     const uint8_t* response,
                                     size_t response_len,
                                     int dispatch_fail, int32_t fail_op,
                                     uint8_t* scratch)
{
    test_dispatch_context_t context;
    uint8_t provider_request[WT_PKCS11_MESSAGE_MAX];
    uint8_t provider_response[WT_PKCS11_MESSAGE_MAX];
    size_t length = 0U;
    int rc;

    context.response = response;
    context.response_len = response_len;
    context.fail = dispatch_fail;
    if (queue_request(request, request_len) != 0) {
        return -1;
    }
    (void)memset(provider_request, 0xA5, sizeof(provider_request));
    (void)memset(provider_response, 0x5A, sizeof(provider_response));
    g_transport_fail_op = fail_op;
    rc = wt_pkcs11_psa_provider_step(provider_request,
        sizeof(provider_request), provider_response, sizeof(provider_response),
        provider_dispatch, &context);
    if (rc == 0 || buffer_is_zero(provider_request,
                                  sizeof(provider_request)) == 0 ||
            buffer_is_zero(provider_response,
                           sizeof(provider_response)) == 0 ||
            report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) !=
                (psa_status_t)WT_PKCS11_E_EMPTY) {
        return -2;
    }
    return round_trip(request, request_len, response, response_len, scratch);
}

static int provider_step_round_trip(const uint8_t* request,
                                    size_t request_len,
                                    const uint8_t* response,
                                    size_t response_len, uint8_t* scratch)
{
    test_dispatch_context_t context;
    uint8_t provider_request[WT_PKCS11_MESSAGE_MAX];
    uint8_t provider_response[WT_PKCS11_MESSAGE_MAX];
    size_t length = 0U;

    context.response = response;
    context.response_len = response_len;
    context.fail = 0;
    if (queue_request(request, request_len) != 0 ||
            wt_pkcs11_psa_provider_step(provider_request,
                sizeof(provider_request), provider_response,
                sizeof(provider_response), provider_dispatch, &context) != 0 ||
            buffer_is_zero(provider_request, sizeof(provider_request)) == 0 ||
            buffer_is_zero(provider_response, sizeof(provider_response)) == 0 ||
            report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) !=
                PSA_SUCCESS || length != response_len ||
            read_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, scratch,
                        length) != PSA_SUCCESS ||
            memcmp(scratch, response, response_len) != 0) {
        return -1;
    }
    return 0;
}

static int provider_reconnect_recovers(const uint8_t* request,
                                       size_t request_len,
                                       const uint8_t* response,
                                       size_t response_len, uint8_t* scratch)
{
    test_dispatch_context_t context;
    uint8_t provider_request[WT_PKCS11_MESSAGE_MAX];
    uint8_t provider_response[WT_PKCS11_MESSAGE_MAX];
    size_t length = 0U;
    int rc;

    context.response = response;
    context.response_len = response_len;
    context.fail = 0;
    if (queue_request(request, request_len) != 0) {
        return -1;
    }
    g_provider_dispatches = 0U;
    g_transport_fail_op = WT_PKCS11_OP_PROVIDER_WRITE;
    g_transport_repeat_fail_op = WT_PKCS11_OP_PROVIDER_ABORT;
    g_transport_repeat_failures = 2U;
    rc = wt_pkcs11_psa_provider_step(provider_request,
        sizeof(provider_request), provider_response, sizeof(provider_response),
        provider_dispatch, &context);
    if (rc == 0 || g_transport_repeat_failures != 0U ||
            g_provider_dispatches != 1U) {
        return -2;
    }
    rc = wt_pkcs11_psa_provider_step(provider_request,
        sizeof(provider_request), provider_response, sizeof(provider_response),
        provider_dispatch, &context);
    if (rc != PSA_ERROR_BAD_STATE || g_provider_dispatches != 1U ||
            wt_pkcs11_psa_provider_step(provider_request,
                sizeof(provider_request), provider_response,
                sizeof(provider_response), provider_dispatch, &context) !=
                WT_PKCS11_E_EMPTY || g_provider_dispatches != 1U ||
            report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) !=
                (psa_status_t)WT_PKCS11_E_EMPTY) {
        return -3;
    }
    return provider_step_round_trip(request, request_len, response,
                                    response_len, scratch);
}

static int provider_oversize_recovers(const uint8_t* request,
                                      size_t request_len,
                                      const uint8_t* response,
                                      size_t response_len, uint8_t* scratch)
{
    uint8_t provider_request[WT_PKCS11_MESSAGE_MAX];
    uint8_t provider_response[WT_PKCS11_MESSAGE_MAX];
    size_t length = 0U;
    int rc;

    if (queue_request(request, request_len) != 0) {
        return -1;
    }
    (void)memset(provider_request, 0xA5, sizeof(provider_request));
    (void)memset(provider_response, 0x5A, sizeof(provider_response));
    rc = wt_pkcs11_psa_provider_step(provider_request,
        sizeof(provider_request), provider_response, 8U,
        provider_oversize_dispatch, NULL);
    if (rc != PSA_ERROR_INVALID_ARGUMENT ||
            buffer_is_zero(provider_request,
                           sizeof(provider_request)) == 0 ||
            buffer_is_zero(provider_response, 8U) == 0 ||
            report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) !=
                (psa_status_t)WT_PKCS11_E_EMPTY) {
        return -2;
    }
    return round_trip(request, request_len, response, response_len, scratch);
}

static int round_trip(const uint8_t* request, size_t request_len,
                      const uint8_t* response, size_t response_len,
                      uint8_t* scratch)
{
    size_t length = 0U;

    if (begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, request_len) !=
            PSA_SUCCESS ||
            write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
                         request_len) != PSA_SUCCESS ||
            p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL,
                   0U, NULL) != PSA_SUCCESS ||
            report_length(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_FETCH,
                          &length) != PSA_SUCCESS || length != request_len ||
            read_chunks(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_READ,
                        scratch, length) != PSA_SUCCESS ||
            memcmp(scratch, request, request_len) != 0) {
        return -1;
    }
    if (begin_message(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_BEGIN,
                      response_len) != PSA_SUCCESS ||
            write_chunks(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_WRITE,
                         response, response_len) != PSA_SUCCESS ||
            p11_op(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_COMMIT, NULL,
                   0U, NULL, 0U, NULL) != PSA_SUCCESS ||
            report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) !=
                PSA_SUCCESS || length != response_len ||
            read_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, scratch,
                        length) != PSA_SUCCESS ||
            memcmp(scratch, response, response_len) != 0) {
        return -2;
    }
    return 0;
}

int main(void)
{
    uint8_t request[WT_PKCS11_MESSAGE_MAX];
    uint8_t response[WT_PKCS11_MESSAGE_MAX];
    uint8_t scratch[WT_PKCS11_MESSAGE_MAX];
    wt_pkcs11_chunk_t chunk;
    wt_pkcs11_range_t range;
    size_t length = 0U;
    size_t output_len = 0U;
    size_t i;

    for (i = 0U; i < sizeof(request); i++) {
        request[i] = (uint8_t)i;
        response[i] = (uint8_t)(0xA5U ^ (uint8_t)i);
    }
    check(wt_ffm_init(&g_runtime, &g_manifest, &g_port_ops, NULL) ==
              WT_FFM_SUCCESS,
          "in-process FF-M runtime initializes");
    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_ERROR_NOT_SUPPORTED,
          "unbound relay refuses every operation");

    wt_pkcs11_relay_set_roles(TEST_APP_CLIENT, TEST_PROVIDER_CLIENT);
    wt_pkcs11_relay_set_transport(test_relay_transport);
    check(report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) ==
              (psa_status_t)WT_PKCS11_E_EMPTY,
          "application POLL reports an empty slot");
    check(report_length(TEST_PROVIDER_CLIENT,
                        WT_PKCS11_OP_PROVIDER_FETCH, &length) ==
              (psa_status_t)WT_PKCS11_E_EMPTY,
          "provider FETCH reports an empty slot");
    check(wt_pkcs11_psa_provider_step(request, sizeof(request), response,
              sizeof(response), provider_dispatch, NULL) ==
              WT_PKCS11_E_EMPTY,
          "idle provider step preserves the empty status");
    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 0U) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN,
                        WT_PKCS11_MESSAGE_MAX + 1U) ==
              PSA_ERROR_INVALID_ARGUMENT,
          "zero and oversized messages are refused");

    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS,
          "application begins a request");
    (void)memset(&chunk, 0, sizeof(chunk));
    chunk.offset = 1U;
    chunk.length = 8U;
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
                 NULL, 0U, NULL) == PSA_ERROR_INVALID_ARGUMENT &&
              chunk_wipe_matches(PSA_ERROR_INVALID_ARGUMENT),
          "invalid-offset request is refused and its chunk is scrubbed");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL,
                 0U, NULL) == PSA_ERROR_BAD_STATE,
          "partial request cannot commit");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_ABORT, NULL, 0U, NULL, 0U,
                 NULL) == PSA_SUCCESS &&
          report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) ==
              (psa_status_t)WT_PKCS11_E_EMPTY,
          "application abort scrubs a partial request");

    chunk.offset = 0U;
    chunk.length = 8U;
    (void)memset(chunk.data, 0xA5, 8U);
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
                 NULL, 0U, NULL) == PSA_ERROR_BAD_STATE &&
              chunk_wipe_matches(PSA_ERROR_BAD_STATE),
          "bad-state request is refused and its chunk is scrubbed");

    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS,
          "application begins malformed-frame test request");
    chunk.length = 7U;
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
                 NULL, 0U, NULL) == PSA_ERROR_INVALID_ARGUMENT &&
              chunk_wipe_matches(PSA_ERROR_INVALID_ARGUMENT),
          "malformed request is refused and its chunk is scrubbed");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_ABORT, NULL, 0U, NULL, 0U,
                 NULL) == PSA_SUCCESS,
          "malformed-frame transaction can be aborted safely");

    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS,
          "application begins partial-read test request");
    chunk.length = 8U;
    g_relay_partial_read = 1;
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
                 NULL, 0U, NULL) == PSA_ERROR_INVALID_ARGUMENT &&
              g_relay_partial_read == 0 &&
              chunk_wipe_matches(PSA_ERROR_INVALID_ARGUMENT),
          "partial read is refused and its copied chunk is scrubbed");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_ABORT, NULL, 0U, NULL, 0U,
                 NULL) == PSA_SUCCESS,
          "partial-read transaction can be aborted safely");

    check(round_trip(request, 19U, response, 37U, scratch) == 0,
          "multi-step request and response cross the copied FF-M relay");
    check(round_trip(request, WT_PKCS11_MESSAGE_MAX, response,
                     WT_PKCS11_MESSAGE_MAX, scratch) == 0,
          "exact maximum-size messages cross every chunk boundary");
    check(provider_failure_recovers(request, 31U, response, 41U, 1, 0,
                                    scratch) == 0,
          "dispatch failure aborts and releases the provider transaction");
    check(provider_failure_recovers(request, 31U, response, 41U, 0,
                                    WT_PKCS11_OP_PROVIDER_BEGIN,
                                    scratch) == 0,
          "response-begin failure aborts and releases the transaction");
    check(provider_failure_recovers(request, 31U, response, 41U, 0,
                                    WT_PKCS11_OP_PROVIDER_WRITE,
                                    scratch) == 0,
          "response-write failure aborts and releases the transaction");
    check(provider_failure_recovers(request, 31U, response, 41U, 0,
                                    WT_PKCS11_OP_PROVIDER_COMMIT,
                                    scratch) == 0,
          "response-commit failure aborts and releases the transaction");
    check(provider_step_round_trip(request, 31U, response, 41U, scratch) == 0,
          "provider step publishes a response and scrubs its local buffers");
    check(provider_oversize_recovers(request, 31U, response, 41U, scratch) ==
              0,
          "oversized provider response aborts before transport and recovers");

    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS &&
          write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
                       16U) == PSA_SUCCESS &&
          p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL,
                 0U, NULL) == PSA_SUCCESS &&
          report_length(TEST_PROVIDER_CLIENT,
                        WT_PKCS11_OP_PROVIDER_FETCH, &length) == PSA_SUCCESS &&
          p11_op(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_ABORT, NULL, 0U,
                 NULL, 0U, NULL) == PSA_SUCCESS &&
          report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) ==
              (psa_status_t)WT_PKCS11_E_EMPTY &&
          round_trip(request, 13U, response, 17U, scratch) == 0,
          "provider abort recovers a processing transaction");

    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS &&
          write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
                       16U) == PSA_SUCCESS &&
          p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL,
                 0U, NULL) == PSA_SUCCESS &&
          report_length(TEST_PROVIDER_CLIENT,
                        WT_PKCS11_OP_PROVIDER_FETCH, &length) == PSA_SUCCESS &&
          read_chunks(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_READ,
                      scratch, 16U) == PSA_SUCCESS &&
          begin_message(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_BEGIN,
                        16U) == PSA_SUCCESS &&
          p11_op(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_ABORT, NULL, 0U,
                 NULL, 0U, NULL) == PSA_SUCCESS &&
          round_trip(request, 23U, response, 29U, scratch) == 0,
          "provider abort recovers a responding transaction");

    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS &&
          write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
                       16U) == PSA_SUCCESS &&
          p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL,
                 0U, NULL) == PSA_SUCCESS &&
          report_length(TEST_PROVIDER_CLIENT,
                        WT_PKCS11_OP_PROVIDER_FETCH, &length) == PSA_SUCCESS &&
          begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 8U) ==
              (psa_status_t)WT_PKCS11_E_BUSY &&
          p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_ABORT, NULL, 0U, NULL, 0U,
                 NULL) == (psa_status_t)WT_PKCS11_E_BUSY &&
          report_length(TEST_PROVIDER_CLIENT,
                        WT_PKCS11_OP_PROVIDER_FETCH, &length) ==
              PSA_ERROR_BAD_STATE &&
          p11_op(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_ABORT, NULL, 0U,
                 NULL, 0U, NULL) == PSA_SUCCESS &&
          report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) ==
              (psa_status_t)WT_PKCS11_E_EMPTY &&
          round_trip(request, 23U, response, 29U, scratch) == 0,
          "provider restart fails an indeterminate request without replay");

    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS &&
          write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
                       16U) == PSA_SUCCESS &&
          p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_COMMIT, NULL, 0U, NULL,
                 0U, NULL) == PSA_SUCCESS &&
          report_length(TEST_PROVIDER_CLIENT,
                        WT_PKCS11_OP_PROVIDER_FETCH, &length) == PSA_SUCCESS &&
          read_chunks(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_READ,
                      scratch, 16U) == PSA_SUCCESS &&
          begin_message(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_BEGIN,
                        16U) == PSA_SUCCESS &&
          write_chunks(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_WRITE,
                       response, 16U) == PSA_SUCCESS &&
          p11_op(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_PROVIDER_COMMIT, NULL, 0U,
                 NULL, 0U, NULL) == PSA_SUCCESS,
          "provider publishes a response for bounded application reads");

    check(report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_POLL, &length) ==
              PSA_SUCCESS && length == 16U,
          "application observes the completed response length");
    range.offset = 0U;
    range.length = 16U;
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, &range, sizeof(range),
                 scratch, 8U, &output_len) == PSA_ERROR_BUFFER_TOO_SMALL,
          "short output buffer preserves the completed response");
    check(read_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, scratch, 16U) ==
              PSA_SUCCESS && memcmp(scratch, response, 16U) == 0,
          "retry with enough space collects and scrubs the response");

    (void)memset(&chunk, 0, sizeof(chunk));
    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN,
                        WT_PKCS11_MESSAGE_MAX) == PSA_SUCCESS,
          "maximum-size request begins");
    chunk.length = WT_PKCS11_CHUNK_MAX + 1U;
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk,
                 sizeof(chunk), NULL, 0U, NULL) ==
              PSA_ERROR_INVALID_ARGUMENT,
          "oversized chunk is refused");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_ABORT, NULL, 0U, NULL, 0U,
                 NULL) == PSA_SUCCESS,
          "oversized-chunk transaction can be aborted safely");

    check(begin_message(TEST_PROVIDER_CLIENT, WT_PKCS11_OP_APP_BEGIN, 8U) ==
              PSA_ERROR_NOT_PERMITTED,
          "provider cannot submit as the application");
    check(report_length(TEST_APP_CLIENT, WT_PKCS11_OP_PROVIDER_FETCH,
                        &length) == PSA_ERROR_NOT_PERMITTED,
          "application cannot fetch as the provider");
    check(begin_message(TEST_OTHER_CLIENT, WT_PKCS11_OP_APP_BEGIN, 8U) ==
              PSA_ERROR_NOT_PERMITTED,
          "unrelated guest is refused both roles");
    check(begin_message(TEST_SP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 8U) !=
              PSA_SUCCESS,
          "unrelated Secure Partition is refused both roles");
    check(provider_reconnect_recovers(request, 31U, response, 41U, scratch) ==
              0,
          "provider reconnect clears an indeterminate response without replay");

    if (g_failures == 0) {
        printf("PASS: pkcs11_relay (copied PKCS11 messages over the "
               "SPM-mediated door)\n");
        return 0;
    }
    printf("FAIL: pkcs11_relay (%d failures)\n", g_failures);
    return 1;
}
