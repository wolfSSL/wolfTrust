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

/* WT-FFM-0054: the actual client and Secure service exchange copied frames
 * through the FF-M runtime. The handler needs no worker or operating system. */

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
static uint8_t g_received_request[WT_PKCS11_MESSAGE_MAX];
static size_t g_received_length;
static const uint8_t* g_private_request;
static uint8_t* g_private_response;
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
    return wt_ffm_connect(&g_runtime, TEST_APP_CLIENT, sid, version);
}

void psa_close(psa_handle_t handle)
{
    (void)wt_ffm_close(&g_runtime, TEST_APP_CLIENT, handle);
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
    return wt_ffm_call(&g_runtime, TEST_APP_CLIENT, handle, type,
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

static int provider_dispatch(uint8_t* request, size_t request_len,
                             uint8_t* response, size_t response_cap,
                             size_t* response_len, void* context)
{
    test_dispatch_context_t* test = (test_dispatch_context_t*)context;

    g_provider_dispatches++;
    g_private_request = request;
    g_private_response = response;
    g_received_length = request_len;
    (void)memcpy(g_received_request, request, request_len);
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

static void test_direct_execution(void)
{
    uint8_t request[WT_PKCS11_MESSAGE_MAX];
    uint8_t response[WT_PKCS11_MESSAGE_MAX];
    uint8_t collected[WT_PKCS11_MESSAGE_MAX];
    test_dispatch_context_t context;
    size_t length = 0U;
    size_t i;
    unsigned int calls;

    check(wt_ffm_init(&g_runtime, &g_manifest, &g_port_ops, NULL) ==
              WT_FFM_SUCCESS, "WT-FFM-0054 direct PKCS11 runtime initializes");
    for (i = 0U; i < sizeof(request); i++) {
        request[i] = (uint8_t)i;
        response[i] = (uint8_t)(i ^ 0x5AU);
    }
    wt_pkcs11_psa_close();
    context.response = response;
    context.response_len = sizeof(response);
    context.fail = 0;
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, NULL, 0U,
              NULL, 0U, NULL) == PSA_ERROR_NOT_SUPPORTED,
          "unbound PKCS11 service fails closed");
    wt_pkcs11_relay_set_client(TEST_APP_CLIENT);
    wt_pkcs11_relay_set_local_provider(provider_dispatch, &context);
    calls = g_provider_dispatches;
    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN,
              sizeof(request)) == PSA_SUCCESS &&
          write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
              sizeof(request)) == PSA_SUCCESS,
          "direct PKCS11 stages the full bounded message");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_EXECUTE, NULL, 0U,
              collected, 1U, NULL) == PSA_ERROR_INVALID_ARGUMENT &&
              g_provider_dispatches == calls,
          "bad reply metadata capacity cannot execute a PKCS11 operation");
    check(report_length(TEST_OTHER_CLIENT, WT_PKCS11_OP_APP_EXECUTE,
              &length) == PSA_ERROR_NOT_PERMITTED &&
              g_provider_dispatches == calls,
          "WT-FFM-0059 wrong PKCS11 caller cannot execute the staged operation");
    check(report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_EXECUTE,
              &length) == PSA_SUCCESS && length == sizeof(response) &&
              g_provider_dispatches == calls + 1U,
          "one execute call returns the completed response length without polling");
    check(report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_EXECUTE,
              &length) == PSA_ERROR_BAD_STATE &&
              g_provider_dispatches == calls + 1U,
          "duplicate execute never replays a completed PKCS11 operation");
    check(read_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, collected,
              sizeof(collected)) == PSA_SUCCESS &&
              memcmp(collected, response, sizeof(response)) == 0,
          "direct PKCS11 returns the exact maximum-sized response");
    check(g_received_length == sizeof(request) &&
              memcmp(g_received_request, request, sizeof(request)) == 0 &&
              g_private_request != request && g_private_response != collected &&
              buffer_is_zero(g_private_request, WT_PKCS11_MESSAGE_MAX) &&
              buffer_is_zero(g_private_response, WT_PKCS11_MESSAGE_MAX),
          "both directions copy exact bytes and scrub all private staging");
    check(report_length(TEST_PROVIDER_CLIENT, 7 /* retired worker FETCH */,
              &length) == PSA_ERROR_NOT_PERMITTED,
          "there is no external provider role in the direct service");
    wt_pkcs11_relay_set_local_provider(NULL, NULL);
}

static void test_bounds_and_recovery(void)
{
    uint8_t request[31];
    uint8_t response[41];
    uint8_t collected[41];
    test_dispatch_context_t context;
    wt_pkcs11_chunk_t chunk;
    wt_pkcs11_range_t range;
    size_t length = 0U;
    unsigned int calls;

    (void)memset(request, 0xA5, sizeof(request));
    (void)memset(response, 0x5A, sizeof(response));
    context.response = response;
    context.response_len = sizeof(response);
    context.fail = 0;
    wt_pkcs11_relay_set_client(TEST_APP_CLIENT);
    wt_pkcs11_relay_set_local_provider(provider_dispatch, &context);
    wt_pkcs11_relay_set_transport(test_relay_transport);
    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 0U) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN,
              WT_PKCS11_MESSAGE_MAX + 1U) == PSA_ERROR_INVALID_ARGUMENT,
          "empty and oversized PKCS11 messages are refused");
    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN, 16U) ==
              PSA_SUCCESS,
          "begin partial request");
    check(report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_EXECUTE,
              &length) == PSA_ERROR_BAD_STATE,
          "partial requests never execute");
    chunk.offset = 0U;
    chunk.length = 7U;
    (void)memset(chunk.data, 0xA5, sizeof(chunk.data));
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
              NULL, 0U, NULL) == PSA_ERROR_INVALID_ARGUMENT &&
              chunk_wipe_matches(PSA_ERROR_INVALID_ARGUMENT),
          "malformed chunk is refused and scrubbed");
    chunk.length = 8U;
    chunk.offset = UINT32_MAX;
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
              NULL, 0U, NULL) == PSA_ERROR_INVALID_ARGUMENT,
          "chunk offset overflow is refused");
    chunk.offset = 0U;
    g_relay_partial_read = 1;
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
              NULL, 0U, NULL) == PSA_ERROR_INVALID_ARGUMENT &&
              chunk_wipe_matches(PSA_ERROR_INVALID_ARGUMENT),
          "short copied read is refused and scrubbed");
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
              NULL, 0U, NULL) == PSA_SUCCESS &&
              chunk_wipe_matches(PSA_SUCCESS),
          "valid copied chunk is scrubbed after staging");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
              NULL, 0U, NULL) == PSA_ERROR_INVALID_ARGUMENT,
          "duplicate chunk offsets are refused");
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_ABORT, NULL, 0U,
              NULL, 0U, NULL) == PSA_SUCCESS,
          "abort discards a partial request");
    chunk_wipe_reset();
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, &chunk, 16U,
              NULL, 0U, NULL) == PSA_ERROR_BAD_STATE &&
              chunk_wipe_matches(PSA_ERROR_BAD_STATE),
          "bad-state chunk is refused and scrubbed");
    calls = g_provider_dispatches;
    check(wt_pkcs11_psa_call(request, sizeof(request), collected,
              sizeof(collected), &length) == 0 && length == sizeof(response) &&
              memcmp(collected, response, sizeof(response)) == 0 &&
              g_provider_dispatches == calls + 1U,
          "the production client completes one synchronous service exchange");
    context.fail = 1;
    calls = g_provider_dispatches;
    check(wt_pkcs11_psa_call(request, sizeof(request), collected,
              sizeof(collected), &length) == PSA_ERROR_GENERIC_ERROR &&
              g_provider_dispatches == calls + 1U &&
              buffer_is_zero(g_private_request, WT_PKCS11_MESSAGE_MAX) &&
              buffer_is_zero(g_private_response, WT_PKCS11_MESSAGE_MAX),
          "handler failure scrubs both frames without replay");
    context.fail = 0;
    wt_pkcs11_relay_set_local_provider(provider_oversize_dispatch, NULL);
    check(wt_pkcs11_psa_call(request, sizeof(request), collected,
              sizeof(collected), &length) == PSA_ERROR_GENERIC_ERROR &&
              buffer_is_zero(g_private_request, WT_PKCS11_MESSAGE_MAX) &&
              buffer_is_zero(g_private_response, WT_PKCS11_MESSAGE_MAX),
          "oversized handler response is refused and scrubbed");
    wt_pkcs11_relay_set_local_provider(provider_dispatch, &context);
    check(wt_pkcs11_psa_call(request, sizeof(request), collected,
              sizeof(collected), &length) == 0,
          "a new request succeeds after handler failures");
    calls = g_provider_dispatches;
    g_transport_repeat_fail_op = WT_PKCS11_OP_APP_EXECUTE;
    g_transport_repeat_failures = 1U;
    check(wt_pkcs11_psa_call(request, sizeof(request), collected,
              sizeof(collected), &length) == PSA_ERROR_COMMUNICATION_FAILURE &&
              g_provider_dispatches == calls,
          "lost execute transport never triggers an implicit replay");
    check(wt_pkcs11_psa_call(request, sizeof(request), collected,
              sizeof(collected), &length) == 0 &&
              g_provider_dispatches == calls + 1U,
          "next explicit request reconnects and succeeds");
    check(begin_message(TEST_APP_CLIENT, WT_PKCS11_OP_APP_BEGIN,
              sizeof(request)) == PSA_SUCCESS &&
          write_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_WRITE, request,
              sizeof(request)) == PSA_SUCCESS &&
          report_length(TEST_APP_CLIENT, WT_PKCS11_OP_APP_EXECUTE,
              &length) == PSA_SUCCESS,
          "prepare a response for bounded reads");
    range.offset = UINT32_MAX;
    range.length = 1U;
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, &range,
              sizeof(range), collected, 1U, NULL) == PSA_ERROR_INVALID_ARGUMENT,
          "response range overflow is refused");
    range.offset = 0U;
    range.length = sizeof(response);
    check(p11_op(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, &range,
              sizeof(range), collected, 1U, NULL) == PSA_ERROR_BUFFER_TOO_SMALL,
          "short response capacity cannot consume the reply");
    check(read_chunks(TEST_APP_CLIENT, WT_PKCS11_OP_APP_READ, collected,
              sizeof(collected)) == PSA_SUCCESS &&
              buffer_is_zero(g_private_response, WT_PKCS11_MESSAGE_MAX),
          "valid read consumes and scrubs the reply after a rejected read");
    check(p11_op(TEST_SP_CLIENT, WT_PKCS11_OP_APP_ABORT, NULL, 0U,
              NULL, 0U, NULL) != PSA_SUCCESS,
          "WT-FFM-0059 unrelated Secure caller cannot access PKCS11");
    wt_pkcs11_psa_close();
    wt_pkcs11_relay_set_local_provider(NULL, NULL);
    wt_pkcs11_relay_set_transport(NULL);
}

int main(void)
{
    test_direct_execution();
    test_bounds_and_recovery();
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: WT-FFM-0054 synchronous PKCS11 service\n");
    return 0;
}
