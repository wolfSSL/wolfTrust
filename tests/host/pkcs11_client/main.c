/* main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 */

/* PKCS11 PSA client suite: a scripted relay checks chunking, bounded polling,
 * response framing, abort recovery, and cached-connection recovery. */

#include "psa/client.h"
#include "psa/error.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/pkcs11_psa_transport.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum mock_state {
    MOCK_IDLE,
    MOCK_WRITING,
    MOCK_PENDING,
    MOCK_DONE
};

static int g_failures;
static int g_connects;
static int g_calls;
static int g_closes;
static int g_aborts;
static int32_t g_fail_op;
static psa_status_t g_fail_status;
static enum mock_state g_state;
static uint8_t g_request[WT_PKCS11_MESSAGE_MAX];
static size_t g_request_expected;
static size_t g_request_received;
static uint8_t g_response[WT_PKCS11_MESSAGE_MAX];
static size_t g_response_len;
static uint32_t g_poll_busy;
static int g_auto_complete;
static size_t g_forced_poll_len;
static size_t g_forced_read_len;

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

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    check(sid == WT_PKCS11_SERVICE_SID &&
              version == WT_PKCS11_SERVICE_VERSION,
          "client connects to SERVICE_PKCS11 with the supported version");
    g_connects++;
    return (psa_handle_t)42;
}

void psa_close(psa_handle_t handle)
{
    check(handle == (psa_handle_t)42,
          "client closes the cached PKCS11 handle");
    g_closes++;
}

static psa_status_t mock_begin(const psa_invec* in_vec, size_t in_len)
{
    const wt_pkcs11_length_t* length;

    if (in_vec == NULL || in_len != 1U ||
            in_vec[0].len != sizeof(*length) ||
            in_vec[0].base == NULL || g_state != MOCK_IDLE) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    length = (const wt_pkcs11_length_t*)in_vec[0].base;
    if (length->length == 0U || length->length > sizeof(g_request)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    g_request_expected = length->length;
    g_request_received = 0U;
    g_state = MOCK_WRITING;
    return PSA_SUCCESS;
}

static psa_status_t mock_write(const psa_invec* in_vec, size_t in_len)
{
    const wt_pkcs11_chunk_t* chunk;
    size_t header = sizeof(chunk->offset) + sizeof(chunk->length);

    if (in_vec == NULL || in_len != 1U || in_vec[0].base == NULL ||
            in_vec[0].len < header || g_state != MOCK_WRITING) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    chunk = (const wt_pkcs11_chunk_t*)in_vec[0].base;
    if (chunk->length != in_vec[0].len - header ||
            chunk->offset != g_request_received ||
            chunk->length > WT_PKCS11_CHUNK_MAX ||
            chunk->length > g_request_expected - g_request_received) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memcpy(g_request + g_request_received, chunk->data,
                 chunk->length);
    g_request_received += chunk->length;
    return PSA_SUCCESS;
}

static psa_status_t mock_poll(psa_outvec* out_vec, size_t out_len)
{
    wt_pkcs11_length_t length;

    if (out_vec == NULL || out_len != 1U || out_vec[0].base == NULL ||
            out_vec[0].len < sizeof(length)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (g_state == MOCK_PENDING) {
        if (g_poll_busy > 0U) {
            g_poll_busy--;
            return (psa_status_t)WT_PKCS11_E_BUSY;
        }
        if (g_auto_complete == 0) {
            return (psa_status_t)WT_PKCS11_E_BUSY;
        }
        g_state = MOCK_DONE;
    }
    if (g_state != MOCK_DONE) {
        return (psa_status_t)WT_PKCS11_E_EMPTY;
    }
    length.length = (uint32_t)g_response_len;
    (void)memcpy(out_vec[0].base, &length, sizeof(length));
    out_vec[0].len = g_forced_poll_len != 0U ? g_forced_poll_len :
                                                    sizeof(length);
    return PSA_SUCCESS;
}

static psa_status_t mock_read(const psa_invec* in_vec, size_t in_len,
                              psa_outvec* out_vec, size_t out_len)
{
    const wt_pkcs11_range_t* range;

    if (in_vec == NULL || in_len != 1U || out_vec == NULL || out_len != 1U ||
            in_vec[0].base == NULL || in_vec[0].len != sizeof(*range) ||
            out_vec[0].base == NULL || g_state != MOCK_DONE) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    range = (const wt_pkcs11_range_t*)in_vec[0].base;
    if (range->offset > g_response_len ||
            range->length > g_response_len - range->offset ||
            out_vec[0].len < range->length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    (void)memcpy(out_vec[0].base, g_response + range->offset, range->length);
    out_vec[0].len = g_forced_read_len != 0U ? g_forced_read_len :
                                                   range->length;
    if (range->offset + range->length == g_response_len) {
        g_state = MOCK_IDLE;
    }
    return PSA_SUCCESS;
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    g_calls++;
    if (handle != (psa_handle_t)42) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (type == g_fail_op) {
        g_fail_op = 0;
        return g_fail_status;
    }
    switch (type) {
        case WT_PKCS11_OP_APP_BEGIN:
            return mock_begin(in_vec, in_len);
        case WT_PKCS11_OP_APP_WRITE:
            return mock_write(in_vec, in_len);
        case WT_PKCS11_OP_APP_COMMIT:
            if (g_state != MOCK_WRITING ||
                    g_request_received != g_request_expected) {
                return PSA_ERROR_BAD_STATE;
            }
            g_state = MOCK_PENDING;
            return PSA_SUCCESS;
        case WT_PKCS11_OP_APP_POLL:
            return mock_poll(out_vec, out_len);
        case WT_PKCS11_OP_APP_READ:
            return mock_read(in_vec, in_len, out_vec, out_len);
        case WT_PKCS11_OP_APP_ABORT:
            g_state = MOCK_IDLE;
            g_aborts++;
            return PSA_SUCCESS;
        default:
            return PSA_ERROR_PROGRAMMER_ERROR;
    }
}

static void mock_reset(void)
{
    wt_pkcs11_psa_close();
    g_connects = 0;
    g_calls = 0;
    g_closes = 0;
    g_aborts = 0;
    g_fail_op = 0;
    g_fail_status = PSA_SUCCESS;
    g_state = MOCK_IDLE;
    g_request_expected = 0U;
    g_request_received = 0U;
    g_response_len = 0U;
    g_poll_busy = 0U;
    g_auto_complete = 1;
    g_forced_poll_len = 0U;
    g_forced_read_len = 0U;
    (void)memset(g_request, 0, sizeof(g_request));
    (void)memset(g_response, 0, sizeof(g_response));
}

static void fill_pattern(uint8_t* buffer, size_t length, uint8_t mask)
{
    size_t i;

    for (i = 0U; i < length; i++) {
        buffer[i] = (uint8_t)i ^ mask;
    }
}

static void test_arguments(void)
{
    uint8_t byte = 0U;
    size_t length = 0U;

    mock_reset();
    check(wt_pkcs11_psa_call(NULL, 1U, &byte, 1U, &length) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_pkcs11_psa_call(&byte, 0U, &byte, 1U, &length) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_pkcs11_psa_call(&byte, 1U, NULL, 1U, &length) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_pkcs11_psa_call(&byte, 1U, &byte, 0U, &length) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_pkcs11_psa_call(&byte, 1U, &byte, 1U, NULL) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          g_connects == 0 && g_calls == 0,
          "client rejects invalid call arguments before connecting");
}

static void test_chunking_and_polling(void)
{
    uint8_t request[WT_PKCS11_CHUNK_MAX + 17U];
    uint8_t output[WT_PKCS11_CHUNK_MAX + 23U];
    size_t output_len = 0U;

    mock_reset();
    fill_pattern(request, sizeof(request), 0x5AU);
    fill_pattern(g_response, sizeof(output), 0xA5U);
    g_response_len = sizeof(output);
    g_poll_busy = 2U;
    check(wt_pkcs11_psa_call(request, sizeof(request), output, sizeof(output),
              &output_len) == PSA_SUCCESS &&
          output_len == sizeof(output) &&
          memcmp(g_request, request, sizeof(request)) == 0 &&
          memcmp(output, g_response, sizeof(output)) == 0 &&
          g_connects == 1 && g_state == MOCK_IDLE,
          "multi-chunk client call completes after bounded busy polls");

    mock_reset();
    g_auto_complete = 0;
    check(wt_pkcs11_psa_call(request, 16U, output, sizeof(output),
              &output_len) == WT_PKCS11_E_BUSY && g_aborts == 1 &&
              g_state == MOCK_IDLE,
          "poll exhaustion aborts at the configured bound");
}

static void test_response_failures(void)
{
    uint8_t request[32];
    uint8_t output[32];
    size_t output_len = 99U;

    fill_pattern(request, sizeof(request), 0x11U);

    mock_reset();
    g_response_len = sizeof(output);
    check(wt_pkcs11_psa_call(request, sizeof(request), output, 8U,
              &output_len) == PSA_ERROR_BUFFER_TOO_SMALL &&
          output_len == 0U && g_aborts == 1 && g_state == MOCK_IDLE,
          "short response capacity aborts the completed transaction");

    mock_reset();
    g_response_len = sizeof(output);
    g_forced_poll_len = sizeof(wt_pkcs11_length_t) - 1U;
    check(wt_pkcs11_psa_call(request, sizeof(request), output, sizeof(output),
              &output_len) == PSA_ERROR_COMMUNICATION_FAILURE &&
              g_aborts == 1 && g_state == MOCK_IDLE,
          "short response-length metadata aborts the transaction");

    mock_reset();
    g_response_len = sizeof(output);
    g_forced_read_len = sizeof(output) - 1U;
    check(wt_pkcs11_psa_call(request, sizeof(request), output, sizeof(output),
              &output_len) == PSA_ERROR_COMMUNICATION_FAILURE &&
          g_aborts == 1 && g_state == MOCK_IDLE,
          "short response chunk aborts the transaction");

    mock_reset();
    g_response_len = sizeof(output);
    g_fail_op = WT_PKCS11_OP_APP_WRITE;
    g_fail_status = PSA_ERROR_GENERIC_ERROR;
    check(wt_pkcs11_psa_call(request, sizeof(request), output, sizeof(output),
              &output_len) == PSA_ERROR_GENERIC_ERROR &&
          g_aborts == 1 && g_state == MOCK_IDLE,
          "request-write failure aborts the partial transaction");
}

static void test_connection_recovery(void)
{
    static const psa_status_t dead[] = {
        PSA_ERROR_PROGRAMMER_ERROR,
        PSA_ERROR_CONNECTION_BUSY,
        PSA_ERROR_COMMUNICATION_FAILURE,
        PSA_ERROR_BAD_STATE
    };
    uint8_t request[16] = { 0U };
    uint8_t output[16];
    size_t output_len;
    size_t i;

    for (i = 0U; i < sizeof(dead) / sizeof(dead[0]); i++) {
        mock_reset();
        g_fail_op = WT_PKCS11_OP_APP_BEGIN;
        g_fail_status = dead[i];
        check(wt_pkcs11_psa_call(request, sizeof(request), output,
                  sizeof(output), &output_len) == dead[i] &&
              g_connects == 1 && g_closes == 1,
              "dead connection status evicts the cached handle");
        g_response_len = sizeof(output);
        check(wt_pkcs11_psa_call(request, sizeof(request), output,
                  sizeof(output), &output_len) == PSA_SUCCESS &&
              g_connects == 2,
              "the request after eviction reconnects");
    }
}

int main(void)
{
    test_arguments();
    test_chunking_and_polling();
    test_response_failures();
    test_connection_recovery();

    wt_pkcs11_psa_close();
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: PKCS11 PSA client chunking, polling, and recovery\n");
    return 0;
}
