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

/* TPM PSA client suite: a scripted PSA transport checks connection recovery,
 * synchronous execution, response framing, and the user transport contract. */

#include "psa/client.h"
#include "psa/error.h"
#include "wolftrust/tpm_psa_transport.h"

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_tis.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_connects;
static int g_calls;
static int g_closes;
static psa_status_t g_call_status;
static uint8_t g_response[WT_TPM_FRAME_MAX];
static size_t g_response_len;
static size_t g_forced_out_len;
static int g_rng_mode;
static size_t g_rng_cap;
static uint32_t g_rng_rc;
static int g_rng_bad_cmd;
static size_t g_rng_over;
static uint32_t g_rng_size_skew;
static size_t g_rng_n_skew;
static uint8_t g_rng_tag_lo;
static int g_fail_call;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    }
    else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    check(sid == WT_TPM_SERVICE_SID && version == WT_TPM_SERVICE_VERSION,
          "client connects to SERVICE_TPM with the supported version");
    g_connects++;
    return (psa_handle_t)42;
}

void psa_close(psa_handle_t handle)
{
    check(handle == (psa_handle_t)42, "client closes the cached TPM handle");
    g_closes++;
}

static void mock_put32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Answers TPM2_GetRandom with byte i of the stream set to 0xA0 + i. */
static void mock_get_random(const psa_invec* in)
{
    static const uint8_t head[10] = { 0x80U, 0x01U, 0x00U, 0x00U, 0x00U,
                                      0x0CU, 0x00U, 0x00U, 0x01U, 0x7BU };
    static size_t stream;
    const uint8_t* cmd = (const uint8_t*)in->base;
    size_t want;
    size_t skew;
    size_t i;

    if (g_calls == 1) {
        stream = 0U;
    }
    if (in->len != 12U || memcmp(cmd, head, sizeof(head)) != 0) {
        g_rng_bad_cmd++;
        g_response_len = 0U;
        return;
    }
    want = ((size_t)cmd[10] << 8) | (size_t)cmd[11];
    if (want > g_rng_cap) {
        want = g_rng_cap;
    }
    want += g_rng_over;
    g_response[0] = 0x80U;
    g_response[1] = g_rng_tag_lo;
    mock_put32(&g_response[6], g_rng_rc);
    skew = (g_calls == 1) ? g_rng_n_skew : 0U;
    g_response[10] = (uint8_t)((want - skew) >> 8);
    g_response[11] = (uint8_t)(want - skew);
    for (i = 0U; i < want; i++) {
        g_response[12U + i] = (uint8_t)(0xA0U + stream + i);
    }
    stream += want;
    g_response_len = 12U + want;
    mock_put32(&g_response[2], (uint32_t)g_response_len + g_rng_size_skew);
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    size_t copy_len;

    g_calls++;
    if (handle != (psa_handle_t)42) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (g_call_status != PSA_SUCCESS) {
        return g_call_status;
    }
    if (g_fail_call != 0 && g_calls == g_fail_call) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    if (type != WT_TPM_OP_TRANSACT || in_vec == NULL || in_len != 1U ||
            out_vec == NULL || out_len != 1U ||
            in_vec[0].len > WT_TPM_FRAME_MAX ||
            out_vec[0].len > WT_TPM_FRAME_MAX) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (g_rng_mode) {
        mock_get_random(&in_vec[0]);
    }
    copy_len = g_response_len;
    if (copy_len > out_vec[0].len) {
        copy_len = out_vec[0].len;
    }
    (void)memcpy(out_vec[0].base, g_response, copy_len);
    out_vec[0].len = (g_forced_out_len != 0U) ? g_forced_out_len : copy_len;
    return PSA_SUCCESS;
}

static void mock_reset(void)
{
    wt_tpm_psa_close();
    g_connects = 0;
    g_calls = 0;
    g_closes = 0;
    g_call_status = PSA_SUCCESS;
    g_response_len = 0U;
    g_forced_out_len = 0U;
    g_rng_mode = 0;
    g_rng_cap = 32U;
    g_rng_rc = 0U;
    g_rng_bad_cmd = 0;
    g_rng_over = 0U;
    g_rng_size_skew = 0U;
    g_rng_n_skew = 0U;
    g_rng_tag_lo = 0x01U;
    g_fail_call = 0;
    (void)memset(g_response, 0, sizeof(g_response));
}

static void set_success_response(size_t declared, size_t received)
{
    g_response[0] = 0x80U;
    g_response[1] = 0x01U;
    g_response[2] = (uint8_t)(declared >> 24);
    g_response[3] = (uint8_t)(declared >> 16);
    g_response[4] = (uint8_t)(declared >> 8);
    g_response[5] = (uint8_t)declared;
    g_response_len = received;
}

static TPM_RC send_startup(void)
{
    Startup_In in;

    (void)memset(&in, 0, sizeof(in));
    in.startupType = TPM_SU_CLEAR;
    return TPM2_Startup(&in);
}

static void test_arguments(void)
{
    uint8_t frame[WT_TPM_FRAME_MAX + 1U];
    size_t len = 0U;

    mock_reset();
    check(wt_tpm_psa_transact(NULL, 1U, frame, sizeof(frame), &len) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_tpm_psa_transact(frame, 0U, frame, sizeof(frame), &len) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_tpm_psa_transact(frame, sizeof(frame), frame, sizeof(frame),
              &len) == PSA_ERROR_INVALID_ARGUMENT &&
          g_connects == 0 && g_calls == 0,
          "transact rejects invalid commands before connecting");
    check(wt_tpm_psa_transact(frame, 1U, NULL, 1U, &len) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_tpm_psa_transact(frame, 1U, frame, 0U, &len) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          wt_tpm_psa_transact(frame, 1U, frame, sizeof(frame), NULL) ==
              PSA_ERROR_INVALID_ARGUMENT &&
          g_connects == 0 && g_calls == 0,
          "transact rejects invalid response buffers before connecting");
}

static void test_connection_recovery(void)
{
    static const psa_status_t dead[] = {
        PSA_ERROR_PROGRAMMER_ERROR,
        PSA_ERROR_CONNECTION_BUSY,
        PSA_ERROR_COMMUNICATION_FAILURE,
        PSA_ERROR_BAD_STATE
    };
    uint8_t frame[TPM2_HEADER_SIZE] = { 0U };
    size_t i;
    size_t length;

    for (i = 0U; i < sizeof(dead) / sizeof(dead[0]); i++) {
        mock_reset();
        set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE);
        check(wt_tpm_psa_transact(frame, sizeof(frame), frame, sizeof(frame), &length) == PSA_SUCCESS &&
              g_connects == 1 && g_calls == 1,
              "first TPM request opens one cached connection");
        check(wt_tpm_psa_transact(frame, sizeof(frame), frame, sizeof(frame), &length) == PSA_SUCCESS &&
              g_connects == 1 && g_calls == 2,
              "next TPM request reuses the cached connection");
        g_call_status = dead[i];
        check(wt_tpm_psa_transact(frame, sizeof(frame), frame, sizeof(frame), &length) == dead[i] &&
              g_closes == 1,
              "a dead-connection status evicts the cached handle");
        g_call_status = PSA_SUCCESS;
        check(wt_tpm_psa_transact(frame, sizeof(frame), frame, sizeof(frame), &length) == PSA_SUCCESS &&
              g_connects == 2,
              "the request after eviction reconnects");
    }
}

static void test_execution_and_framing(void)
{
    TPM2_CTX ctx;

    check(TPM2_Init(&ctx, wt_tpm_psa_io, NULL) == TPM_RC_SUCCESS,
          "user transport initializes without a TIS startup");

    mock_reset();
    set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE);
    check(send_startup() == TPM_RC_SUCCESS && g_calls == 1,
          "one synchronous call returns the framed response");

    mock_reset();
    g_call_status = PSA_ERROR_CONNECTION_BUSY;
    check(send_startup() == TPM_RC_FAILURE && g_calls == 1,
          "a failed command is never implicitly replayed");

    mock_reset();
    set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE - 1U);
    check(send_startup() == TPM_RC_FAILURE,
          "a response shorter than the TPM header is refused");

    mock_reset();
    set_success_response(TPM2_HEADER_SIZE + 1U, TPM2_HEADER_SIZE);
    check(send_startup() == TPM_RC_FAILURE,
          "a response whose declared length disagrees is refused");

    mock_reset();
    set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE);
    g_forced_out_len = WT_TPM_FRAME_MAX + 1U;
    check(send_startup() == TPM_RC_FAILURE,
          "a response reported beyond the packet capacity is refused");

    (void)TPM2_Cleanup(&ctx);
}

static void test_init_contract(void)
{
    TPM2_CTX ctx;
    int rc;

    mock_reset();
    check(TPM2_Init(&ctx, NULL, NULL) == BAD_FUNC_ARG && g_calls == 0,
          "initialization without the PSA IO callback is refused");
    rc = TPM2_Init(&ctx, wt_tpm_psa_io, NULL);
    check(rc == TPM_RC_SUCCESS && ctx.locality == WOLFTPM_LOCALITY_DEFAULT &&
          TPM2_GetActiveCtx() == &ctx,
          "direct TPM initialization uses the default locality");
    set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE);
    check(send_startup() == TPM_RC_SUCCESS && g_connects == 1,
          "the first command opens the service connection");
    check(TPM2_Cleanup(&ctx) == TPM_RC_SUCCESS &&
          TPM2_GetActiveCtx() == NULL && g_closes == 0,
          "TPM cleanup leaves the service connection to the caller");
    wt_tpm_psa_close();
    check(g_closes == 1, "closing the transport closes the connection");

    check(TPM2_Init_ex(&ctx, wt_tpm_psa_io, NULL, 1) == BAD_FUNC_ARG &&
          g_calls == 1,
          "a TIS chip startup is refused without I/O");
    (void)TPM2_Cleanup(&ctx);
}

static int rng_stream_ok(const uint8_t* out, size_t len)
{
    size_t i;

    for (i = 0U; i < len; i++) {
        if (out[i] != (uint8_t)(0xA0U + i)) {
            return 0;
        }
    }
    return 1;
}

static int all_zero(const uint8_t* out, size_t len)
{
    size_t i;

    for (i = 0U; i < len; i++) {
        if (out[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

static void test_random(void)
{
    uint8_t out[40];

    mock_reset();
    check(wt_tpm_psa_random(NULL, 1U) == PSA_ERROR_INVALID_ARGUMENT &&
              wt_tpm_psa_random(out, 0U) == PSA_ERROR_INVALID_ARGUMENT &&
              g_calls == 0,
          "random rejects invalid buffers before connecting");

    mock_reset();
    g_rng_mode = 1;
    (void)memset(out, 0, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) == 0 && g_calls == 2 &&
              g_rng_bad_cmd == 0 && rng_stream_ok(out, sizeof(out)),
          "random splits a request into well-formed GetRandom commands");

    mock_reset();
    g_rng_mode = 1;
    g_rng_cap = 16U;
    (void)memset(out, 0, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) == 0 && g_calls == 3 &&
              rng_stream_ok(out, sizeof(out)),
          "random keeps asking when the TPM returns fewer bytes");

    mock_reset();
    g_rng_mode = 1;
    g_rng_rc = 0x100U;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && all_zero(out, sizeof(out)),
          "random refuses a TPM error and zeroes the output");

    mock_reset();
    g_rng_mode = 1;
    g_rng_cap = 0U;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && g_calls == 1 &&
              all_zero(out, sizeof(out)),
          "random refuses an empty GetRandom response");

    mock_reset();
    g_rng_mode = 1;
    g_rng_over = 1U;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, 8U) == PSA_ERROR_COMMUNICATION_FAILURE &&
              all_zero(out, 8U),
          "random refuses a response longer than requested");

    mock_reset();
    g_rng_mode = 1;
    g_forced_out_len = 12U + 31U;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && all_zero(out, sizeof(out)),
          "random refuses a size field that disagrees with the frame");

    mock_reset();
    g_rng_mode = 1;
    g_rng_size_skew = 1U;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && all_zero(out, sizeof(out)),
          "random refuses a header length that disagrees with the frame");

    mock_reset();
    g_rng_mode = 1;
    g_rng_n_skew = 1U;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && all_zero(out, sizeof(out)),
          "random refuses a byte count that disagrees with the frame");

    mock_reset();
    g_rng_mode = 1;
    g_rng_tag_lo = 0x02U;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && all_zero(out, sizeof(out)),
          "random refuses a response with a session tag");

    mock_reset();
    g_rng_mode = 1;
    g_fail_call = 1;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && g_calls == 1 &&
              all_zero(out, sizeof(out)),
          "random reports a transport failure and zeroes the output");

    mock_reset();
    g_rng_mode = 1;
    g_fail_call = 2;
    (void)memset(out, 0x55, sizeof(out));
    check(wt_tpm_psa_random(out, sizeof(out)) ==
              PSA_ERROR_COMMUNICATION_FAILURE && g_calls == 2 &&
              all_zero(out, sizeof(out)),
          "random zeroes earlier chunks when a later transfer fails");
}

int main(void)
{
    test_arguments();
    test_connection_recovery();
    test_execution_and_framing();
    test_init_contract();
    test_random();

    wt_tpm_psa_close();
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: TPM PSA client recovery, framing, and initialization\n");
    return 0;
}
