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
 * synchronous execution, response framing, and the SWTPM initialization contract. */

#include "psa/client.h"
#include "psa/error.h"
#include "wolftrust/tpm_psa_transport.h"

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_swtpm.h>
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
    if (type != WT_TPM_OP_TRANSACT || in_vec == NULL || in_len != 1U ||
            out_vec == NULL || out_len != 1U ||
            in_vec[0].len > WT_TPM_FRAME_MAX ||
            out_vec[0].len > WT_TPM_FRAME_MAX) {
        return PSA_ERROR_PROGRAMMER_ERROR;
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

static void packet_init(TPM2_Packet* packet, uint8_t* frame, size_t size)
{
    (void)memset(frame, 0, size);
    packet->buf = frame;
    packet->size = (int)size;
    packet->pos = TPM2_HEADER_SIZE;
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
    TPM2_Packet packet;
    uint8_t frame[32];
    int rc;

    mock_reset();
    packet_init(&packet, frame, sizeof(frame));
    set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE);
    rc = TPM2_SWTPM_SendCommand(&ctx, &packet);
    check(rc == TPM_RC_SUCCESS && g_calls == 1 &&
          packet.size == TPM2_HEADER_SIZE,
          "one synchronous call returns the framed response");

    mock_reset();
    packet_init(&packet, frame, sizeof(frame));
    g_call_status = PSA_ERROR_CONNECTION_BUSY;
    rc = TPM2_SWTPM_SendCommand(&ctx, &packet);
    check(rc == TPM_RC_FAILURE && g_calls == 1,
          "a failed command is never implicitly replayed");

    mock_reset();
    packet_init(&packet, frame, sizeof(frame));
    set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE - 1U);
    check(TPM2_SWTPM_SendCommand(&ctx, &packet) == TPM_RC_FAILURE,
          "a response shorter than the TPM header is refused");

    mock_reset();
    packet_init(&packet, frame, sizeof(frame));
    set_success_response(TPM2_HEADER_SIZE + 1U, TPM2_HEADER_SIZE);
    check(TPM2_SWTPM_SendCommand(&ctx, &packet) == TPM_RC_FAILURE,
          "a response whose declared length disagrees is refused");

    mock_reset();
    packet_init(&packet, frame, sizeof(frame));
    set_success_response(TPM2_HEADER_SIZE, TPM2_HEADER_SIZE);
    g_forced_out_len = sizeof(frame) + 1U;
    check(TPM2_SWTPM_SendCommand(&ctx, &packet) == TPM_RC_FAILURE,
          "a response reported beyond the packet capacity is refused");
}

static void test_packet_bounds(void)
{
    TPM2_CTX ctx;
    TPM2_Packet packet;
    uint8_t frame[32];

    mock_reset();
    packet_init(&packet, frame, sizeof(frame));
    packet.size = 0;
    check(TPM2_SWTPM_SendCommand(&ctx, &packet) == BAD_FUNC_ARG &&
              g_connects == 0 && g_calls == 0,
          "SWTPM transport rejects a zero packet capacity before I/O");

    packet_init(&packet, frame, sizeof(frame));
    packet.size = -1;
    check(TPM2_SWTPM_SendCommand(&ctx, &packet) == BAD_FUNC_ARG &&
              g_connects == 0 && g_calls == 0,
          "SWTPM transport rejects a negative packet capacity before I/O");

    packet_init(&packet, frame, sizeof(frame));
    packet.pos = packet.size + 1;
    check(TPM2_SWTPM_SendCommand(&ctx, &packet) == BAD_FUNC_ARG &&
              g_connects == 0 && g_calls == 0,
          "SWTPM transport rejects a command beyond packet capacity");
}

static void test_locality_contract(void)
{
    TPM2_CTX ctx;
    int rc;

    mock_reset();
    check(TPM2_TIS_RequestLocality(NULL, 1) == BAD_FUNC_ARG,
          "locality request rejects a NULL context");
    rc = TPM2_Init(&ctx, NULL, NULL);
    check(rc == TPM_RC_SUCCESS && ctx.locality == WOLFTPM_LOCALITY_DEFAULT &&
          TPM2_GetActiveCtx() == &ctx,
          "direct TPM initialization records the granted locality");
    check(TPM2_Cleanup(&ctx) == TPM_RC_SUCCESS &&
          TPM2_GetActiveCtx() == NULL,
          "direct TPM cleanup clears the active context");

    rc = TPM2_Init_ex(&ctx, NULL, NULL, 1);
    check(rc == TPM_RC_SUCCESS && ctx.locality == WOLFTPM_LOCALITY_DEFAULT &&
          TPM2_GetActiveCtx() == &ctx,
          "explicit SWTPM startup records the granted locality");
    check(TPM2_Cleanup(&ctx) == TPM_RC_SUCCESS &&
          TPM2_GetActiveCtx() == NULL,
          "explicit SWTPM startup remains cleanup-safe");
}

int main(void)
{
    test_arguments();
    test_connection_recovery();
    test_execution_and_framing();
    test_packet_bounds();
    test_locality_contract();

    wt_tpm_psa_close();
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: TPM PSA client recovery, framing, and initialization\n");
    return 0;
}
