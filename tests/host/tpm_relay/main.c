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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolftrust/ffm.h"
#include "wolftrust/services/tpm_relay.h"
#include "psa/client.h"

#define TEST_TPM_PARTITION 2
#define TEST_APP_CLIENT    (-1)
#define TEST_OTHER_CLIENT  (-3)
#define TEST_SP_CLIENT     (3)

static int g_failures;

static void check(int ok, const char* what)
{
    if (ok) {
        printf("PASS: %s\n", what);
    }
    else {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/* ---- in-process FF-M runtime fixture ---- */
static wt_ffm_runtime_t g_runtime;

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
    return wt_tpm_relay_dispatch(NULL, runtime, partition_id);
}

static const wt_ffm_port_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    test_dispatch,
    test_panic
};

static const wt_service_descriptor_t g_services[] = {
    {
        "SERVICE_TPM", WT_TPM_SERVICE_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x40U, 0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_TPM", TEST_TPM_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "tpm-relay-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

/* One op from one client: connect, call, close. */
static psa_status_t tpm_op(int32_t client_id, int32_t op, const uint8_t* in,
                           size_t in_len, uint8_t* out, size_t out_cap,
                           size_t* out_len)
{
    psa_invec iv[1];
    psa_outvec ov[1];
    int32_t handle;
    psa_status_t st;

    handle = (int32_t)wt_ffm_connect(&g_runtime, client_id,
                                     WT_TPM_SERVICE_SID, 1U);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_CONNECTION_REFUSED;
    }
    iv[0].base = in;
    iv[0].len = in_len;
    ov[0].base = out;
    ov[0].len = out_cap;
    st = wt_ffm_call(&g_runtime, client_id, handle, op,
                     (in != NULL) ? iv : NULL, (in != NULL) ? 1U : 0U,
                     (out != NULL) ? ov : NULL, (out != NULL) ? 1U : 0U);
    if (out_len != NULL) {
        *out_len = ov[0].len;
    }
    (void)wt_ffm_close(&g_runtime, client_id, handle);
    return st;
}

static unsigned int g_direct_calls;
static const uint8_t* g_direct_command;
static uint8_t* g_direct_response;
static int g_direct_fail;
static int g_direct_length_mode;

static int direct_handler(const uint8_t* command, size_t command_len,
                           uint8_t* response, size_t response_cap,
                           size_t* response_len, void* context)
{
    size_t i;

    (void)context;
    g_direct_calls++;
    g_direct_command = command;
    g_direct_response = response;
    if (command_len > response_cap) {
        return -1;
    }
    for (i = 0U; i < command_len; i++) {
        response[i] = command[i] ^ 0x5AU;
    }
    *response_len = command_len;
    if (g_direct_length_mode > 0) {
        *response_len = response_cap + 1U;
    }
    else if (g_direct_length_mode < 0) {
        *response_len = 0U;
    }
    return g_direct_fail;
}

static void test_direct_exchange(void)
{
    uint8_t command[WT_TPM_FRAME_MAX + 1U];
    uint8_t response[WT_TPM_FRAME_MAX];
    size_t length = 0U;
    size_t i;
    unsigned int calls;
    int exact = 1;
    int scrubbed = 1;

    check(wt_ffm_init(&g_runtime, &g_manifest, &g_port_ops, NULL) ==
              WT_FFM_SUCCESS, "WT-FFM-0054 direct TPM runtime initializes");
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 1U,
              response, sizeof(response), &length) == PSA_ERROR_NOT_SUPPORTED,
          "unbound TPM service fails closed");
    wt_tpm_relay_set_client(TEST_APP_CLIENT);
    wt_tpm_relay_set_local_provider(direct_handler, NULL);
    for (i = 0U; i < sizeof(command); i++) {
        command[i] = (uint8_t)i;
    }
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command,
              WT_TPM_FRAME_MAX, response, sizeof(response), &length) ==
              PSA_SUCCESS && length == WT_TPM_FRAME_MAX,
          "one copied call carries maximum TPM command and response");
    for (i = 0U; i < sizeof(response); i++) {
        if (response[i] != (uint8_t)(command[i] ^ 0x5AU)) {
            exact = 0;
        }
        if (g_direct_command[i] != 0U || g_direct_response[i] != 0U) {
            scrubbed = 0;
        }
    }
    check(exact && scrubbed, "direct TPM delivers exact bytes and scrubs staging");
    calls = g_direct_calls;
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 0U,
              response, sizeof(response), &length) == PSA_ERROR_INVALID_ARGUMENT &&
          tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, 0U, &length) == PSA_ERROR_INVALID_ARGUMENT &&
              g_direct_calls == calls,
          "empty input or output is refused before executing a TPM command");
    check(tpm_op(TEST_OTHER_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) == PSA_ERROR_NOT_PERMITTED &&
              g_direct_calls == calls,
          "WT-FFM-0059 wrong TPM caller never reaches the handler");
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command,
              sizeof(command), response, 16U, &length) ==
              PSA_ERROR_INVALID_ARGUMENT && g_direct_calls == calls,
          "oversized direct command is rejected before dispatch");
    check(tpm_op(TEST_APP_CLIENT, 1 /* retired SUBMIT */, command, 16U,
              response, sizeof(response), &length) == PSA_ERROR_NOT_SUPPORTED &&
              g_direct_calls == calls,
          "retired worker operations cannot execute commands");
    check(tpm_op(TEST_SP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) != PSA_SUCCESS &&
              g_direct_calls == calls,
          "WT-FFM-0059 unrelated Secure caller cannot access TPM");
    g_direct_fail = -1;
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) == PSA_ERROR_GENERIC_ERROR &&
              g_direct_calls == calls + 1U && g_direct_command[0] == 0U &&
              g_direct_response[0] == 0U,
          "failed direct command is scrubbed and never replayed");
    g_direct_fail = 0;
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) == PSA_SUCCESS,
          "a new direct command succeeds after a handler failure");
    g_direct_length_mode = 1;
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) == PSA_ERROR_GENERIC_ERROR &&
              g_direct_response[0] == 0U,
          "oversized TPM handler response is refused and scrubbed");
    g_direct_length_mode = -1;
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) == PSA_ERROR_GENERIC_ERROR,
          "empty TPM handler response is refused");
    g_direct_length_mode = 0;
    calls = g_direct_calls;
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, 8U, &length) == PSA_ERROR_INVALID_ARGUMENT &&
              g_direct_calls == calls + 1U && g_direct_response[0] == 0U,
          "short output cannot retain or replay an executed TPM command");
    wt_tpm_relay_set_client(1);
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) == PSA_ERROR_NOT_SUPPORTED,
          "invalid caller binding fails closed");
    wt_tpm_relay_set_client(TEST_APP_CLIENT);
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_TRANSACT, command, 16U,
              response, sizeof(response), &length) == PSA_SUCCESS,
          "new command succeeds after rebinding the restarted service");
}

int main(void)
{
    test_direct_exchange();
    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: WT-FFM-0054 synchronous TPM service\n");
    return 0;
}
