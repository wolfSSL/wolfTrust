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

/* Host proof of the SERVICE_TPM mediated mailbox (WT-FFM-0054): the
 * application guest and the fwTPM guest both reach the relay through real
 * wt_ffm_connect/wt_ffm_call round trips on the in-process FF-M runtime,
 * and a whole TPM command frame crosses app -> relay -> fwTPM and its
 * response crosses back, byte-exact. Also proves the mediation rules: roles
 * are bound to the SPM-stamped client id, state transitions are enforced,
 * frames are bounded, and the relay fails closed until roles are bound. The
 * fwTPM side here is a loopback; the real responder is a later slice. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolftrust/ffm.h"
#include "wolftrust/services/tpm_relay.h"
#include "psa/client.h"

#define TEST_TPM_PARTITION 2
#define TEST_APP_CLIENT    (-1)
#define TEST_FTPM_CLIENT   (-2)
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

static psa_status_t app_submit(const uint8_t* cmd, size_t len)
{
    return tpm_op(TEST_APP_CLIENT, WT_TPM_OP_SUBMIT, cmd, len, NULL, 0U, NULL);
}

static psa_status_t app_poll(uint8_t* resp, size_t cap, size_t* len)
{
    return tpm_op(TEST_APP_CLIENT, WT_TPM_OP_POLL, NULL, 0U, resp, cap, len);
}

static psa_status_t ftpm_fetch(uint8_t* cmd, size_t cap, size_t* len)
{
    return tpm_op(TEST_FTPM_CLIENT, WT_TPM_OP_FETCH, NULL, 0U, cmd, cap, len);
}

static psa_status_t ftpm_respond(const uint8_t* resp, size_t len)
{
    return tpm_op(TEST_FTPM_CLIENT, WT_TPM_OP_RESPOND, resp, len, NULL, 0U,
                  NULL);
}

/* Full exchange: app submits cmd, fwTPM fetches it and posts resp built from
 * it, app collects resp. Returns 0 when every leg and byte checks out. */
static int round_trip(const uint8_t* cmd, size_t cmd_len, uint8_t* scratch,
                      size_t scratch_cap)
{
    static const uint8_t tag[4] = { 'T', 'P', 'M', 'r' };
    uint8_t resp[WT_TPM_FRAME_MAX];
    size_t n = 0U;
    size_t resp_len;

    if (app_submit(cmd, cmd_len) != PSA_SUCCESS) {
        return -1;
    }
    if (ftpm_fetch(scratch, scratch_cap, &n) != PSA_SUCCESS || n != cmd_len ||
            memcmp(scratch, cmd, cmd_len) != 0) {
        return -2;
    }
    resp_len = sizeof(tag) + cmd_len;
    if (resp_len > sizeof(resp)) {
        return -3;
    }
    memcpy(resp, tag, sizeof(tag));
    memcpy(resp + sizeof(tag), cmd, cmd_len);
    if (ftpm_respond(resp, resp_len) != PSA_SUCCESS) {
        return -4;
    }
    memset(scratch, 0, scratch_cap);
    if (app_poll(scratch, scratch_cap, &n) != PSA_SUCCESS || n != resp_len ||
            memcmp(scratch, resp, resp_len) != 0) {
        return -5;
    }
    return 0;
}

int main(void)
{
    static const uint8_t cmd[16] = {
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00,
        0x01, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08
    };
    static const uint8_t cmd2[12] = {
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00,
        0x01, 0x7B, 0x00, 0x00
    };
    uint8_t buf[WT_TPM_FRAME_MAX];
    uint8_t big[WT_TPM_FRAME_MAX + 64U];
    size_t n = 0U;
    psa_status_t st;

    check(wt_ffm_init(&g_runtime, &g_manifest, &g_port_ops, NULL) ==
              WT_FFM_SUCCESS,
          "in-process FF-M runtime initializes");

    /* === Fail closed until both roles are bound. */
    st = app_submit(cmd, sizeof(cmd));
    check(st == PSA_ERROR_NOT_SUPPORTED,
          "WT-FFM-0054 relay with unbound roles refuses every op");

    wt_tpm_relay_set_roles(TEST_APP_CLIENT, TEST_FTPM_CLIENT);

    /* === Idle slot: nothing to collect, nothing to serve. */
    check(app_poll(buf, sizeof(buf), &n) == (psa_status_t)WT_TPM_E_EMPTY,
          "app POLL with nothing in flight reports EMPTY");
    check(ftpm_fetch(buf, sizeof(buf), &n) == (psa_status_t)WT_TPM_E_EMPTY,
          "fwTPM FETCH with nothing pending reports EMPTY");
    check(ftpm_respond(cmd, sizeof(cmd)) == PSA_ERROR_BAD_STATE,
          "fwTPM RESPOND with nothing fetched is a bad state");

    /* === State machine along one exchange. */
    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS,
          "app SUBMIT lands a command frame in the slot");
    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS,
          "second SUBMIT reclaims the slot for a fresh transaction");
    check(app_poll(buf, sizeof(buf), &n) == (psa_status_t)WT_TPM_E_BUSY,
          "app POLL before the fwTPM served it reports BUSY");
    check(ftpm_respond(cmd, sizeof(cmd)) == PSA_ERROR_BAD_STATE,
          "fwTPM RESPOND before FETCH is a bad state");
    check(ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS && n == sizeof(cmd) &&
              memcmp(buf, cmd, sizeof(cmd)) == 0,
          "fwTPM FETCH receives the exact command frame");
    check(app_poll(buf, sizeof(buf), &n) == (psa_status_t)WT_TPM_E_BUSY,
          "app POLL while the fwTPM is serving reports BUSY");
    check(ftpm_respond(cmd, 8U) == PSA_SUCCESS,
          "fwTPM RESPOND posts the response frame");
    check(app_poll(buf, sizeof(buf), &n) == PSA_SUCCESS && n == 8U &&
              memcmp(buf, cmd, 8U) == 0,
          "app POLL collects the exact response frame");
    check(app_poll(buf, sizeof(buf), &n) == (psa_status_t)WT_TPM_E_EMPTY,
          "slot returns to idle after the response is collected");

    /* === Byte-exact full round trips, slot reusable. */
    check(round_trip(cmd, sizeof(cmd), buf, sizeof(buf)) == 0,
          "TPM command frame round-trips app -> SERVICE_TPM -> fwTPM -> app");
    memset(big, 0x5A, sizeof(big));
    check(round_trip(big, WT_TPM_FRAME_MAX - 8U, buf, sizeof(buf)) == 0,
          "a full-size frame round-trips through the relay");

    /* === Exact WT_TPM_FRAME_MAX boundary, both directions (the accept edge). */
    memset(big, 0x5A, sizeof(big));
    check(app_submit(big, WT_TPM_FRAME_MAX) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              n == WT_TPM_FRAME_MAX &&
              memcmp(buf, big, WT_TPM_FRAME_MAX) == 0,
          "a command of exactly WT_TPM_FRAME_MAX submits and fetches whole");
    check(ftpm_respond(big, WT_TPM_FRAME_MAX) == PSA_SUCCESS &&
              app_poll(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              n == WT_TPM_FRAME_MAX &&
              memcmp(buf, big, WT_TPM_FRAME_MAX) == 0,
          "a response of exactly WT_TPM_FRAME_MAX posts and polls whole");

    /* === Role enforcement by SPM-stamped identity. */
    check(tpm_op(TEST_FTPM_CLIENT, WT_TPM_OP_SUBMIT, cmd, sizeof(cmd), NULL,
                 0U, NULL) == PSA_ERROR_NOT_PERMITTED,
          "fwTPM client cannot SUBMIT as the application");
    check(tpm_op(TEST_APP_CLIENT, WT_TPM_OP_FETCH, NULL, 0U, buf, sizeof(buf),
                 &n) == PSA_ERROR_NOT_PERMITTED,
          "application client cannot FETCH as the fwTPM");
    check(tpm_op(TEST_OTHER_CLIENT, WT_TPM_OP_SUBMIT, cmd, sizeof(cmd), NULL,
                 0U, NULL) == PSA_ERROR_NOT_PERMITTED,
          "a third guest is refused both roles");
    check(tpm_op(TEST_SP_CLIENT, WT_TPM_OP_SUBMIT, cmd, sizeof(cmd), NULL, 0U,
                 NULL) != PSA_SUCCESS,
          "Secure-Partition caller refused by SERVICE_TPM");

    /* === Frame bounds. */
    check(app_submit(cmd, 0U) != PSA_SUCCESS,
          "zero-length command frame refused");
    check(app_submit(big, sizeof(big)) != PSA_SUCCESS,
          "oversized command frame refused by the relay");
    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              ftpm_respond(big, sizeof(big)) != PSA_SUCCESS,
          "oversized response frame refused by the relay");
    check(ftpm_respond(cmd, 8U) == PSA_SUCCESS &&
              app_poll(buf, 4U, &n) == PSA_ERROR_INVALID_ARGUMENT,
          "POLL with a too-small buffer is refused and keeps the response");
    check(app_poll(buf, sizeof(buf), &n) == PSA_SUCCESS && n == 8U,
          "POLL with a large enough buffer then collects it");

    /* === Guest-restart recovery (WT-FFM-0054): a restart of either endpoint
     *     mid-exchange must not wedge the single slot. */
    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS &&
              app_submit(cmd2, sizeof(cmd2)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              n == sizeof(cmd2) && memcmp(buf, cmd2, sizeof(cmd2)) == 0,
          "app resubmit in PENDING scrubs the old command and serves the new");
    check(ftpm_respond(cmd2, sizeof(cmd2)) == PSA_SUCCESS &&
              app_poll(buf, sizeof(buf), &n) == PSA_SUCCESS,
          "the reclaimed PENDING transaction then completes and idles");

    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              ftpm_respond(cmd, 8U) == PSA_SUCCESS &&
              app_submit(cmd2, sizeof(cmd2)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              n == sizeof(cmd2) && memcmp(buf, cmd2, sizeof(cmd2)) == 0,
          "app resubmit in DONE scrubs the stale response and serves the new");
    check(ftpm_respond(cmd2, sizeof(cmd2)) == PSA_SUCCESS &&
              app_poll(buf, sizeof(buf), &n) == PSA_SUCCESS,
          "the reclaimed DONE transaction then completes and idles");

    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) ==
                  (psa_status_t)WT_TPM_E_EMPTY &&
              ftpm_fetch(buf, sizeof(buf), &n) ==
                  (psa_status_t)WT_TPM_E_EMPTY,
          "fwTPM re-FETCH after a responder restart never replays the command");
    check(ftpm_respond(cmd, 8U) == PSA_ERROR_BAD_STATE &&
              app_poll(buf, sizeof(buf), &n) ==
                  (psa_status_t)WT_TPM_E_ABORTED &&
              app_poll(buf, sizeof(buf), &n) == (psa_status_t)WT_TPM_E_EMPTY,
          "the lost command fails to the application once, then idles");
    check(round_trip(cmd2, sizeof(cmd2), buf, sizeof(buf)) == 0,
          "the relay serves a fresh exchange after an aborted one");
    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) ==
                  (psa_status_t)WT_TPM_E_EMPTY &&
              app_submit(cmd2, sizeof(cmd2)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              n == sizeof(cmd2) && memcmp(buf, cmd2, sizeof(cmd2)) == 0 &&
              ftpm_respond(cmd2, sizeof(cmd2)) == PSA_SUCCESS &&
              app_poll(buf, sizeof(buf), &n) == PSA_SUCCESS,
          "a new SUBMIT reclaims an aborted slot");

    check(app_submit(cmd, sizeof(cmd)) == PSA_SUCCESS &&
              ftpm_fetch(buf, sizeof(buf), &n) == PSA_SUCCESS &&
              app_submit(cmd2, sizeof(cmd2)) == (psa_status_t)WT_TPM_E_BUSY,
          "SUBMIT while a command is IN_SERVICE is refused, not erased");
    check(ftpm_respond(cmd, 8U) == PSA_SUCCESS &&
              app_poll(buf, sizeof(buf), &n) == PSA_SUCCESS && n == 8U &&
              memcmp(buf, cmd, 8U) == 0,
          "the IN_SERVICE command still completes to its own response");

    if (g_failures == 0) {
        printf("PASS: tpm_relay (TPM frames over the SPM-mediated door, "
               "WT-FFM-0054)\n");
        return 0;
    }
    printf("FAIL: tpm_relay (%d failures)\n", g_failures);
    return 1;
}
