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

#include "psa_binding.h"

#include "val_interfaces.h"

#include <stdio.h>
#include <string.h>

#define TEST_SERVER_PARTITION 1
#define TEST_CLIENT_PARTITION 2
#define TEST_NS_CLIENT        (-1)

typedef struct test_context {
    psa_client_id_t caller;
    int32_t partition;
    unsigned int failures;
} test_context_t;

static test_context_t g_context;

/* Selects which test's server behavior test_dispatch() provides (0 =
 * generic reply-success). The upstream tests reuse SIDs with different
 * server expectations, so dispatch keys on the active test, not the SID.
 * Every per-test behavior below is derived solely from the compiled client
 * sources' visible assertions plus the pinned FF-M specification; the
 * upstream suite's own partition-side sources are not consulted. */
static int g_active_test;
static int g_i002_check;
static int g_i002_connect_seq;
static int g_i002_call_seq;
static int g_i003_check;

int32_t client_test_psa_framework_version(caller_security_t caller);
int32_t client_test_psa_version(caller_security_t caller);
int32_t client_test_sid_does_not_exists(caller_security_t caller);
int32_t client_test_strict_policy_higher_version(caller_security_t caller);
int32_t client_test_strict_policy_lower_version(caller_security_t caller);
int32_t client_test_relax_policy_higher_version(caller_security_t caller);
int32_t client_test_unspecified_policy_with_higher_version(
    caller_security_t caller);
int32_t client_test_unspecified_policy_with_lower_version(
    caller_security_t caller);
int32_t client_test_psa_call_with_iovec_more_than_max_limit(
    caller_security_t caller);
int32_t client_test_psa_call_with_neg_type(caller_security_t caller);
int32_t client_test_connection_busy_and_reject(caller_security_t caller);
int32_t client_test_psa_call_with_allowed_status_code(
    caller_security_t caller);
int32_t client_test_identity(caller_security_t caller);
int32_t client_test_spm_concurrent_connect_limit(caller_security_t caller);
int32_t client_test_psa_block_behave(caller_security_t caller);
int32_t client_test_psa_poll_behave(caller_security_t caller);
int32_t client_test_accept_and_close_connect(caller_security_t caller);
int32_t client_test_connect_with_allowed_version_policy(
    caller_security_t caller);
int32_t client_test_psa_call_with_allowed_type_values(
    caller_security_t caller);
int32_t client_test_zero_length_invec(caller_security_t caller);
int32_t client_test_zero_length_outvec(caller_security_t caller);
int32_t client_test_call_read_and_skip(caller_security_t caller);
int32_t client_test_call_and_write(caller_security_t caller);
int32_t client_test_psa_set_rhandle(caller_security_t caller);
int32_t client_test_overlapping_vectors(caller_security_t caller);
int32_t client_test_secure_access_only_connection(caller_security_t caller);
int32_t client_test_psa_close_with_invalid_handle(caller_security_t caller);
int32_t client_test_psa_call_with_invalid_handle(caller_security_t caller);
int32_t client_test_psa_call_with_null_handle(caller_security_t caller);
int32_t client_test_psa_drop_connection(caller_security_t caller);
int32_t client_test_psa_wait_signal_mask(caller_security_t caller);
int32_t client_test_dynamic_mem_alloc_fn(caller_security_t caller);
int32_t client_test_mem_manipulation_fn(caller_security_t caller);
int32_t client_test_psa_rot_lifecycle_state(caller_security_t caller);

val_api_t* valtest_entry_i001;
psa_api_t* psatest_entry_i001;
val_api_t* valtest_entry_i002;
psa_api_t* psatest_entry_i002;
val_api_t* valtest_entry_i003;
psa_api_t* psatest_entry_i003;
val_api_t* valtest_entry_i004;
psa_api_t* psatest_entry_i004;
val_api_t* valtest_entry_i005;
psa_api_t* psatest_entry_i005;
val_api_t* valtest_entry_i006;
psa_api_t* psatest_entry_i006;
val_api_t* valtest_entry_i007;
psa_api_t* psatest_entry_i007;
val_api_t* valtest_entry_i008;
psa_api_t* psatest_entry_i008;
val_api_t* valtest_entry_i010;
psa_api_t* psatest_entry_i010;
val_api_t* valtest_entry_i011;
psa_api_t* psatest_entry_i011;
val_api_t* valtest_entry_i012;
psa_api_t* psatest_entry_i012;
val_api_t* valtest_entry_i024;
psa_api_t* psatest_entry_i024;
val_api_t* valtest_entry_i025;
psa_api_t* psatest_entry_i025;
val_api_t* valtest_entry_i026;
psa_api_t* psatest_entry_i026;
val_api_t* valtest_entry_i027;
psa_api_t* psatest_entry_i027;
val_api_t* valtest_entry_i063;
psa_api_t* psatest_entry_i063;
val_api_t* valtest_entry_i067;
psa_api_t* psatest_entry_i067;
val_api_t* valtest_entry_i071;
psa_api_t* psatest_entry_i071;
val_api_t* valtest_entry_i088;
psa_api_t* psatest_entry_i088;
val_api_t* valtest_entry_i090;
psa_api_t* psatest_entry_i090;

static const wt_service_descriptor_t g_services[] = {
    {
        "SERVER_TEST_DISPATCHER", SERVER_TEST_DISPATCHER_SID,
        SERVER_TEST_DISPATCHER_VERSION, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    },
    {
        "SERVER_SECURE_CONNECT_ONLY", SERVER_SECURE_CONNECT_ONLY_SID,
        SERVER_SECURE_CONNECT_ONLY_VERSION, WT_SERVICE_VERSION_RELAXED,
        0x20U, 0U, 0U, 1U
    },
    {
        "SERVER_STRICT_VERSION", SERVER_STRICT_VERSION_SID,
        SERVER_STRICT_VERSION_VERSION, WT_SERVICE_VERSION_STRICT,
        0x40U, 0U, 1U, 1U
    },
    {
        "SERVER_RELAX_VERSION", SERVER_RELAX_VERSION_SID,
        SERVER_RELAX_VERSION_VERSION, WT_SERVICE_VERSION_RELAXED,
        0x80U, 0U, 1U, 1U
    },
    {
        /* FF-M defaults an unspecified version_policy to STRICT at version 1. */
        "SERVER_UNSPECIFIED_VERSION", SERVER_UNSPECIFIED_VERSION_SID,
        SERVER_UNSPECIFIED_VERSION_VERSION, WT_SERVICE_VERSION_STRICT,
        0x100U, 0U, 1U, 1U
    },
    {
        "SERVER_CONNECTION_DROP", SERVER_CONNECTION_DROP_SID,
        SERVER_CONNECTION_DROP_VERSION, WT_SERVICE_VERSION_RELAXED,
        0x200U, 0U, 1U, 1U
    }
};

static const uint32_t g_dependencies[] = {
    SERVER_TEST_DISPATCHER_SID,
    SERVER_SECURE_CONNECT_ONLY_SID,
    SERVER_STRICT_VERSION_SID,
    SERVER_RELAX_VERSION_SID,
    SERVER_UNSPECIFIED_VERSION_SID,
    SERVER_CONNECTION_DROP_SID
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "SERVER_PARTITION", TEST_SERVER_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    },
    {
        "CLIENT_PARTITION", TEST_CLIENT_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        NULL, 0U, g_dependencies,
        sizeof(g_dependencies) / sizeof(g_dependencies[0]), NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "psa-arch-tests",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static int32_t report(const char* test_id, const char* name,
                      int32_t status)
{
    if (status == VAL_STATUS_SUCCESS) {
        (void)printf("PASS: Arm PSA FF %s %s\n", test_id, name);
        return VAL_STATUS_SUCCESS;
    }
    if (val_status_step((uint32_t)status) == VAL_STEP_SKIPPED) {
        (void)printf("SKIP: Arm PSA FF %s %s\n", test_id, name);
        return VAL_STATUS_SUCCESS;
    }
    (void)fprintf(stderr, "FAIL: Arm PSA FF %s %s\n", test_id, name);
    return status;
}

static val_status_t test_print(print_verbosity_t verbosity,
                               const char* string, int32_t data)
{
    if (verbosity == ERROR)
        (void)fprintf(stderr, string, data);
    return VAL_STATUS_SUCCESS;
}

static val_status_t test_err_check(uint32_t checkpoint, val_status_t status)
{
    (void)checkpoint;
    return status;
}

static val_status_t test_set_boot_flag(boot_state_t state)
{
    (void)state;
    return VAL_STATUS_SUCCESS;
}

static val_status_t test_ipc_connect(uint32_t sid, uint32_t version,
                                     psa_handle_t* handle)
{
    *handle = psa_connect(sid, version);
    return PSA_HANDLE_IS_VALID(*handle) ? VAL_STATUS_SUCCESS :
                                          VAL_STATUS_CONNECTION_FAILED;
}

static void test_ipc_close(psa_handle_t handle)
{
    psa_close(handle);
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

/* i003 check 3 server. The client (test_i003.c client_test_call_read_and_skip)
 * sends four all-input vectors — two ints (0xaa, 0xbb) and the little-endian
 * u64s 0x1122334455667788 and 0x1020304050607080 — and requires only a
 * nonnegative reply, asking the server to exercise inbound/outbound read and
 * skip. The sequence below is wolfTrust's own: partial read, skip advancing
 * then clamping at the vector end, a truncated read, and zero-length
 * read/skip, with every expected value the little-endian slice of the
 * client's documented data at the current cursor. A mismatch replies a
 * negative status, which fails the client call. */
static psa_status_t dispatch_i003_read_skip(int32_t partition_id,
                                            psa_handle_t handle)
{
    int a = 0;

    if (wt_spm_host_read(partition_id, handle, 0, &a, sizeof(int)) !=
            sizeof(int) || a != 0xaa)
        return -3;
    if (wt_spm_host_read(partition_id, handle, 1, &a, sizeof(int)) !=
            sizeof(int) || a != 0xbb)
        return -4;
    /* invec 2, cursor 0: the first four LE bytes of 0x1122334455667788. */
    if (wt_spm_host_read(partition_id, handle, 2, &a, 4U) != 4U ||
            a != 0x55667788)
        return -5;
    /* Skip two, then a three-byte read truncates to the two remaining. */
    if (wt_spm_host_skip(partition_id, handle, 2, 2U) != 2U)
        return -6;
    a = 0;
    if (wt_spm_host_read(partition_id, handle, 2, &a, 3U) != 2U ||
            a != 0x1122)
        return -7;
    /* Exhausted: skip clamps to zero and a zero-length read reads nothing. */
    if (wt_spm_host_skip(partition_id, handle, 2, 5U) != 0U)
        return -8;
    if (wt_spm_host_read(partition_id, handle, 2, &a, 0U) != 0U ||
            a != 0x1122)
        return -9;
    /* invec 3: a zero-length skip moves nothing. */
    if (wt_spm_host_skip(partition_id, handle, 3, 0U) != 0U)
        return -10;
    if (wt_spm_host_read(partition_id, handle, 3, &a, 4U) != 4U ||
            a != 0x50607080)
        return -11;
    /* Skip one, then a four-byte read truncates to the three remaining. */
    if (wt_spm_host_skip(partition_id, handle, 3, 1U) != 1U)
        return -12;
    a = 0;
    if (wt_spm_host_read(partition_id, handle, 3, &a, 4U) != 3U ||
            a != 0x102030)
        return -13;
    if (wt_spm_host_skip(partition_id, handle, 3, 5U) != 0U)
        return -14;
    return PSA_SUCCESS;
}

/* Per-check server for Arm FF-M test i003 (invec/outvec data plane). Each
 * client check runs its own connect/call/close; g_i003_check selects the
 * matching server behavior. */
static int dispatch_i003(int32_t partition_id,
                         const psa_msg_t* message)
{
    static int rhandle_a = 5;
    static int rhandle_b = 10;
    static int call_seq;
    int values[5];
    psa_handle_t handle;
    psa_status_t reply;
    int i;

    handle = message->handle;
    reply = PSA_SUCCESS;
    if (message->type == PSA_IPC_CONNECT) {
        if (g_i003_check == 5)
            call_seq = 0;
        return wt_spm_host_reply(partition_id, handle, reply);
    }
    if (message->type == PSA_IPC_DISCONNECT)
        return wt_spm_host_reply(partition_id, handle, PSA_SUCCESS);

    values[0] = 0xaa;
    values[1] = 0xbb;
    values[2] = 0xcc;
    values[3] = 0xdd;
    values[4] = 0xee;
    switch (g_i003_check) {
    case 1:
        if (wt_spm_host_read(partition_id, handle, 2, &values[0],
                sizeof(int)) != sizeof(int))
            reply = -1;
        else
            (void)wt_spm_host_write(partition_id, handle, 0, &values[0],
                sizeof(int));
        break;
    case 2:
        if (wt_spm_host_read(partition_id, handle, 0, &values[0],
                sizeof(int)) != sizeof(int))
            reply = -1;
        else
            (void)wt_spm_host_write(partition_id, handle, 2, &values[0],
                sizeof(int));
        break;
    case 3:
        reply = dispatch_i003_read_skip(partition_id, handle);
        break;
    case 4:
        for (i = 0; i < 3; i++)
            (void)wt_spm_host_write(partition_id, handle, (uint32_t)i,
                &values[i], sizeof(int));
        (void)wt_spm_host_write(partition_id, handle, 3, &values[3], 0U);
        (void)wt_spm_host_write(partition_id, handle, 3, &values[3], 1U);
        (void)wt_spm_host_write(partition_id, handle, 3, &values[4], 1U);
        break;
    case 5:
        if (call_seq == 0) {
            if (message->rhandle != NULL)
                reply = -102;
            (void)wt_spm_host_set_rhandle(partition_id, handle,
                &rhandle_a);
        }
        else if (call_seq == 1) {
            if (message->rhandle != &rhandle_a)
                reply = -103;
            (void)wt_spm_host_set_rhandle(partition_id, handle,
                &rhandle_b);
        }
        else if (message->rhandle != &rhandle_b) {
            reply = -104;
        }
        call_seq++;
        break;
    case 6:
        values[0] = 0x22;
        values[1] = 0x33;
        (void)wt_spm_host_write(partition_id, handle, 0, &values[0], 1U);
        (void)wt_spm_host_read(partition_id, handle, 0, &values[2], 1U);
        (void)wt_spm_host_write(partition_id, handle, 1, &values[1], 1U);
        break;
    default:
        break;
    }
    return wt_spm_host_reply(partition_id, handle, reply);
}

/* Per-check server for Arm FF-M test i002 (connection lifecycle). Checks 2, 3,
 * and 5 accept every connection and call; later checks add per-message
 * behavior keyed on g_i002_check. */
static int dispatch_i002(int32_t partition_id,
                         const psa_msg_t* message)
{
    static const psa_status_t status_codes[] = {
        PSA_SUCCESS, 1, 2, INT32_MAX, -1, -2, INT32_MIN + 128
    };
    static int32_t id_at_connect;
    psa_handle_t handle;
    psa_status_t reply;

    handle = message->handle;
    reply = PSA_SUCCESS;
    switch (g_i002_check) {
    case 1:
        if (message->type == PSA_IPC_CONNECT) {
            reply = g_i002_connect_seq == 0 ? PSA_ERROR_CONNECTION_BUSY :
                                              PSA_ERROR_CONNECTION_REFUSED;
            g_i002_connect_seq++;
        }
        break;
    case 4:
        if (message->type >= PSA_IPC_CALL) {
            reply = status_codes[g_i002_call_seq %
                (int)(sizeof(status_codes) / sizeof(status_codes[0]))];
            g_i002_call_seq++;
        }
        break;
    case 6:
        if (message->type == PSA_IPC_CONNECT)
            id_at_connect = message->client_id;
        else if (message->type >= PSA_IPC_CALL) {
            (void)wt_spm_host_write(partition_id, handle, 0,
                &id_at_connect, sizeof(int32_t));
            (void)wt_spm_host_write(partition_id, handle, 1,
                &message->client_id, sizeof(int32_t));
        }
        break;
    case 8:
    case 9:
        /* Client-visible half of the block/poll checks: the service refuses
         * the connect. The server-side PSA_BLOCK vs PSA_POLL wait semantics
         * need a real scheduler (task #14) and are deferred to M33MU. */
        if (message->type == PSA_IPC_CONNECT)
            reply = PSA_ERROR_CONNECTION_REFUSED;
        break;
    default:
        /* Checks 2, 3, 5, 7 accept every connection and call; check 7 relies
         * on the runtime returning CONNECTION_BUSY when the pool is full. */
        break;
    }
    return wt_spm_host_reply(partition_id, handle, reply);
}

static int test_dispatch(void* context, wt_ffm_runtime_t* runtime,
                         int32_t partition_id)
{
    test_context_t* test = (test_context_t*)context;
    psa_signal_t asserted;
    psa_msg_t message;
    int32_t saved_partition;
    int rc;

    (void)runtime;
    saved_partition = test->partition;
    test->partition = partition_id;
    if (wt_spm_host_wait(partition_id, PSA_WAIT_ANY, &asserted) !=
            WT_FFM_SUCCESS ||
            wt_spm_host_get(partition_id, asserted, &message) !=
                PSA_SUCCESS) {
        test->partition = saved_partition;
        return WT_FFM_ERROR_STATE;
    }
    if (g_active_test == 2)
        rc = dispatch_i002(partition_id, &message);
    else if (g_active_test == 3)
        rc = dispatch_i003(partition_id, &message);
    else if (g_active_test == 27)
        /* i027: the RoT service drops the connection by replying
         * PROGRAMMER_ERROR to the call; connect/disconnect reply success. */
        rc = wt_spm_host_reply(partition_id, message.handle,
                message.type >= PSA_IPC_CALL ? PSA_ERROR_PROGRAMMER_ERROR :
                                               PSA_SUCCESS);
    else if (g_active_test == 63)
        /* i063: the RoT service refuses both connects (the client asserts
         * CONNECTION_REFUSED on each). Server-side signal-mask semantics
         * need a real multi-signal scheduler and ride the M33MU suite. */
        rc = wt_spm_host_reply(partition_id, message.handle,
                          PSA_ERROR_CONNECTION_REFUSED);
    else
        rc = wt_spm_host_reply(partition_id, message.handle,
                          PSA_SUCCESS);
    test->partition = saved_partition;
    return rc == WT_FFM_SUCCESS ? WT_FFM_SUCCESS : WT_FFM_ERROR_STATE;
}

static void test_panic(void* context, int32_t partition_id)
{
    test_context_t* test = (test_context_t*)context;

    (void)partition_id;
    test->failures++;
}

static psa_client_id_t test_current_client(void* context)
{
    return ((test_context_t*)context)->caller;
}

static int32_t test_current_partition(void* context)
{
    return ((test_context_t*)context)->partition;
}

static const wt_spm_host_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    test_dispatch,
    test_panic
};

static const wt_psa_host_identity_t g_identity_ops = {
    test_current_client,
    test_current_partition
};

static val_api_t g_val_api = {
    .print = test_print,
    .err_check_set = test_err_check,
    .ipc_connect = test_ipc_connect,
    .ipc_close = test_ipc_close,
    .set_boot_flag = test_set_boot_flag
};

static psa_api_t g_psa_api = {
    .framework_version = psa_framework_version,
    .version = psa_version,
    .connect = psa_connect,
    .call = psa_call,
    .close = psa_close
};

int main(void)
{
    int32_t status;

    (void)memset(&g_context, 0, sizeof(g_context));
    if (wt_spm_host_init(&g_manifest, &g_port_ops, &g_context) !=
            WT_FFM_SUCCESS ||
            wt_psa_host_bind(&g_identity_ops, &g_context) !=
                WT_FFM_SUCCESS) {
        return 1;
    }
    valtest_entry_i001 = &g_val_api;
    psatest_entry_i001 = &g_psa_api;
    valtest_entry_i002 = &g_val_api;
    psatest_entry_i002 = &g_psa_api;
    valtest_entry_i003 = &g_val_api;
    psatest_entry_i003 = &g_psa_api;
    valtest_entry_i004 = &g_val_api;
    psatest_entry_i004 = &g_psa_api;
    valtest_entry_i005 = &g_val_api;
    psatest_entry_i005 = &g_psa_api;
    valtest_entry_i006 = &g_val_api;
    psatest_entry_i006 = &g_psa_api;
    valtest_entry_i007 = &g_val_api;
    psatest_entry_i007 = &g_psa_api;
    valtest_entry_i008 = &g_val_api;
    psatest_entry_i008 = &g_psa_api;
    valtest_entry_i010 = &g_val_api;
    psatest_entry_i010 = &g_psa_api;
    valtest_entry_i011 = &g_val_api;
    psatest_entry_i011 = &g_psa_api;
    valtest_entry_i012 = &g_val_api;
    psatest_entry_i012 = &g_psa_api;
    valtest_entry_i024 = &g_val_api;
    psatest_entry_i024 = &g_psa_api;
    valtest_entry_i025 = &g_val_api;
    psatest_entry_i025 = &g_psa_api;
    valtest_entry_i026 = &g_val_api;
    psatest_entry_i026 = &g_psa_api;
    valtest_entry_i027 = &g_val_api;
    psatest_entry_i027 = &g_psa_api;
    valtest_entry_i063 = &g_val_api;
    psatest_entry_i063 = &g_psa_api;
    valtest_entry_i067 = &g_val_api;
    psatest_entry_i067 = &g_psa_api;
    valtest_entry_i071 = &g_val_api;
    psatest_entry_i071 = &g_psa_api;
    valtest_entry_i088 = &g_val_api;
    psatest_entry_i088 = &g_psa_api;
    valtest_entry_i090 = &g_val_api;
    psatest_entry_i090 = &g_psa_api;

    g_context.caller = TEST_NS_CLIENT;
    status = client_test_psa_framework_version(CALLER_NONSECURE);
    status = report("i001", "psa_framework_version (NS)", status);
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_version(CALLER_NONSECURE);
        status = report("i001", "psa_version (NS)", status);
    }
    if (status != VAL_STATUS_SUCCESS)
        return 1;
    status = client_test_sid_does_not_exists(CALLER_NONSECURE);
    status = report("i004", "sid_does_not_exists", status);
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_strict_policy_higher_version(CALLER_NONSECURE);
        status = report("i005", "strict_policy_higher_version", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_strict_policy_lower_version(CALLER_NONSECURE);
        status = report("i006", "strict_policy_lower_version", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_relax_policy_higher_version(CALLER_NONSECURE);
        status = report("i007", "relax_policy_higher_version", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_secure_access_only_connection(CALLER_NONSECURE);
        status = report("i008", "secure_access_only_connection (NS)",
                        status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_unspecified_policy_with_higher_version(
            CALLER_NONSECURE);
        status = report("i010", "unspecified_policy_higher_version", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_unspecified_policy_with_lower_version(
            CALLER_NONSECURE);
        status = report("i011", "unspecified_policy_lower_version", status);
    }
    if (status != VAL_STATUS_SUCCESS)
        return 1;
    status = client_test_psa_close_with_invalid_handle(CALLER_NONSECURE);
    status = report("i012", "psa_close_with_invalid_handle", status);
    /* NS psa_close(invalid) is spec-permitted to panic; that expected
     * panic must not fail the aggregate g_context.failures check below. */
    g_context.failures = 0U;
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_call_with_invalid_handle(CALLER_NONSECURE);
        status = report("i024", "psa_call_with_invalid_handle", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_call_with_null_handle(CALLER_NONSECURE);
        status = report("i025", "psa_call_with_null_handle", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_call_with_iovec_more_than_max_limit(
            CALLER_NONSECURE);
        status = report("i026", "psa_call_with_iovec_more_than_max_limit",
                        status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_call_with_neg_type(CALLER_NONSECURE);
        status = report("i090", "psa_call_with_neg_type", status);
    }
    g_active_test = 2;
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 1;
        g_i002_connect_seq = 0;
        status = client_test_connection_busy_and_reject(CALLER_NONSECURE);
        status = report("i002", "connection_busy_and_reject", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 2;
        status = client_test_accept_and_close_connect(CALLER_NONSECURE);
        status = report("i002", "accept_and_close_connect", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 3;
        status = client_test_connect_with_allowed_version_policy(
            CALLER_NONSECURE);
        status = report("i002", "connect_with_allowed_version_policy",
                        status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 5;
        status = client_test_psa_call_with_allowed_type_values(
            CALLER_NONSECURE);
        status = report("i002", "psa_call_with_allowed_type_values", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 4;
        g_i002_call_seq = 0;
        status = client_test_psa_call_with_allowed_status_code(
            CALLER_NONSECURE);
        status = report("i002", "psa_call_with_allowed_status_code", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 6;
        status = client_test_identity(CALLER_NONSECURE);
        status = report("i002", "identity", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 7;
        status = client_test_spm_concurrent_connect_limit(CALLER_NONSECURE);
        status = report("i002", "spm_concurrent_connect_limit", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 8;
        status = client_test_psa_block_behave(CALLER_NONSECURE);
        status = report("i002", "psa_block_behave", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i002_check = 9;
        status = client_test_psa_poll_behave(CALLER_NONSECURE);
        status = report("i002", "psa_poll_behave", status);
    }
    g_active_test = 3;
    if (status == VAL_STATUS_SUCCESS) {
        g_i003_check = 1;
        status = client_test_zero_length_invec(CALLER_NONSECURE);
        status = report("i003", "zero_length_invec", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i003_check = 2;
        status = client_test_zero_length_outvec(CALLER_NONSECURE);
        status = report("i003", "zero_length_outvec", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i003_check = 3;
        status = client_test_call_read_and_skip(CALLER_NONSECURE);
        status = report("i003", "call_read_and_skip", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i003_check = 4;
        status = client_test_call_and_write(CALLER_NONSECURE);
        status = report("i003", "call_and_write", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i003_check = 5;
        status = client_test_psa_set_rhandle(CALLER_NONSECURE);
        status = report("i003", "psa_set_rhandle", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        g_i003_check = 6;
        status = client_test_overlapping_vectors(CALLER_NONSECURE);
        status = report("i003", "overlapping_vectors", status);
    }
    g_active_test = 27;
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_drop_connection(CALLER_NONSECURE);
        status = report("i027", "psa_drop_connection", status);
    }
    g_active_test = 63;
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_wait_signal_mask(CALLER_NONSECURE);
        status = report("i063", "psa_wait_signal_mask", status);
    }
    g_active_test = 0;
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_dynamic_mem_alloc_fn(CALLER_NONSECURE);
        status = report("i067", "dynamic_mem_alloc_fn", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_mem_manipulation_fn(CALLER_NONSECURE);
        status = report("i071", "mem_manipulation_fn", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_rot_lifecycle_state(CALLER_NONSECURE);
        status = report("i088", "psa_rot_lifecycle_state", status);
    }
    if (status != VAL_STATUS_SUCCESS)
        return 1;

    g_context.caller = TEST_CLIENT_PARTITION;
    g_context.partition = TEST_CLIENT_PARTITION;
    status = client_test_psa_framework_version(CALLER_SECURE);
    status = report("i001", "psa_framework_version (secure)", status);
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_psa_version(CALLER_SECURE);
        status = report("i001", "psa_version (secure)", status);
    }
    if (status == VAL_STATUS_SUCCESS) {
        status = client_test_secure_access_only_connection(CALLER_SECURE);
        status = report("i008", "secure_access_only_connection (secure)",
                        status);
    }
    wt_psa_host_unbind();
    if (status != VAL_STATUS_SUCCESS || g_context.failures != 0U)
        return 1;

    (void)printf("PASS: Arm PSA FF i001-i008, i010, i011, i012, "
                "i024, i025, i026, i027, i063, i067, i071, i088, i090 "
                "on wolfTrust\n");
    return 0;
}
