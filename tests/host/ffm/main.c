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

#include "wolftrust/ffm.h"

#include <stdio.h>
#include <string.h>

#define TEST_SERVICE_SID       0x1000U
#define TEST_STRICT_SID        0x1001U
#define TEST_UNSPEC_SID        0x1002U
#define TEST_SERVICE_SIGNAL    0x10U
#define TEST_STRICT_SIGNAL     0x20U
#define TEST_UNSPEC_SIGNAL     0x40U
#define TEST_NONINTR_SIGNAL    0x80U
#define TEST_IRQ_SIGNAL        0x100U
#define TEST_PARTITION_ID      1
#define TEST_CLIENT_PARTITION  2
#define TEST_NS_CLIENT         (-1)
#define TEST_OTHER_NS_CLIENT   (-2)
#define TEST_RHANDLE           ((void*)(uintptr_t)0xA5A5U)

typedef struct test_context {
    unsigned int dispatches;
    unsigned int read_checks;
    unsigned int write_checks;
    unsigned int deny_write_check;
    unsigned int panics;
    int reject_write;
    int reply_programmer_error;
    int refuse_dispatch;
    psa_msg_t delayed_message;
    int delay_result;
} test_context_t;

static unsigned int g_checks;
static unsigned int g_failures;

#define EXPECT_INT(actual, expected) \
    do { \
        int actual_value = (int)(actual); \
        int expected_value = (int)(expected); \
        g_checks++; \
        if (actual_value != expected_value) { \
            (void)fprintf(stderr, \
                "line %d: expected %d, received %d\n", __LINE__, \
                expected_value, actual_value); \
            g_failures++; \
        } \
    } while (0)

#define EXPECT_SIZE(actual, expected) \
    do { \
        size_t actual_value = (actual); \
        size_t expected_value = (expected); \
        g_checks++; \
        if (actual_value != expected_value) { \
            (void)fprintf(stderr, \
                "line %d: expected %zu, received %zu\n", __LINE__, \
                expected_value, actual_value); \
            g_failures++; \
        } \
    } while (0)

#define EXPECT_TRUE(condition) \
    do { \
        g_checks++; \
        if (!(condition)) { \
            (void)fprintf(stderr, "line %d: condition failed\n", __LINE__); \
            g_failures++; \
        } \
    } while (0)

static const wt_service_descriptor_t g_services[] = {
    {
        "test_service", TEST_SERVICE_SID, 3U,
        WT_SERVICE_VERSION_RELAXED, TEST_SERVICE_SIGNAL, 0U, 1U, 1U
    },
    {
        "strict_service", TEST_STRICT_SID, 2U,
        WT_SERVICE_VERSION_STRICT, TEST_STRICT_SIGNAL, 0U, 1U, 1U
    },
    {
        "unspec_service", TEST_UNSPEC_SID, 2U,
        WT_SERVICE_VERSION_UNSPECIFIED, TEST_UNSPEC_SIGNAL, 0U, 1U, 1U
    }
};

static const uint32_t g_client_dependencies[] = {
    TEST_SERVICE_SID,
    TEST_STRICT_SID
};

static const wt_manifest_interrupt_t g_interrupts[] = {
    { "TEST_IRQ", 42U, TEST_IRQ_SIGNAL }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "test_partition", TEST_PARTITION_ID, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, g_interrupts,
        sizeof(g_interrupts) / sizeof(g_interrupts[0])
    },
    {
        "client_partition", TEST_CLIENT_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        NULL, 0U, g_client_dependencies,
        sizeof(g_client_dependencies) / sizeof(g_client_dependencies[0]),
        NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "host-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static const wt_partition_manifest_t g_partitions_v10[] = {
    {
        "v10_partition", TEST_PARTITION_ID, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest_v10 = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "host-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions_v10,
    .partition_count = sizeof(g_partitions_v10) / sizeof(g_partitions_v10[0])
};

static int test_check_read(void* context, psa_client_id_t caller,
                           const void* address, size_t size)
{
    test_context_t* test = (test_context_t*)context;

    (void)caller;
    test->read_checks++;
    return size == 0U || address != NULL;
}

static int test_check_write(void* context, psa_client_id_t caller,
                            void* address, size_t size)
{
    test_context_t* test = (test_context_t*)context;

    (void)caller;
    test->write_checks++;
    if (test->reject_write != 0 &&
            test->write_checks == test->deny_write_check) {
        return 0;
    }
    return size == 0U || address != NULL;
}

static int test_dispatch(void* context, wt_ffm_runtime_t* runtime,
                         int32_t partition_id)
{
    static const uint8_t response[] = { 'O', 'K' };
    test_context_t* test = (test_context_t*)context;
    psa_signal_t asserted = 0U;
    psa_msg_t message;
    uint8_t input[3];
    size_t length;

    test->dispatches++;
    if (test->refuse_dispatch) {
        /* A masked or busy partition leaves the message queued. */
        return WT_FFM_ERROR_NOT_READY;
    }
    EXPECT_INT(partition_id, TEST_PARTITION_ID);
    EXPECT_INT(wt_ffm_wait(runtime, partition_id, PSA_WAIT_ANY, &asserted),
               WT_FFM_SUCCESS);
    EXPECT_TRUE(asserted == TEST_SERVICE_SIGNAL ||
                asserted == TEST_STRICT_SIGNAL ||
                asserted == TEST_UNSPEC_SIGNAL);
    EXPECT_INT(wt_ffm_get(runtime, partition_id, asserted, &message),
               PSA_SUCCESS);

    if (message.type == PSA_IPC_CONNECT) {
        EXPECT_INT(wt_ffm_set_rhandle(runtime, partition_id, message.handle,
                                      TEST_RHANDLE), WT_FFM_SUCCESS);
        EXPECT_INT(wt_ffm_reply(runtime, partition_id, message.handle,
                                PSA_SUCCESS), WT_FFM_SUCCESS);
    }
    else if (message.type == PSA_IPC_DISCONNECT) {
        EXPECT_TRUE(message.rhandle == TEST_RHANDLE);
        /* FF-M: set_rhandle during disconnect succeeds with no observable
         * effect (i003 checkpoint 206 panics the server otherwise). */
        EXPECT_INT(wt_ffm_set_rhandle(runtime, partition_id, message.handle,
                                      NULL), WT_FFM_SUCCESS);
        EXPECT_INT(wt_ffm_reply(runtime, partition_id, message.handle,
                                PSA_SUCCESS), WT_FFM_SUCCESS);
    }
    else if (test->reply_programmer_error) {
        EXPECT_INT(wt_ffm_reply(runtime, partition_id, message.handle,
                                PSA_ERROR_PROGRAMMER_ERROR), WT_FFM_SUCCESS);
    }
    else {
        EXPECT_TRUE(message.rhandle == TEST_RHANDLE);
        EXPECT_SIZE(message.in_size[0], 3U);
        EXPECT_SIZE(message.out_size[0], 2U);
        length = wt_ffm_read(runtime, partition_id, message.handle, 0U,
                             input, 1U);
        EXPECT_SIZE(length, 1U);
        EXPECT_INT(input[0], 'a');
        EXPECT_SIZE(wt_ffm_skip(runtime, partition_id, message.handle, 0U,
                                1U), 1U);
        EXPECT_SIZE(wt_ffm_read(runtime, partition_id, message.handle, 0U,
                                &input[1], 2U), 1U);
        EXPECT_INT(input[1], 'c');
        EXPECT_INT(wt_ffm_write(runtime, partition_id, message.handle, 0U,
                                response, sizeof(response)), WT_FFM_SUCCESS);
        EXPECT_INT(wt_ffm_write(runtime, partition_id, message.handle, 0U,
                                response, 1U), WT_FFM_ERROR_BUFFER);
        /* FF-M: a connection-only status (REFUSED/BUSY) on a request reply is a
         * server PROGRAMMER ERROR the SPM rejects; the message stays active so
         * the real reply below still completes it. */
        EXPECT_INT(wt_ffm_reply(runtime, partition_id, message.handle,
                                PSA_ERROR_CONNECTION_REFUSED),
                   WT_FFM_ERROR_ARGUMENT);
        EXPECT_INT(wt_ffm_reply(runtime, partition_id, message.handle,
                                PSA_SUCCESS), WT_FFM_SUCCESS);
        EXPECT_SIZE(wt_ffm_read(runtime, partition_id, message.handle, 0U,
                                input, sizeof(input)), 0U);
    }

    return WT_FFM_SUCCESS;
}

static void test_panic(void* context, int32_t partition_id)
{
    test_context_t* test = (test_context_t*)context;

    (void)partition_id;
    test->panics++;
}

static const wt_ffm_port_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    test_dispatch,
    test_panic
};

static void test_init(wt_ffm_runtime_t* runtime, test_context_t* context)
{
    (void)memset(context, 0, sizeof(*context));
    EXPECT_INT(wt_ffm_init(runtime, &g_manifest, &g_port_ops, context),
               WT_FFM_SUCCESS);
}

static const wt_partition_manifest_t g_v11_partitions[] = {
    {
        "v11_partition", TEST_PARTITION_ID, WT_FFM_VERSION_1_1,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_v11_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "host-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_v11_partitions,
    .partition_count = sizeof(g_v11_partitions) / sizeof(g_v11_partitions[0])
};

static void test_framework_and_policy(void)
{
    wt_ffm_runtime_t runtime;
    wt_ffm_runtime_t runtime_v10;
    wt_ffm_runtime_t runtime_v11;
    test_context_t context;
    psa_handle_t handle;

    test_init(&runtime, &context);
    /* Discovery reports the compiled public contract (PSA_FRAMEWORK_VERSION,
     * 1.0) and a NULL runtime reports 0. A partition declaring a framework
     * newer than that contract must fail activation outright: the build
     * cannot honor its ABI, so it never reaches a clamped report. */
    EXPECT_INT(wt_ffm_framework_version(&runtime), PSA_FRAMEWORK_VERSION);
    EXPECT_INT(wt_ffm_init(&runtime_v10, &g_manifest_v10, &g_port_ops,
                           &context), WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_framework_version(&runtime_v10), WT_FFM_VERSION_1_0);
    EXPECT_INT(wt_ffm_framework_version(NULL), 0U);
    EXPECT_INT(wt_ffm_init(&runtime_v11, &g_v11_manifest, &g_port_ops,
                           &context), WT_FFM_ERROR_MANIFEST);
    EXPECT_INT(wt_ffm_service_version(&runtime, TEST_NS_CLIENT,
                                      TEST_SERVICE_SID), 3U);
    EXPECT_INT(wt_ffm_service_version(&runtime, TEST_CLIENT_PARTITION,
                                      TEST_SERVICE_SID), 3U);
    EXPECT_INT(wt_ffm_service_version(&runtime, TEST_PARTITION_ID,
                                      TEST_SERVICE_SID), PSA_VERSION_NONE);
    EXPECT_INT(wt_ffm_service_version(&runtime, TEST_NS_CLIENT, 0xFFFFU),
               PSA_VERSION_NONE);

    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 2U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 4U),
               PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT(wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_STRICT_SID, 1U),
               PSA_ERROR_CONNECTION_REFUSED);
    /* UNSPECIFIED accepts any nonzero version, including one that both STRICT
     * and RELAXED would refuse (5 > the service's own version of 2). */
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_UNSPEC_SID, 5U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_UNSPEC_SID, 0U),
               PSA_ERROR_CONNECTION_REFUSED);
    handle = wt_ffm_connect(&runtime, TEST_CLIENT_PARTITION,
                            TEST_STRICT_SID, 2U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_close(&runtime, TEST_CLIENT_PARTITION, handle),
               WT_FFM_SUCCESS);
    (void)printf("PASS: WT-FFM-0020 framework and policy\n");
}

static void test_connection_and_vectors(void)
{
    static const uint8_t request[] = { 'a', 'b', 'c' };
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_invec input = { request, sizeof(request) };
    uint8_t response[2] = { 0U, 0U };
    psa_outvec output = { response, sizeof(response) };
    psa_handle_t handle;

    test_init(&runtime, &context);
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    /* A handle is valid only for its creating caller; another caller using it
     * is invalid-handle use, a PROGRAMMER ERROR (FF-M 4.4.3). */
    EXPECT_INT(wt_ffm_call(&runtime, TEST_OTHER_NS_CLIENT, handle,
                           PSA_IPC_CALL, &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle,
                           PSA_IPC_CALL, &input, 1U, &output, 1U),
               PSA_SUCCESS);
    EXPECT_SIZE(output.len, 2U);
    EXPECT_TRUE(memcmp(response, "OK", 2U) == 0);
    EXPECT_INT(context.read_checks, 1U);
    EXPECT_INT(context.write_checks, 2U);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle,
                           PSA_IPC_CALL, &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT,
                           (psa_handle_t)(handle + 0x80), PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    (void)printf("PASS: WT-FFM-0021 connection, messages, and vectors\n");
}

static void test_connection_drop(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_handle_t handle;

    test_init(&runtime, &context);
    context.reply_programmer_error = 1;
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           NULL, 0U, NULL, 0U), PSA_ERROR_PROGRAMMER_ERROR);
    /* The dropped connection is still closable, and a later call on the
     * released handle returns PROGRAMMER_ERROR. */
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           NULL, 0U, NULL, 0U), PSA_ERROR_PROGRAMMER_ERROR);
    (void)printf("PASS: WT-FFM-0022 dropped connection close\n");
}

static void test_vector_rejection(void)
{
    uint8_t input_bytes[WT_FFM_TRANSFER_BYTES + 1U];
    uint8_t output_bytes[2];
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_invec inputs[PSA_MAX_IOVEC + 1U];
    psa_outvec output = { output_bytes, sizeof(output_bytes) };
    psa_handle_t handle;
    size_t i;

    test_init(&runtime, &context);
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    for (i = 0U; i < PSA_MAX_IOVEC + 1U; i++) {
        inputs[i].base = input_bytes;
        inputs[i].len = 1U;
    }
    inputs[0].len = sizeof(input_bytes);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           inputs, 1U, &output, 1U),
               PSA_ERROR_INVALID_ARGUMENT);
    /* The size error leaves the connection usable; the over-count below is a
     * PROGRAMMER ERROR that drops it, so it runs after the size case. */
    inputs[0].len = 1U;
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           inputs, PSA_MAX_IOVEC + 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    /* An unreadable base is an FF-M PROGRAMMER ERROR (memory reference),
     * not a size error. */
    inputs[0].base = NULL;
    inputs[0].len = 1U;
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           inputs, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    /* Containment outranks the transfer cap: a vector whose range escapes
     * the caller's memory must not downgrade into a size error even when it
     * also exceeds the cap (i052/i053). */
    inputs[0].base = NULL;
    inputs[0].len = (size_t)WT_FFM_TRANSFER_BYTES * 2U;
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           inputs, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
               WT_FFM_SUCCESS);
    (void)printf("PASS: WT-FFM-0032 bounded vector rejection\n");
}

static void test_output_revalidation(void)
{
    static const uint8_t request[] = { 'a', 'b', 'c' };
    uint8_t response[2] = { 0x5AU, 0x5AU };
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_invec input = { request, sizeof(request) };
    psa_outvec output = { response, sizeof(response) };
    psa_handle_t handle;

    test_init(&runtime, &context);
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    context.reject_write = 1;
    context.deny_write_check = 2U;
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(response[0], 0x5A);
    EXPECT_INT(response[1], 0x5A);
    EXPECT_INT(context.write_checks, 2U);
    (void)printf("PASS: WT-FFM-0033 output revalidation\n");
}

static void test_bounded_resources(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_handle_t handles[WT_FFM_MAX_CONNECTIONS];
    size_t i;
    size_t j;

    test_init(&runtime, &context);
    /* One client may hold up to its quota, then is refused: it cannot reserve
     * the whole shared pool (WT-FFM-0035, CWE-400). */
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS_PER_CLIENT; i++) {
        handles[i] = wt_ffm_connect(&runtime, TEST_NS_CLIENT,
                                    TEST_SERVICE_SID, 3U);
        EXPECT_TRUE(PSA_HANDLE_IS_VALID(handles[i]));
    }
    EXPECT_INT(wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U),
               PSA_ERROR_CONNECTION_BUSY);
    /* A peer is not starved: it can still reach its own quota from the
     * remainder the first client could not take. */
    for (i = WT_FFM_MAX_CONNECTIONS_PER_CLIENT;
            i < WT_FFM_MAX_CONNECTIONS; i++) {
        handles[i] = wt_ffm_connect(&runtime, TEST_OTHER_NS_CLIENT,
                                    TEST_SERVICE_SID, 3U);
        EXPECT_TRUE(PSA_HANDLE_IS_VALID(handles[i]));
    }
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        EXPECT_INT(wt_ffm_close(&runtime,
                       (i < WT_FFM_MAX_CONNECTIONS_PER_CLIENT) ?
                           TEST_NS_CLIENT : TEST_OTHER_NS_CLIENT,
                       handles[i]), WT_FFM_SUCCESS);
    }
    for (i = 0U; i < WT_FFM_MAX_MESSAGES; i++) {
        EXPECT_INT(runtime.messages[i].allocated, 0U);
        for (j = 0U; j < WT_FFM_TRANSFER_BYTES; j++) {
            EXPECT_INT(runtime.messages[i].input[j], 0U);
            EXPECT_INT(runtime.messages[i].output[j], 0U);
        }
    }
    EXPECT_INT(context.panics, 0U);
    (void)printf("PASS: WT-FFM-0035 bounded pools and scrubbing\n");
}

static void test_arguments(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_signal_t signals;
    psa_handle_t handle;

    (void)memset(&context, 0, sizeof(context));
    EXPECT_INT(wt_ffm_init(NULL, &g_manifest, &g_port_ops, &context),
               WT_FFM_ERROR_ARGUMENT);
    EXPECT_INT(wt_ffm_init(&runtime, NULL, &g_port_ops, &context),
               WT_FFM_ERROR_ARGUMENT);
    test_init(&runtime, &context);
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, -1,
                           NULL, 0U, NULL, 0U), PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_wait(&runtime, TEST_PARTITION_ID, PSA_WAIT_ANY,
                           &signals), WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(wt_ffm_get(&runtime, TEST_PARTITION_ID, TEST_SERVICE_SIGNAL,
                          NULL), PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, PSA_NULL_HANDLE),
               WT_FFM_SUCCESS);
    (void)printf("PASS: WT-FFM-0036 invalid arguments and empty wait\n");
}

static void test_doorbell_signal(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_signal_t asserted;

    test_init(&runtime, &context);

    EXPECT_INT(wt_ffm_notify(&runtime, 99), WT_FFM_ERROR_POLICY);
    EXPECT_INT(wt_ffm_clear(&runtime, TEST_CLIENT_PARTITION),
               WT_FFM_ERROR_STATE);

    EXPECT_INT(wt_ffm_notify(&runtime, TEST_CLIENT_PARTITION),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_wait(&runtime, TEST_CLIENT_PARTITION, PSA_WAIT_ANY,
                           &asserted), WT_FFM_SUCCESS);
    EXPECT_INT(asserted, PSA_DOORBELL);
    EXPECT_INT(wt_ffm_wait(&runtime, TEST_PARTITION_ID, PSA_WAIT_ANY,
                           &asserted), WT_FFM_ERROR_NOT_READY);

    EXPECT_INT(wt_ffm_clear(&runtime, TEST_CLIENT_PARTITION),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_wait(&runtime, TEST_CLIENT_PARTITION, PSA_WAIT_ANY,
                           &asserted), WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(wt_ffm_clear(&runtime, TEST_CLIENT_PARTITION),
               WT_FFM_ERROR_STATE);

    (void)printf("PASS: WT-FFM-0027 doorbell notify and clear\n");
}

/* psa_wait must honor the signal mask: it returns only the asserted signals
 * that intersect the mask, and reports NOT_READY when the intersection is
 * empty even though other signals are asserted. This is the primitive the
 * scheduler relies on to keep a masked-out partition blocked. */
static void test_wait_signal_mask(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_signal_t asserted;

    test_init(&runtime, &context);

    EXPECT_INT(wt_ffm_notify(&runtime, TEST_CLIENT_PARTITION),
               WT_FFM_SUCCESS);

    /* Waiting on a signal the partition cannot be assigned is the i062
     * PROGRAMMER ERROR, not a poll miss. */
    asserted = 0xFFFFFFFFU;
    EXPECT_INT(wt_ffm_wait(&runtime, TEST_CLIENT_PARTITION,
                           TEST_SERVICE_SIGNAL, &asserted),
               WT_FFM_ERROR_ARGUMENT);

    /* A mixed mask with at least one assigned bit is valid (i062): the
     * unassigned bit is ignored and the asserted assigned signal returns. */
    asserted = 0U;
    EXPECT_INT(wt_ffm_wait(&runtime, TEST_CLIENT_PARTITION,
                           PSA_DOORBELL | TEST_SERVICE_SIGNAL, &asserted),
               WT_FFM_SUCCESS);
    EXPECT_INT(asserted, PSA_DOORBELL);

    EXPECT_INT(wt_ffm_wait(&runtime, TEST_CLIENT_PARTITION, PSA_DOORBELL,
                           &asserted), WT_FFM_SUCCESS);
    EXPECT_INT(asserted, PSA_DOORBELL);

    EXPECT_INT(wt_ffm_clear(&runtime, TEST_CLIENT_PARTITION), WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_wait(&runtime, TEST_CLIENT_PARTITION, PSA_WAIT_ANY,
                           &asserted), WT_FFM_ERROR_NOT_READY);

    (void)printf("PASS: WT-FFM-0027 psa_wait signal-mask filtering\n");
}

static unsigned int g_registry_dispatches;

/* A registered service loop for TEST_PARTITION_ID: completes connect and
 * disconnect messages so the manifest-bound partition table, not the port
 * dispatch op, drives the message (WT-FFM-0014). */
static int registry_dispatch(void* context, wt_ffm_runtime_t* runtime,
                             int32_t partition_id)
{
    psa_signal_t asserted = 0U;
    psa_msg_t message;

    (void)context;
    g_registry_dispatches++;
    if (wt_ffm_wait(runtime, partition_id, PSA_WAIT_ANY, &asserted) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (wt_ffm_get(runtime, partition_id, asserted, &message) != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (message.type == PSA_IPC_CONNECT) {
        (void)wt_ffm_set_rhandle(runtime, partition_id, message.handle,
                                 TEST_RHANDLE);
    }
    if (wt_ffm_reply(runtime, partition_id, message.handle, PSA_SUCCESS) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static void test_partition_dispatch_registry(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_handle_t handle;

    test_init(&runtime, &context);
    g_registry_dispatches = 0U;

    EXPECT_INT(wt_ffm_register_partition(NULL, TEST_PARTITION_ID,
                                         registry_dispatch, NULL),
               WT_FFM_ERROR_ARGUMENT);
    EXPECT_INT(wt_ffm_register_partition(&runtime, TEST_PARTITION_ID,
                                         NULL, NULL), WT_FFM_ERROR_ARGUMENT);
    EXPECT_INT(wt_ffm_register_partition(&runtime, 0x7FFF,
                                         registry_dispatch, NULL),
               WT_FFM_ERROR_POLICY);

    EXPECT_INT(wt_ffm_register_partition(&runtime, TEST_PARTITION_ID,
                                         registry_dispatch, NULL),
               WT_FFM_SUCCESS);
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 2U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    /* The registered loop ran and the generic port op did not. */
    EXPECT_INT(g_registry_dispatches, 1);
    EXPECT_INT(context.dispatches, 0);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);
    EXPECT_INT(g_registry_dispatches, 2);
    EXPECT_INT(context.dispatches, 0);
    EXPECT_INT(context.panics, 0);

    (void)printf("PASS: WT-FFM-0014 partition dispatch routing\n");
}

static void test_eoi_signal(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;

    (void)memset(&context, 0, sizeof(context));
    test_init(&runtime, &context);

    /* More than one asserted bit is a programmer error. */
    EXPECT_INT(wt_ffm_eoi(&runtime, TEST_PARTITION_ID,
                          TEST_IRQ_SIGNAL | TEST_NONINTR_SIGNAL),
               WT_FFM_ERROR_ARGUMENT);
    /* Zero bits likewise. */
    EXPECT_INT(wt_ffm_eoi(&runtime, TEST_PARTITION_ID, 0U),
               WT_FFM_ERROR_ARGUMENT);
    /* A single bit the partition never declared as an interrupt (i064). */
    EXPECT_INT(wt_ffm_eoi(&runtime, TEST_PARTITION_ID, TEST_NONINTR_SIGNAL),
               WT_FFM_ERROR_POLICY);
    /* The declared interrupt signal, but not currently asserted (i065). */
    EXPECT_INT(wt_ffm_eoi(&runtime, TEST_PARTITION_ID, TEST_IRQ_SIGNAL),
               WT_FFM_ERROR_STATE);
    /* A legal end-of-interrupt clears the asserted signal. The host stands in
     * for the FLIH that asserts it on real hardware (P6/i021). */
    runtime.partitions[0].asserted_signals |= TEST_IRQ_SIGNAL;
    EXPECT_INT(wt_ffm_eoi(&runtime, TEST_PARTITION_ID, TEST_IRQ_SIGNAL),
               WT_FFM_SUCCESS);
    EXPECT_INT(runtime.partitions[0].asserted_signals & TEST_IRQ_SIGNAL, 0);
    /* Cleared: a second eoi on it is again a programmer error. */
    EXPECT_INT(wt_ffm_eoi(&runtime, TEST_PARTITION_ID, TEST_IRQ_SIGNAL),
               WT_FFM_ERROR_STATE);

    (void)printf("PASS: psa_eoi argument validation\n");
}

static void test_irq_route_and_assert(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    uint32_t irq = 0U;
    int32_t partition_id = 0;
    psa_signal_t signal = 0U;

    (void)memset(&context, 0, sizeof(context));
    test_init(&runtime, &context);

    /* Signal-to-interrupt lookup honors only manifest-declared interrupts. */
    EXPECT_INT(wt_ffm_irq_lookup(&runtime, TEST_PARTITION_ID,
                                 TEST_IRQ_SIGNAL, &irq), WT_FFM_SUCCESS);
    EXPECT_INT(irq, 42);
    EXPECT_INT(wt_ffm_irq_lookup(&runtime, TEST_PARTITION_ID,
                                 TEST_NONINTR_SIGNAL, &irq),
               WT_FFM_ERROR_POLICY);
    EXPECT_INT(wt_ffm_irq_lookup(&runtime, TEST_PARTITION_ID,
                                 TEST_IRQ_SIGNAL | TEST_NONINTR_SIGNAL, &irq),
               WT_FFM_ERROR_ARGUMENT);

    /* Interrupt-to-partition routing: the FLIH resolves who owns the line. */
    EXPECT_INT(wt_ffm_irq_route(&runtime, 42U, &partition_id, &signal),
               WT_FFM_SUCCESS);
    EXPECT_INT(partition_id, TEST_PARTITION_ID);
    EXPECT_INT(signal, TEST_IRQ_SIGNAL);
    EXPECT_INT(wt_ffm_irq_route(&runtime, 99U, &partition_id, &signal),
               WT_FFM_ERROR_POLICY);

    /* Asserting the routed signal makes it visible to psa_wait and legal for
     * psa_eoi; non-interrupt signals cannot be asserted through this path. */
    EXPECT_INT(wt_ffm_assert_signal(&runtime, TEST_PARTITION_ID,
                                    TEST_NONINTR_SIGNAL),
               WT_FFM_ERROR_POLICY);
    EXPECT_INT(wt_ffm_assert_signal(&runtime, TEST_PARTITION_ID,
                                    TEST_IRQ_SIGNAL), WT_FFM_SUCCESS);
    EXPECT_INT(runtime.partitions[0].asserted_signals & TEST_IRQ_SIGNAL,
               (int)TEST_IRQ_SIGNAL);
    EXPECT_INT(wt_ffm_eoi(&runtime, TEST_PARTITION_ID, TEST_IRQ_SIGNAL),
               WT_FFM_SUCCESS);
    EXPECT_INT(runtime.partitions[0].asserted_signals & TEST_IRQ_SIGNAL, 0);

    (void)printf("PASS: interrupt signal routing and assertion\n");
}

/* WT-FFM-0017: a client pinned on a faulted partition unblocks with a defined
 * error instead of hanging. Enqueue a real request (never dispatched, standing
 * in for a partition that faults mid-service), then fail the partition's
 * messages and confirm the pinned request completes with the injected error,
 * the connection drops to ERROR, and unrelated partitions are untouched. */
static void test_fault_unblock(void)
{
    static const uint8_t request[] = { 'a', 'b', 'c' };
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_invec input = { request, sizeof(request) };
    uint8_t response[2] = { 0U, 0U };
    psa_outvec output = { response, sizeof(response) };
    psa_handle_t handle;
    uint16_t msg_index = 0U;

    test_init(&runtime, &context);
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));

    EXPECT_INT(wt_ffm_call_begin(&runtime, TEST_NS_CLIENT, handle,
                                 PSA_IPC_CALL, &input, 1U, &output, 1U,
                                 &msg_index), PSA_SUCCESS);
    EXPECT_INT(wt_ffm_msg_complete(&runtime, msg_index), 0);
    EXPECT_INT(runtime.partitions[0].asserted_signals & TEST_SERVICE_SIGNAL,
               (int)TEST_SERVICE_SIGNAL);

    /* Failing an unrelated partition leaves the pinned message alone. */
    EXPECT_INT(wt_ffm_fail_partition_messages(&runtime, TEST_CLIENT_PARTITION,
                                              PSA_ERROR_COMMUNICATION_FAILURE),
               0);
    EXPECT_INT(wt_ffm_msg_complete(&runtime, msg_index), 0);

    /* Failing the serving partition completes exactly the pinned message and
     * drains its queue: the service signal deasserts so a restarted partition
     * wakes for new work only, never for the corpse of this request. */
    EXPECT_INT(wt_ffm_fail_partition_messages(&runtime, TEST_PARTITION_ID,
                                              PSA_ERROR_COMMUNICATION_FAILURE),
               1);
    EXPECT_INT(wt_ffm_msg_complete(&runtime, msg_index), 1);
    EXPECT_INT(runtime.partitions[0].asserted_signals & TEST_SERVICE_SIGNAL,
               0);
    EXPECT_INT(wt_ffm_call_finish(&runtime, msg_index, &output, 1U),
               PSA_ERROR_COMMUNICATION_FAILURE);

    /* The connection is now unusable: a call on a connection dropped by an
     * abnormal completion is a PROGRAMMER ERROR until the client closes it
     * (FF-M 4.4.3), never a silently reopened or merely bad-state call. It
     * stays a PROGRAMMER ERROR on a repeat before close. */
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);

    EXPECT_INT(wt_ffm_fail_partition_messages(NULL, TEST_PARTITION_ID,
                                              PSA_ERROR_COMMUNICATION_FAILURE),
               0);
    (void)printf("PASS: WT-FFM-0017 pinned client unblock on partition fault\n");
}

/* Locate a client's allocated connection slot for white-box assertions. */
static int find_connection(const wt_ffm_runtime_t* runtime,
                           psa_client_id_t caller, size_t* out_index)
{
    size_t i;

    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        if (runtime->connections[i].allocated != 0U &&
                runtime->connections[i].caller == caller) {
            *out_index = i;
            return 1;
        }
    }
    return 0;
}

/* WT-FFM-0026: a connection that is IDLE when its serving partition faults is
 * referenced by no message row, so the message sweep never visits it. The
 * partition-fault cleanup must still drop it to the error state and clear its
 * reverse handle, or the restarted instance receives a pointer into the domain
 * that was just scrubbed and the client's next call is silently served. */
static void test_idle_connection_fault(void)
{
    static const uint8_t request[] = { 'a', 'b', 'c' };
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_invec input = { request, sizeof(request) };
    uint8_t response[2] = { 0U, 0U };
    psa_outvec output = { response, sizeof(response) };
    psa_handle_t handle;
    size_t idx = 0U;

    test_init(&runtime, &context);
    /* A successful connect leaves the connection IDLE with no message in
     * flight — exactly the row the message sweep cannot reach. */
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_TRUE(find_connection(&runtime, TEST_NS_CLIENT, &idx));
    EXPECT_INT(runtime.connections[idx].state, WT_IPC_CONNECTION_IDLE);
    /* Model the served instance having pinned a reverse handle before it died. */
    runtime.connections[idx].rhandle = (uintptr_t)TEST_RHANDLE;

    /* The serving partition faults with no message in flight. */
    EXPECT_INT(wt_ffm_fail_partition_messages(&runtime, TEST_PARTITION_ID,
                                              PSA_ERROR_COMMUNICATION_FAILURE),
               0);
    EXPECT_INT(runtime.connections[idx].state, WT_IPC_CONNECTION_ERROR);
    EXPECT_TRUE(runtime.connections[idx].rhandle == 0U);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    (void)printf("PASS: WT-FFM-0026 idle connection sweeps on serving fault\n");
}

/* WT-FFM-0026/0035: a client that terminates abnormally (a quarantined or
 * restarted guest) never closes its handles, so its connection slots must be
 * released outright — otherwise repeated faults exhaust the static pool and
 * every psa_connect on the system reports CONNECTION_BUSY forever. Peers keep
 * their connections; a request still in flight is force-completed first so a
 * later service reply cannot land in a reissued slot. */
static void test_client_connection_release(void)
{
    static const uint8_t request[] = { 'a', 'b', 'c' };
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_invec input = { request, sizeof(request) };
    uint8_t response[2] = { 0U, 0U };
    psa_outvec output = { response, sizeof(response) };
    psa_handle_t victim;
    psa_handle_t peer;
    psa_handle_t fresh;
    uint16_t msg_index = 0U;
    size_t idx = 0U;

    test_init(&runtime, &context);
    victim = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    peer = wt_ffm_connect(&runtime, TEST_OTHER_NS_CLIENT, TEST_SERVICE_SID,
                          3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(victim));
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(peer));

    /* Leave a request in flight on the victim's connection. */
    EXPECT_INT(wt_ffm_call_begin(&runtime, TEST_NS_CLIENT, victim,
                                 PSA_IPC_CALL, &input, 1U, &output, 1U,
                                 &msg_index), PSA_SUCCESS);

    EXPECT_TRUE(wt_ffm_fail_client_connections(&runtime, TEST_NS_CLIENT) >= 1);
    /* The victim's slot is gone, not merely errored: its handle no longer
     * resolves and the pool row is free for reuse. */
    EXPECT_TRUE(!find_connection(&runtime, TEST_NS_CLIENT, &idx));
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, victim, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);

    /* The peer is untouched and can still be used and reconnected against. */
    EXPECT_INT(wt_ffm_call(&runtime, TEST_OTHER_NS_CLIENT, peer, PSA_IPC_CALL,
                           &input, 1U, &output, 1U), PSA_SUCCESS);
    fresh = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(fresh));

    EXPECT_INT(wt_ffm_fail_client_connections(NULL, TEST_NS_CLIENT), 0);
    (void)printf("PASS: WT-FFM-0026 abnormal client release frees its slots\n");
}

/* FF-M Appendix A: a client PROGRAMMER ERROR against a connection latches it
 * into the error state even when the in-flight request later completes
 * normally, and it stays a PROGRAMMER ERROR until close. Also covers psa_write
 * to an OMITTED output vector: zero bytes succeed (zero-sized entry through
 * PSA_MAX_IOVEC), a payload exceeds its zero capacity. */
static void test_error_latch_and_omitted_write(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    uint8_t request[3] = { 'a', 'b', 'c' };
    psa_invec input = { request, sizeof(request) };
    uint8_t response[2] = { 0U, 0U };
    psa_outvec output = { response, sizeof(response) };
    psa_handle_t handle;
    uint16_t msg_index = 0U;
    psa_msg_t message;

    test_init(&runtime, &context);
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));

    EXPECT_INT(wt_ffm_call_begin(&runtime, TEST_NS_CLIENT, handle,
                                 PSA_IPC_CALL, &input, 1U, &output, 1U,
                                 &msg_index), PSA_SUCCESS);

    /* Client misuse while the request is in flight. */
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);

    /* The server completes the pinned request normally. */
    EXPECT_INT(wt_ffm_get(&runtime, TEST_PARTITION_ID, TEST_SERVICE_SIGNAL,
                          &message), PSA_SUCCESS);
    EXPECT_INT(wt_ffm_write(&runtime, TEST_PARTITION_ID, message.handle, 1U,
                            NULL, 0U), WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_write(&runtime, TEST_PARTITION_ID, message.handle, 1U,
                            response, 1U), WT_FFM_ERROR_BUFFER);
    EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID, message.handle,
                            PSA_SUCCESS), WT_FFM_SUCCESS);
    EXPECT_INT(wt_ffm_call_finish(&runtime, msg_index, &output, 1U),
               PSA_SUCCESS);

    /* The latched misuse survives the successful completion. */
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);
    (void)printf("PASS: WT-FFM-0022 client error latch and omitted-vector "
                 "write\n");
}

static void test_predispatch_error_drops_connection(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    uint8_t request[3] = { 'a', 'b', 'c' };
    psa_invec input = { request, sizeof(request) };
    uint8_t response[2] = { 0U, 0U };
    psa_outvec output = { response, sizeof(response) };
    psa_invec many_in[PSA_MAX_IOVEC + 1U];
    psa_handle_t handle;
    size_t i;

    test_init(&runtime, &context);

    /* A negative type on a valid idle connection drops it, so a later
     * well-formed call is refused until the client closes the handle. */
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, -5,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);

    /* A combined vector over-count drops the connection the same way. */
    for (i = 0U; i < PSA_MAX_IOVEC + 1U; i++) {
        many_in[i].base = request;
        many_in[i].len = sizeof(request);
    }
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           many_in, PSA_MAX_IOVEC + 1U, NULL, 0U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);

    /* The gateway refuse path drops a valid connection but ignores a forged
     * handle. */
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    wt_ffm_call_refuse(&runtime, TEST_NS_CLIENT, handle + 0x1000);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U), PSA_SUCCESS);
    wt_ffm_call_refuse(&runtime, TEST_NS_CLIENT, handle);
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);

    (void)printf("PASS: WT-FFM-0024 pre-dispatch programmer error drops the "
                 "connection\n");
}

/* WT-FFM-0014: a dispatch the partition refuses must unlink the queued
 * message before its slot is released, so the slot cannot alias the next
 * request and the service serves normally once the partition accepts. */
static void test_refused_dispatch_queue_consistency(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    uint8_t request[3] = { 'a', 'b', 'c' };
    psa_invec input = { request, sizeof(request) };
    uint8_t response[2] = { 0U, 0U };
    psa_outvec output = { response, sizeof(response) };
    psa_handle_t handle;

    test_init(&runtime, &context);

    /* A refused CONNECT dispatch must also leave no queued slot behind. */
    context.refuse_dispatch = 1;
    EXPECT_TRUE(!PSA_HANDLE_IS_VALID(
        wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U)));
    context.refuse_dispatch = 0;

    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));

    context.refuse_dispatch = 1;
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U),
               PSA_ERROR_GENERIC_ERROR);
    context.refuse_dispatch = 0;
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);

    /* A fresh connection on a fresh slot must serve cleanly: the refused
     * message left no stale queue reference behind. */
    handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID, 3U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           &input, 1U, &output, 1U), PSA_SUCCESS);
    EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);

    (void)printf("PASS: WT-FFM-0014 refused dispatch leaves the service "
                 "queue consistent\n");
}

static int delayed_dispatch(void* context, wt_ffm_runtime_t* runtime,
                             int32_t partition_id)
{
    test_context_t* test = (test_context_t*)context;

    test->dispatches++;
    EXPECT_INT(wt_ffm_get(runtime, partition_id, TEST_SERVICE_SIGNAL,
                          &test->delayed_message), PSA_SUCCESS);
    return test->delay_result;
}

static void expect_ffm_pools_empty(const wt_ffm_runtime_t* runtime)
{
    size_t i;

    for (i = 0U; i < WT_FFM_MAX_MESSAGES; i++)
        EXPECT_INT(runtime->messages[i].allocated, 0);
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++)
        EXPECT_INT(runtime->connections[i].allocated, 0);
}

static void test_delayed_synchronous_reply(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    wt_ffm_port_ops_t ops = g_port_ops;
    psa_handle_t handle;
    psa_handle_t message_handle;
    uint8_t request[3] = { 'a', 'b', 'c' };
    uint8_t copied[3];
    uint8_t response[2];
    psa_invec input = { request, sizeof(request) };
    psa_outvec output = { response, sizeof(response) };
    unsigned int mode;
    size_t i;

    for (mode = 0U; mode < 4U; mode++) {
        test_init(&runtime, &context);
        handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID,
                                 3U);
        EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
        context.delay_result = (mode & 1U) != 0U ?
            WT_FFM_ERROR_NOT_READY : WT_FFM_SUCCESS;
        if ((mode & 2U) != 0U) {
            EXPECT_INT(wt_ffm_register_partition(&runtime, TEST_PARTITION_ID,
                           delayed_dispatch, &context), WT_FFM_SUCCESS);
        }
        else {
            ops.dispatch = delayed_dispatch;
            runtime.ops = &ops;
        }
        (void)memset(response, 0, sizeof(response));
        EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle,
                       PSA_IPC_CALL, &input, 1U, &output, 1U),
                   PSA_ERROR_GENERIC_ERROR);
        message_handle = context.delayed_message.handle;
        if ((mode & 1U) != 0U) {
            EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
                       WT_FFM_SUCCESS);
            EXPECT_INT(runtime.services[0].queue_head, WT_FFM_QUEUE_NONE);
        }
        EXPECT_SIZE(wt_ffm_read(&runtime, TEST_PARTITION_ID, message_handle,
                                0U, copied, sizeof(copied)), sizeof(copied));
        EXPECT_TRUE(memcmp(copied, request, sizeof(copied)) == 0);
        EXPECT_INT(wt_ffm_write(&runtime, TEST_PARTITION_ID, message_handle,
                                0U, "OK", 2U), WT_FFM_SUCCESS);
        EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID, message_handle,
                                PSA_SUCCESS), WT_FFM_SUCCESS);
        EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID, message_handle,
                                PSA_SUCCESS), WT_FFM_ERROR_HANDLE);
        EXPECT_INT(response[0], 0);
        EXPECT_INT(response[1], 0);
        EXPECT_SIZE(output.len, sizeof(response));
        if ((mode & 1U) != 0U) {
            (void)delayed_dispatch(&context, &runtime, TEST_PARTITION_ID);
        }
        else {
            EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle,
                           PSA_IPC_CALL, &input, 1U, &output, 1U),
                       PSA_ERROR_PROGRAMMER_ERROR);
            EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
                       WT_FFM_ERROR_NOT_READY);
        }
        EXPECT_INT(context.delayed_message.type, PSA_IPC_DISCONNECT);
        EXPECT_TRUE(context.delayed_message.rhandle == TEST_RHANDLE);
        EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID,
                                context.delayed_message.handle, PSA_SUCCESS),
                   WT_FFM_SUCCESS);
        expect_ffm_pools_empty(&runtime);

        for (i = 0U; i < WT_FFM_MAX_CONNECTIONS + 1U; i++) {
            EXPECT_INT(wt_ffm_connect(&runtime, TEST_NS_CLIENT,
                           TEST_SERVICE_SID, 3U), PSA_ERROR_GENERIC_ERROR);
            message_handle = context.delayed_message.handle;
            EXPECT_INT(wt_ffm_set_rhandle(&runtime, TEST_PARTITION_ID,
                           message_handle, TEST_RHANDLE), WT_FFM_SUCCESS);
            EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID,
                           message_handle, PSA_SUCCESS), WT_FFM_SUCCESS);
            (void)delayed_dispatch(&context, &runtime, TEST_PARTITION_ID);
            EXPECT_INT(context.delayed_message.type, PSA_IPC_DISCONNECT);
            EXPECT_TRUE(context.delayed_message.rhandle == TEST_RHANDLE);
            EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID,
                           context.delayed_message.handle, PSA_SUCCESS),
                       WT_FFM_SUCCESS);
            expect_ffm_pools_empty(&runtime);
        }
        EXPECT_INT(wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_SERVICE_SID,
                                   3U), PSA_ERROR_GENERIC_ERROR);
        EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID,
                       context.delayed_message.handle,
                       PSA_ERROR_CONNECTION_REFUSED), WT_FFM_SUCCESS);
        expect_ffm_pools_empty(&runtime);
        EXPECT_INT(context.panics, 0);
    }
    (void)printf("PASS: WT-FFM-0023/0024/0026/0034 synchronous IPC retains "
                 "messages until delayed replies\n");
}

static void test_delayed_reply_fault_cleanup(void)
{
    wt_ffm_runtime_t runtime;
    test_context_t context;
    psa_handle_t handle = PSA_NULL_HANDLE;
    uint16_t pending;
    unsigned int mode;

    for (mode = 0U; mode < 5U; mode++) {
        test_init(&runtime, &context);
        if (mode >= 2U) {
            handle = wt_ffm_connect(&runtime, TEST_NS_CLIENT,
                                     TEST_SERVICE_SID, 3U);
            EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
        }
        EXPECT_INT(wt_ffm_register_partition(&runtime, TEST_PARTITION_ID,
                       delayed_dispatch, &context), WT_FFM_SUCCESS);
        if (mode < 2U) {
            EXPECT_INT(wt_ffm_connect(&runtime, TEST_NS_CLIENT,
                           TEST_SERVICE_SID, 3U), PSA_ERROR_GENERIC_ERROR);
            if (mode == 1U) {
                EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID,
                               context.delayed_message.handle, PSA_SUCCESS),
                           WT_FFM_SUCCESS);
            }
        }
        else if (mode < 4U) {
            EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle,
                           PSA_IPC_CALL, NULL, 0U, NULL, 0U),
                       PSA_ERROR_GENERIC_ERROR);
            if (mode == 3U) {
                EXPECT_INT(wt_ffm_close_begin(&runtime, TEST_NS_CLIENT,
                                              handle, &pending),
                           WT_FFM_SUCCESS);
                EXPECT_INT(pending, WT_FFM_QUEUE_NONE);
            }
        }
        else {
            EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
                       WT_FFM_ERROR_NOT_READY);
        }
        EXPECT_INT(wt_ffm_fail_partition_messages(&runtime, TEST_PARTITION_ID,
                       PSA_ERROR_COMMUNICATION_FAILURE), 1);
        EXPECT_INT(wt_ffm_fail_partition_messages(&runtime, TEST_PARTITION_ID,
                       PSA_ERROR_COMMUNICATION_FAILURE), 0);
        EXPECT_INT(runtime.services[0].queue_head, WT_FFM_QUEUE_NONE);
        EXPECT_INT(runtime.services[0].queue_tail, WT_FFM_QUEUE_NONE);
        EXPECT_INT(runtime.partitions[0].asserted_signals, 0);
        if (mode == 2U) {
            EXPECT_INT(wt_ffm_call(&runtime, TEST_NS_CLIENT, handle,
                           PSA_IPC_CALL, NULL, 0U, NULL, 0U),
                       PSA_ERROR_PROGRAMMER_ERROR);
            EXPECT_INT(wt_ffm_close(&runtime, TEST_NS_CLIENT, handle),
                       WT_FFM_ERROR_NOT_READY);
            EXPECT_INT(wt_ffm_reply(&runtime, TEST_PARTITION_ID,
                           context.delayed_message.handle, PSA_SUCCESS),
                       WT_FFM_SUCCESS);
        }
        expect_ffm_pools_empty(&runtime);
    }
    (void)printf("PASS: WT-FFM-0017 delayed reply fault cleanup\n");
}

int main(void)
{
    test_arguments();
    test_error_latch_and_omitted_write();
    test_predispatch_error_drops_connection();
    test_refused_dispatch_queue_consistency();
    test_delayed_synchronous_reply();
    test_delayed_reply_fault_cleanup();
    test_doorbell_signal();
    test_eoi_signal();
    test_irq_route_and_assert();
    test_wait_signal_mask();
    test_framework_and_policy();
    test_connection_and_vectors();
    test_connection_drop();
    test_partition_dispatch_registry();
    test_vector_rejection();
    test_output_revalidation();
    test_bounded_resources();
    test_fault_unblock();
    test_idle_connection_fault();
    test_client_connection_release();
    if (g_failures != 0U) {
        (void)fprintf(stderr, "FF-M checks failed: %u/%u\n",
                      g_failures, g_checks);
        return 1;
    }
    (void)printf("PASS: FF-M runtime checks: %u\n", g_checks);
    return 0;
}
