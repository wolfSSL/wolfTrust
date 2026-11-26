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

/* WT-FFM-0014: every SP-side psa_* call funnels through the one privileged
 * gate wt_spm_gate. These tests prove the gate is a faithful drop-in for the
 * inline wt_ffm_* calls on the real dispatch path, that it classifies an empty
 * psa_wait as "suspend this partition", and that it rejects an SP-supplied
 * pointer outside the partition's protection domain before the SPM touches it.
 * The physical suspend/resume, SVC trap, and unprivileged execution the gate is
 * built for live on Armv8-M and are proven on M33MU (P1t-2). */

#include "spm_host.h"
#include "wolftrust/spm_gate.h"
#include "psa/lifecycle.h"

#include <stdio.h>
#include <string.h>

#define TEST_SERVICE_SID    0x1000U
#define TEST_SERVICE_SIGNAL 0x10U
#define TEST_NONINTR_SIGNAL 0x80U
#define TEST_IRQ_SIGNAL     0x100U
#define TEST_PARTITION_ID   1
#define TEST_NS_CLIENT      (-1)
#define TEST_RHANDLE        ((void*)(uintptr_t)0xA5A5U)

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
        "test_service", TEST_SERVICE_SID, 1U,
        WT_SERVICE_VERSION_RELAXED, TEST_SERVICE_SIGNAL, 0U, 1U, 1U
    }
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
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "host-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

/* The slot stands in for the message index; any value above 0 is valid. */
static psa_handle_t t_connect_begin(psa_client_id_t caller, uint32_t sid,
                                    uint32_t version, uint16_t* msg)
{
    int32_t slot = wt_spm_connect_begin(caller, sid, version);

    *msg = (uint16_t)slot;
    return slot < 0 ? (psa_handle_t)slot : (psa_handle_t)(slot + 1);
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

/* A Secure Partition server body, but every psa_* primitive routed through the
 * gate instead of calling wt_ffm_* directly. A green connect/call round trip
 * proves the gate is behaviorally identical to the inline path. */
static int gate_dispatch(void* context, wt_ffm_runtime_t* runtime,
                         int32_t partition_id)
{
    static const uint8_t response[] = { 'O', 'K' };
    psa_signal_t asserted = 0U;
    psa_msg_t message;
    wt_spm_call_t call;
    uint8_t input[3];

    (void)context;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = partition_id;
    call.signal_mask = PSA_WAIT_ANY;
    call.asserted = &asserted;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(wt_spm_call_would_block(&call), 0);
    EXPECT_INT(asserted, TEST_SERVICE_SIGNAL);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = partition_id;
    call.signal = asserted;
    call.msg = &message;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_status, PSA_SUCCESS);

    if (message.type == PSA_IPC_CONNECT) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_SET_RHANDLE;
        call.partition_id = partition_id;
        call.msg_handle = message.handle;
        call.rhandle = TEST_RHANDLE;
        EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
        EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    }
    else if (message.type != PSA_IPC_DISCONNECT) {
        EXPECT_TRUE(message.rhandle == TEST_RHANDLE);
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_READ;
        call.partition_id = partition_id;
        call.msg_handle = message.handle;
        call.vec_idx = 0U;
        call.buffer = input;
        call.num_bytes = sizeof(input);
        EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
        EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
        EXPECT_SIZE(call.ret_size, 3U);
        EXPECT_INT(input[0], 'a');

        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_WRITE;
        call.partition_id = partition_id;
        call.msg_handle = message.handle;
        call.vec_idx = 0U;
        call.buffer = (void*)(uintptr_t)response;
        call.num_bytes = sizeof(response);
        EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
        EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    }

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = message.handle;
    call.status = PSA_SUCCESS;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);

    return WT_FFM_SUCCESS;
}

static void test_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
}

static const wt_spm_host_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    gate_dispatch,
    test_panic
};

static void test_gate_equivalence(void)
{
    static const uint8_t request[] = { 'a', 'b', 'c' };
    psa_invec in_vec[1];
    psa_outvec out_vec[1];
    uint8_t output[2];
    psa_handle_t handle;

    EXPECT_INT(wt_spm_host_init(&g_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_spm_host_bind(TEST_PARTITION_ID,
                                         gate_dispatch, NULL), WT_FFM_SUCCESS);

    handle = wt_spm_host_connect(TEST_NS_CLIENT, TEST_SERVICE_SID, 1U);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));

    in_vec[0].base = request;
    in_vec[0].len = sizeof(request);
    out_vec[0].base = output;
    out_vec[0].len = sizeof(output);
    (void)memset(output, 0, sizeof(output));
    EXPECT_INT(wt_spm_host_call(TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                           in_vec, 1U, out_vec, 1U), PSA_SUCCESS);
    EXPECT_INT(output[0], 'O');
    EXPECT_INT(output[1], 'K');

    EXPECT_INT(wt_spm_host_close(TEST_NS_CLIENT, handle), WT_FFM_SUCCESS);
    (void)printf("PASS: WT-FFM-0014 gate routes the SP dispatch path\n");
}

static void test_gate_would_block(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    psa_signal_t asserted = 0U;
    wt_spm_call_t call;

    EXPECT_INT(wt_spm_host_init(&g_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = PSA_DOORBELL;
    call.timeout = PSA_BLOCK;
    call.asserted = &asserted;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(wt_spm_call_would_block(&call), 1);

    /* PSA_POLL on the same unasserted signal must return, never block. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = PSA_DOORBELL;
    call.timeout = PSA_POLL;
    call.asserted = &asserted;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(wt_spm_call_would_block(&call), 0);

    EXPECT_INT(wt_spm_notify(TEST_PARTITION_ID), WT_FFM_SUCCESS);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = PSA_DOORBELL;
    call.timeout = PSA_BLOCK;
    call.asserted = &asserted;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(wt_spm_call_would_block(&call), 0);
    EXPECT_INT(asserted, PSA_DOORBELL);

    /* Doorbell asserted but masked out: a blocking wait must stay blocking,
     * not spuriously wake the partition on an unrequested signal. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_SERVICE_SIGNAL;
    call.timeout = PSA_BLOCK;
    call.asserted = &asserted;
    asserted = 0xFFFFFFFFU;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(wt_spm_call_would_block(&call), 1);
    EXPECT_INT(asserted, 0);
    (void)printf("PASS: WT-FFM-0014 gate blocks PSA_BLOCK waits, polls return\n");
}

/* i058 Check 1 through the gate: a notified doorbell stays asserted across a
 * second psa_wait and only psa_clear drops it (WT-FFM-0027). */
static void test_gate_doorbell_state_machine(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    psa_signal_t asserted = 0U;
    wt_spm_call_t call;

    EXPECT_INT(wt_spm_host_init(&g_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_NOTIFY;
    call.partition_id = TEST_PARTITION_ID;
    call.notify_partition = TEST_PARTITION_ID;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = PSA_DOORBELL;
    call.timeout = PSA_BLOCK;
    call.asserted = &asserted;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(wt_spm_call_would_block(&call), 0);
    EXPECT_INT(asserted, PSA_DOORBELL);

    /* Second wait: doorbell must remain asserted (psa_wait does not clear). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = PSA_DOORBELL;
    call.timeout = PSA_BLOCK;
    call.asserted = &asserted;
    asserted = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(asserted, PSA_DOORBELL);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CLEAR;
    call.partition_id = TEST_PARTITION_ID;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);

    /* Poll after clear: no signal, and it must not block. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = PSA_DOORBELL;
    call.timeout = PSA_POLL;
    call.asserted = &asserted;
    asserted = 0xFFFFFFFFU;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(wt_spm_call_would_block(&call), 0);
    EXPECT_INT(asserted, 0);
    (void)printf("PASS: WT-FFM-0027 gate doorbell asserts until psa_clear\n");
}

/* i063 topology: a server partition exporting three connection-based services
 * (two the server consumes, one starved irritator) and a client partition that
 * may connect to the irritator. Mirrors SERVER_UNSPECIFIED/RELAX plus the
 * SECURE_CONNECT_ONLY irritator, and CLIENT_PARTITION. */
#define I063_SERVER_ID    10
#define I063_CLIENT_ID    11
#define I063_SVC_A_SID    0x2000U
#define I063_SVC_B_SID    0x2001U
#define I063_SVC_IRR_SID  0x2002U
#define I063_SIG_A        0x10U
#define I063_SIG_B        0x20U
#define I063_SIG_IRR      0x40U
#define I063_NS_CLIENT    (-1)

static const wt_service_descriptor_t g_i063_services[] = {
    { "svc_a",   I063_SVC_A_SID,   1U, WT_SERVICE_VERSION_RELAXED, I063_SIG_A,
      0U, 1U, 1U },
    { "svc_b",   I063_SVC_B_SID,   1U, WT_SERVICE_VERSION_RELAXED, I063_SIG_B,
      0U, 1U, 1U },
    { "svc_irr", I063_SVC_IRR_SID, 1U, WT_SERVICE_VERSION_RELAXED, I063_SIG_IRR,
      0U, 1U, 1U }
};

static const uint32_t g_i063_client_deps[] = { I063_SVC_IRR_SID };

static const wt_partition_manifest_t g_i063_partitions[] = {
    { "i063_server", I063_SERVER_ID, WT_FFM_VERSION_1_0,
      WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
      g_i063_services, sizeof(g_i063_services) / sizeof(g_i063_services[0]),
      NULL, 0U, NULL, 0U },
    { "i063_client", I063_CLIENT_ID, WT_FFM_VERSION_1_0,
      WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
      NULL, 0U, g_i063_client_deps,
      sizeof(g_i063_client_deps) / sizeof(g_i063_client_deps[0]), NULL, 0U }
};

static const wt_system_manifest_t g_i063_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "host-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_i063_partitions,
    .partition_count = sizeof(g_i063_partitions) /
                       sizeof(g_i063_partitions[0])
};

static void i063_server_serve(psa_signal_t signal, psa_status_t reply)
{
    psa_msg_t msg;

    EXPECT_INT(wt_spm_host_get(I063_SERVER_ID, signal, &msg), PSA_SUCCESS);
    EXPECT_INT(wt_spm_host_reply(I063_SERVER_ID, msg.handle, reply),
               WT_FFM_SUCCESS);
}

/* Phase C (WT-FFM-0014/0027): doorbell-driven origination with masked
 * starvation, the portable core of Arm test i063. A doorbell-woken client
 * partition originates a fresh outbound connect through the SP-as-client gate;
 * that connect asserts a server signal the server masks out, so it stays
 * starved across the server's masked waits and is only delivered once the
 * server waits on it explicitly. The coroutine choreography this drives lives
 * on Armv8-M (wt_spm_sched_dispatch) and is proven on M33MU; here the gate and
 * runtime state machine it relies on are proven directly. */
static void test_doorbell_origination(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t client;
    psa_signal_t asserted;
    uint16_t ns_a_msg;
    uint16_t ns_b_msg;
    psa_handle_t handle;

    EXPECT_INT(wt_spm_host_init(&g_i063_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    /* Server doorbells the client (server_test's psa->notify(CLIENT)). */
    EXPECT_INT(wt_spm_notify(I063_CLIENT_ID), WT_FFM_SUCCESS);
    asserted = 0U;
    EXPECT_INT(wt_spm_host_wait(I063_CLIENT_ID, PSA_WAIT_ANY, &asserted),
               WT_FFM_SUCCESS);
    EXPECT_INT(asserted, PSA_DOORBELL);

    /* Doorbell-woken client originates the irritator connect: gate CONNECT
     * pass 1 enqueues on the server and blocks the client. */
    (void)memset(&client, 0, sizeof(client));
    client.op = WT_SPM_OP_CONNECT;
    client.partition_id = I063_CLIENT_ID;
    client.sid = I063_SVC_IRR_SID;
    client.version = 1U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &client), WT_FFM_SUCCESS);
    EXPECT_INT(client.ret_int, WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(client.pending_valid, 1U);
    EXPECT_INT(wt_spm_call_would_block(&client), 1);

    /* Starvation: the irritator asserted the server's IRR signal, but a wait
     * masking it out must not observe it. */
    asserted = 0xFFFFFFFFU;
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_A | I063_SIG_B,
                           &asserted), WT_FFM_ERROR_NOT_READY);
    EXPECT_INT(asserted, 0);

    /* Two NS connects feed the server's masked loop; the irritator stays
     * starved through both iterations. */
    ns_a_msg = 0xFFFFU;
    handle = t_connect_begin(I063_NS_CLIENT, I063_SVC_A_SID, 1U,
                                  &ns_a_msg);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    asserted = 0U;
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_A | I063_SIG_B,
                           &asserted), WT_FFM_SUCCESS);
    EXPECT_INT(asserted, I063_SIG_A);
    i063_server_serve(I063_SIG_A, PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT((int)wt_spm_connect_finish((uint8_t)ns_a_msg),
               (int)PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT(wt_spm_done((uint8_t)client.pending_msg, I063_CLIENT_ID,
                           PSA_IPC_CONNECT), 0);

    ns_b_msg = 0xFFFFU;
    handle = t_connect_begin(I063_NS_CLIENT, I063_SVC_B_SID, 1U,
                                  &ns_b_msg);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    asserted = 0U;
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_A | I063_SIG_B,
                           &asserted), WT_FFM_SUCCESS);
    EXPECT_INT(asserted, I063_SIG_B);
    i063_server_serve(I063_SIG_B, PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT((int)wt_spm_connect_finish((uint8_t)ns_b_msg),
               (int)PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT(wt_spm_done((uint8_t)client.pending_msg, I063_CLIENT_ID,
                           PSA_IPC_CONNECT), 0);

    /* Server finishes its loop and finally waits on the irritator signal. */
    asserted = 0U;
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_IRR, &asserted),
               WT_FFM_SUCCESS);
    EXPECT_INT(asserted, I063_SIG_IRR);
    i063_server_serve(I063_SIG_IRR, PSA_ERROR_CONNECTION_REFUSED);

    /* The starved origination now completes: gate CONNECT pass 2 harvests the
     * refused connect, matching i063's psa_connect == CONNECTION_REFUSED. */
    EXPECT_INT(wt_spm_done((uint8_t)client.pending_msg, I063_CLIENT_ID,
                           PSA_IPC_CONNECT), 1);
    EXPECT_INT(wt_spm_gate(runtime, NULL, &client), WT_FFM_SUCCESS);
    EXPECT_INT(client.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(client.pending_valid, 0U);
    EXPECT_INT(wt_spm_call_would_block(&client), 0);
    EXPECT_INT((int)client.ret_handle, (int)PSA_ERROR_CONNECTION_REFUSED);
    /* Server-replied refusal is a legal returned status, never a panic. */
    EXPECT_INT((int)client.must_panic, 0);

    /* Client clears the doorbell (client_main's psa_clear after the connect). */
    EXPECT_INT(wt_spm_host_clear(I063_CLIENT_ID), WT_FFM_SUCCESS);
    asserted = 0xFFFFFFFFU;
    EXPECT_INT(wt_spm_host_wait(I063_CLIENT_ID, PSA_WAIT_ANY, &asserted),
               WT_FFM_ERROR_NOT_READY);

    (void)printf("PASS: WT-FFM-0014 doorbell-driven origination, masked "
                 "starvation (i063)\n");
}

static void test_gate_validates_buffers(void)
{
    static uint8_t scratch[64];
    static uint8_t outside[16];
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_secure_domain_t domain;
    wt_spm_call_t call;

    EXPECT_INT(wt_spm_host_init(&g_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    (void)memset(&domain, 0, sizeof(domain));
    domain.regions[0].base = (uintptr_t)scratch;
    domain.regions[0].size = sizeof(scratch);
    domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    domain.region_count = 1U;

    /* Read destination inside the domain: validation passes, so the op runs
     * (an invalid handle then returns zero bytes, not a rejection). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.partition_id = TEST_PARTITION_ID;
    call.buffer = scratch;
    call.num_bytes = 16U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_HANDLE);
    EXPECT_INT((int)call.must_panic, 1);

    /* Read destination outside the domain: rejected before wt_ffm_read runs,
     * and flagged as a must-panic programmer error (FF-M, drives i055). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.partition_id = TEST_PARTITION_ID;
    call.buffer = outside;
    call.num_bytes = 16U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_BUFFER);
    EXPECT_INT((int)call.must_panic, 1);

    /* Write source outside the domain is rejected the same way (drives i057). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WRITE;
    call.partition_id = TEST_PARTITION_ID;
    call.buffer = outside;
    call.num_bytes = 16U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_BUFFER);
    EXPECT_INT((int)call.must_panic, 1);

    /* psa_get with an out-of-domain message pointer must panic (drives i047). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = TEST_PARTITION_ID;
    call.msg = (psa_msg_t*)(void*)outside;
    call.signal = 0x1U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    /* NULL SP pointer with a domain present is rejected and panics. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.partition_id = TEST_PARTITION_ID;
    call.buffer = NULL;
    call.num_bytes = 16U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_BUFFER);
    EXPECT_INT((int)call.must_panic, 1);

    /* A zero-length write on a dead handle still panics (i042): handle
     * validity outranks the zero-length transfer leniency. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WRITE;
    call.partition_id = TEST_PARTITION_ID;
    call.buffer = outside;
    call.num_bytes = 0U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_HANDLE);
    EXPECT_INT((int)call.must_panic, 1);

    /* Zero-length read on a dead handle panics the same way (i030/i036). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.partition_id = TEST_PARTITION_ID;
    call.buffer = NULL;
    call.num_bytes = 0U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_HANDLE);
    EXPECT_INT((int)call.must_panic, 1);

    /* An out-of-domain psa_call input vector is a must-panic programmer
     * error for a Secure caller (the i050-i053 SPE variants). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CALL;
    call.partition_id = TEST_PARTITION_ID;
    call.msg_handle = 1;
    call.sp_in[0].base = outside;
    call.sp_in[0].len = 16U;
    call.sp_in_len = 1U;
    EXPECT_INT(wt_spm_gate(runtime, &domain, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_status, PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT((int)call.must_panic, 1);

    /* No domain: validation is bypassed and the op runs on the raw pointer.
     * The direct transport is exactly this shape — assert it matches. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.partition_id = TEST_PARTITION_ID;
    call.buffer = outside;
    call.num_bytes = 16U;
    EXPECT_INT(wt_spm_transport_direct(runtime, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_HANDLE);
    EXPECT_SIZE(call.ret_size, 0U);
    (void)printf("PASS: WT-FFM-0014 gate bounds SP pointers to the domain\n");
}

static void test_gate_eoi_must_panic(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t call;

    EXPECT_INT(wt_spm_host_init(&g_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    /* Multiple signal bits: FF-M programmer error the gate must flag. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_EOI;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_IRQ_SIGNAL | TEST_NONINTR_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_ARGUMENT);
    EXPECT_INT(call.must_panic, 1);

    /* A signal the partition never declared as an interrupt. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_EOI;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_NONINTR_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_POLICY);
    EXPECT_INT(call.must_panic, 1);

    /* A declared interrupt signal that is not currently asserted. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_EOI;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_IRQ_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_STATE);
    EXPECT_INT(call.must_panic, 1);

    /* A legal end-of-interrupt neither errors nor panics, and clears it. */
    g_wt_spm.asserted[0] |= TEST_IRQ_SIGNAL;
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_EOI;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_IRQ_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(call.must_panic, 0);

    (void)printf("PASS: WT-FFM-0014 gate panics psa_eoi misuse\n");
}

static void test_gate_irq_enable(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t call;

    EXPECT_INT(wt_spm_host_init(&g_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    /* A declared interrupt signal resolves to its manifest interrupt number
     * so the arch layer can unmask the right controller line. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_IRQ_ENABLE;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_IRQ_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_version, 42);
    EXPECT_INT(call.must_panic, 0);

    /* psa_eoi must re-enable the interrupt (FF-M 4.5.3): a successful EOI
     * resolves the same manifest line so the arch layer can unmask it. */
    EXPECT_INT(wt_spm_irq_assert(42U), 0);
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_EOI;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_IRQ_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_version, 42);
    EXPECT_INT(call.must_panic, 0);

    /* psa_irq_enable on a non-interrupt signal is a programmer error. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_IRQ_ENABLE;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_NONINTR_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_POLICY);
    EXPECT_INT(call.must_panic, 1);

    /* Multiple signal bits likewise. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_IRQ_ENABLE;
    call.partition_id = TEST_PARTITION_ID;
    call.signal_mask = TEST_IRQ_SIGNAL | TEST_NONINTR_SIGNAL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_ARGUMENT);
    EXPECT_INT(call.must_panic, 1);

    (void)printf("PASS: WT-FFM-0014 gate validates psa_irq_enable\n");
}

/* The i004-i012 SPE panic classes: an SPM-level connect policy refusal and a
 * close on a bad handle are PROGRAMMER ERRORs that must panic a Secure
 * caller, while resource exhaustion stays a returnable CONNECTION_BUSY. */
static void test_gate_connect_close_panic_class(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t call;
    size_t i;

    EXPECT_INT(wt_spm_host_init(&g_i063_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    /* Unknown SID (i004). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = I063_CLIENT_ID;
    call.sid = 0x9999U;
    call.version = 1U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT((int)call.ret_handle, (int)PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT((int)call.must_panic, 1);

    /* SID missing from the partition's dependency list (i009). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = I063_CLIENT_ID;
    call.sid = I063_SVC_A_SID;
    call.version = 1U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.ret_handle, (int)PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT((int)call.must_panic, 1);

    /* Version above the service's maximum (i005/i007/i010). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = I063_CLIENT_ID;
    call.sid = I063_SVC_IRR_SID;
    call.version = 2U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.ret_handle, (int)PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT((int)call.must_panic, 1);

    /* Version zero is never valid (i011). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = I063_CLIENT_ID;
    call.sid = I063_SVC_IRR_SID;
    call.version = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.ret_handle, (int)PSA_ERROR_CONNECTION_REFUSED);
    EXPECT_INT((int)call.must_panic, 1);

    /* Pool exhaustion returns CONNECTION_BUSY without a panic (the i002
     * concurrent-connect-limit loop must see the status and recover). */
    for (i = 0U; i <= WT_SPM_SLOTS; i++) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_CONNECT;
        call.partition_id = I063_CLIENT_ID;
        call.sid = I063_SVC_IRR_SID;
        call.version = 1U;
        EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
        if (call.ret_int == WT_FFM_SUCCESS)
            break;
        EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    }
    EXPECT_INT((int)call.ret_handle, (int)PSA_ERROR_CONNECTION_BUSY);
    EXPECT_INT((int)call.must_panic, 0);

    /* psa_close on a forged handle must panic (i012's 0x1234DEAD). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CLOSE;
    call.partition_id = I063_CLIENT_ID;
    call.msg_handle = (psa_handle_t)0x1234DEAD;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_TRUE(call.ret_int != WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    /* psa_close(PSA_NULL_HANDLE) stays a legal no-op (i002 check 2). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CLOSE;
    call.partition_id = I063_CLIENT_ID;
    call.msg_handle = PSA_NULL_HANDLE;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 0);

    /* psa_close on an error-status handle (a refused connect's status fed
     * straight back in) is a PROGRAMMER ERROR, not a no-op: only the null
     * handle closes silently. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CLOSE;
    call.partition_id = I063_CLIENT_ID;
    call.msg_handle = (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_TRUE(call.ret_int != WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);
    (void)printf("PASS: WT-FFM-0063 close of an error-status handle is a "
                 "must-panic programmer error\n");

    (void)printf("PASS: WT-FFM-0014 gate panics connect policy refusal and "
                 "bad close (i004-i012)\n");
}

/* The i024-i027 SPE panic classes: psa_call on a forged or null handle and a
 * server-completed PROGRAMMER_ERROR reply must panic a Secure caller. */
static void test_gate_call_panic_class(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t call;
    psa_signal_t asserted;

    EXPECT_INT(wt_spm_host_init(&g_i063_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    /* Forged handle (i024's 0x1234DEAD). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CALL;
    call.partition_id = I063_CLIENT_ID;
    call.msg_handle = (psa_handle_t)0x1234DEAD;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_status, PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT((int)call.must_panic, 1);

    /* Null handle (i025). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CALL;
    call.partition_id = I063_CLIENT_ID;
    call.msg_handle = PSA_NULL_HANDLE;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_status, PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT((int)call.must_panic, 1);

    /* Server-completed PROGRAMMER_ERROR (i027): connect, then a well-formed
     * call the server answers with -129 — the harvesting Secure caller must
     * panic even though the SPM itself found nothing wrong. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = I063_CLIENT_ID;
    call.sid = I063_SVC_IRR_SID;
    call.version = 1U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    asserted = 0U;
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_IRR, &asserted),
               WT_FFM_SUCCESS);
    i063_server_serve(I063_SIG_IRR, PSA_SUCCESS);
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(call.ret_handle));
    EXPECT_INT((int)call.must_panic, 0);

    call.op = WT_SPM_OP_CALL;
    call.msg_handle = call.ret_handle;
    call.pending_valid = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    asserted = 0U;
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_IRR, &asserted),
               WT_FFM_SUCCESS);
    i063_server_serve(I063_SIG_IRR, PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_status, PSA_ERROR_PROGRAMMER_ERROR);
    EXPECT_INT((int)call.must_panic, 1);

    (void)printf("PASS: WT-FFM-0014 gate panics psa_call handle misuse and "
                 "server-completed PROGRAMMER_ERROR (i024-i027)\n");
}

/* The caller's block as the SPM's memory checks see it change under them. */
static wt_spm_call_t* g_swap_call;
static const uint8_t g_swap_good[3] = { 'a', 'b', 'c' };
static const uint8_t g_swap_evil[6] = { 'E', 'V', 'I', 'L', '!', '!' };
static uint8_t g_swap_out[4];
static uint8_t g_swap_other[4];

static void swap_vectors(void)
{
    if (g_swap_call != NULL) {
        g_swap_call->sp_in[0].base = g_swap_evil;
        g_swap_call->sp_in[0].len = sizeof(g_swap_evil);
        g_swap_call->sp_out[0].base = g_swap_other;
        g_swap_call->sp_in_len = 4U;
        g_swap_call->msg_handle = PSA_NULL_HANDLE;
    }
}

static int swap_check_read(void* context, psa_client_id_t caller,
                           const void* address, size_t size)
{
    (void)context;
    (void)caller;
    swap_vectors();
    return size == 0U || address != NULL;
}

static int swap_check_write(void* context, psa_client_id_t caller,
                            void* address, size_t size)
{
    (void)context;
    (void)caller;
    swap_vectors();
    return size == 0U || address != NULL;
}

static const wt_spm_host_ops_t g_swap_ops = {
    swap_check_read,
    swap_check_write,
    gate_dispatch,
    test_panic
};

/* The gate acts on one private copy of the caller's block: a block that
 * changes after the memory checks ran cannot swap the vectors, the counts or
 * the handle the request was checked with. */
static void test_gate_snapshot(void)
{
    static const uint8_t answer[2] = { 'O', 'K' };
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t call;
    psa_signal_t asserted = 0U;
    psa_handle_t handle;
    psa_msg_t msg;
    uint8_t seen[8];

    g_swap_call = NULL;
    EXPECT_INT(wt_spm_host_init(&g_i063_manifest, &g_swap_ops, NULL),
               WT_FFM_SUCCESS);
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = I063_CLIENT_ID;
    call.sid = I063_SVC_IRR_SID;
    call.version = 1U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_IRR, &asserted),
               WT_FFM_SUCCESS);
    i063_server_serve(I063_SIG_IRR, PSA_SUCCESS);
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    handle = call.ret_handle;
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));

    (void)memset(&call, 0, sizeof(call));
    (void)memset(g_swap_out, 0, sizeof(g_swap_out));
    (void)memset(g_swap_other, 0, sizeof(g_swap_other));
    call.op = WT_SPM_OP_CALL;
    call.partition_id = I063_CLIENT_ID;
    call.msg_handle = handle;
    call.call_type = PSA_IPC_CALL;
    call.sp_in[0].base = g_swap_good;
    call.sp_in[0].len = sizeof(g_swap_good);
    call.sp_in_len = 1U;
    call.sp_out[0].base = g_swap_out;
    call.sp_out[0].len = sizeof(g_swap_out);
    call.sp_out_len = 1U;
    g_swap_call = &call;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    EXPECT_INT((int)call.pending_valid, 1);
    /* The gate's copy, not the changed block, is what it hands back. */
    EXPECT_TRUE(call.sp_in[0].base == g_swap_good);
    EXPECT_SIZE(call.sp_in[0].len, sizeof(g_swap_good));
    EXPECT_INT((int)call.sp_in_len, 1);
    EXPECT_TRUE(call.msg_handle == handle);

    /* The server sees the vector that was checked. */
    asserted = 0U;
    EXPECT_INT(wt_spm_host_wait(I063_SERVER_ID, I063_SIG_IRR, &asserted),
               WT_FFM_SUCCESS);
    EXPECT_INT(wt_spm_host_get(I063_SERVER_ID, I063_SIG_IRR, &msg),
               PSA_SUCCESS);
    EXPECT_SIZE(msg.in_size[0], sizeof(g_swap_good));
    EXPECT_SIZE(msg.in_size[1], 0U);
    EXPECT_SIZE(msg.out_size[0], sizeof(g_swap_out));
    (void)memset(seen, 0, sizeof(seen));
    EXPECT_SIZE(wt_spm_host_read(I063_SERVER_ID, msg.handle, 0U, seen,
                            sizeof(seen)), sizeof(g_swap_good));
    EXPECT_INT(memcmp(seen, g_swap_good, sizeof(g_swap_good)), 0);
    EXPECT_INT(wt_spm_host_write(I063_SERVER_ID, msg.handle, 0U, answer,
                            sizeof(answer)), WT_FFM_SUCCESS);
    EXPECT_INT(wt_spm_host_reply(I063_SERVER_ID, msg.handle,
                            PSA_SUCCESS), WT_FFM_SUCCESS);

    /* The reply lands in the buffer that was checked, not the swapped one. */
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_status, PSA_SUCCESS);
    EXPECT_INT(memcmp(g_swap_out, answer, sizeof(answer)), 0);
    EXPECT_INT(g_swap_other[0], 0);
    EXPECT_SIZE(call.sp_out[0].len, sizeof(answer));
    EXPECT_TRUE(call.sp_out[0].base == g_swap_out);
    g_swap_call = NULL;

    (void)printf("PASS: WT-FFM-0012 gate acts on one copy of the caller's "
                 "block\n");
}

/* Keystore platform services are pinned per partition (WT-FFM-0062). */
static void test_keystore_pins(void)
{
    const int32_t vault = 5;
    const int32_t crypto = 4;
    const int32_t attest = 3;
    const int32_t storage = 6;

    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_FLASH, vault,
                                         vault, crypto), 1);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_LOCK, vault,
                                         vault, crypto), 1);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_ENTROPY, vault,
                                         vault, crypto), 1);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_ENTROPY, crypto,
                                         vault, crypto), 1);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_FLASH, crypto,
                                         vault, crypto), 0);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_LOCK, crypto,
                                         vault, crypto), 0);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_FLASH, attest,
                                         vault, crypto), 0);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_LOCK, attest,
                                         vault, crypto), 0);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_ENTROPY, attest,
                                         vault, crypto), 0);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_FLASH, storage,
                                         vault, crypto), 0);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_ENTROPY, storage,
                                         vault, crypto), 0);
    /* No partition identity at all is never the owner. */
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_FLASH, 0, 0, 0),
               0);
    EXPECT_INT(wt_spm_keystore_op_pinned(WT_SPM_OP_KEYSTORE_ENTROPY, -1, -1,
                                         -1), 0);
    (void)printf("PASS: WT-FFM-0062 keystore services pinned per "
                 "partition\n");
}

/* The i013-i023 server-side misuse classes: psa_get on multi-bit, doorbell,
 * or unasserted signals, psa_set_rhandle/psa_reply on forged handles, and a
 * connect reply outside SUCCESS/REFUSED/BUSY all panic the server. */
static void test_gate_server_misuse_panic_class(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t call;
    psa_msg_t msg;
    uint16_t ns_msg;
    psa_signal_t asserted_sig;
    psa_handle_t handle;

    EXPECT_INT(wt_spm_host_init(&g_i063_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    /* Multi-bit signal (i013). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = I063_SERVER_ID;
    call.signal = I063_SIG_A | I063_SIG_B;
    call.msg = &msg;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_TRUE(call.ret_status != PSA_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    /* The doorbell is not an RoT-service signal (i015). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = I063_SERVER_ID;
    call.signal = PSA_DOORBELL;
    call.msg = &msg;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    /* Valid but unasserted signal, no queued message (i014/i016). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = I063_SERVER_ID;
    call.signal = I063_SIG_A;
    call.msg = &msg;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    /* psa_set_rhandle on a forged message handle (i018/i019). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_SET_RHANDLE;
    call.partition_id = I063_SERVER_ID;
    call.msg_handle = (psa_handle_t)0x1234DEAD;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_TRUE(call.ret_int != WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    /* psa_reply on forged and null message handles (i022/i023). */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = I063_SERVER_ID;
    call.msg_handle = (psa_handle_t)0x1234DEAD;
    call.status = PSA_ERROR_CONNECTION_REFUSED;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);
    call.msg_handle = PSA_NULL_HANDLE;
    call.must_panic = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    /* A connect reply outside SUCCESS/REFUSED/BUSY panics (i020); the same
     * message then replies REFUSED legally without a panic. */
    ns_msg = 0xFFFFU;
    handle = t_connect_begin(I063_NS_CLIENT, I063_SVC_A_SID, 1U,
                                  &ns_msg);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_spm_host_get(I063_SERVER_ID, I063_SIG_A, &msg),
               PSA_SUCCESS);
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = I063_SERVER_ID;
    call.msg_handle = msg.handle;
    call.status = PSA_ERROR_CONNECTION_REFUSED + 0x10;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_TRUE(call.ret_int != WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);
    call.status = PSA_ERROR_CONNECTION_REFUSED;
    call.must_panic = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 0);


    /* psa_read/skip/write misuse (i028-i046): forged handles, an index past
     * PSA_MAX_IOVEC, and access to a connect-type message all panic. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.partition_id = I063_SERVER_ID;
    call.msg_handle = (psa_handle_t)0x1234DEAD;
    call.buffer = &msg;
    call.num_bytes = 1U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);
    call.op = WT_SPM_OP_SKIP;
    call.must_panic = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);
    call.op = WT_SPM_OP_WRITE;
    call.must_panic = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    ns_msg = 0xFFFFU;
    handle = t_connect_begin(I063_NS_CLIENT, I063_SVC_B_SID, 1U,
                                  &ns_msg);
    EXPECT_TRUE(PSA_HANDLE_IS_VALID(handle));
    EXPECT_INT(wt_spm_host_get(I063_SERVER_ID, I063_SIG_B, &msg),
               PSA_SUCCESS);
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.partition_id = I063_SERVER_ID;
    call.msg_handle = msg.handle;
    call.buffer = &ns_msg;
    call.num_bytes = 1U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);
    call.op = WT_SPM_OP_READ;
    call.msg_handle = msg.handle;
    call.vec_idx = PSA_MAX_IOVEC;
    call.must_panic = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);


    /* psa_wait on a mask with no assignable signal panics (i062); notify to
     * a bad partition id (i059/i060) and clear with the doorbell unasserted
     * (i061) panic the same way. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = I063_SERVER_ID;
    call.signal_mask = 0x80000000U;
    call.asserted = &asserted_sig;
    call.timeout = PSA_POLL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_ARGUMENT);
    EXPECT_INT((int)call.must_panic, 1);

    /* A mask mixing an assigned bit with an unassigned one is valid (i062):
     * the unassigned bit is ignored, so an unasserted doorbell is a poll
     * miss (NOT_READY), not a panic. */
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.partition_id = I063_SERVER_ID;
    call.signal_mask = PSA_DOORBELL | 0x80000000U;
    call.asserted = &asserted_sig;
    call.timeout = PSA_POLL;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_ERROR_NOT_READY);
    EXPECT_INT((int)call.must_panic, 0);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_NOTIFY;
    call.partition_id = I063_SERVER_ID;
    call.notify_partition = -10;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);
    call.notify_partition = 200;
    call.must_panic = 0U;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CLEAR;
    call.partition_id = I063_SERVER_ID;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT((int)call.must_panic, 1);

    (void)printf("PASS: WT-FFM-0014 gate panics server-side get/rhandle/reply "
                 "misuse (i013-i023)\n");
}

/* WT_SPM_OP_LIFECYCLE reports the boot-handoff lifecycle stamped on the runtime;
 * a runtime with no lifecycle set reports PSA_LIFECYCLE_UNKNOWN. */
static void test_gate_lifecycle(void)
{
    wt_ffm_runtime_t* runtime = &g_wt_spm;
    wt_spm_call_t call;

    EXPECT_INT(wt_spm_host_init(&g_manifest, &g_port_ops, NULL),
               WT_FFM_SUCCESS);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_LIFECYCLE;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT((int)call.ret_version, (int)PSA_LIFECYCLE_UNKNOWN);

    g_wt_spm.lifecycle = PSA_LIFECYCLE_SECURED;
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_LIFECYCLE;
    EXPECT_INT(wt_spm_gate(runtime, NULL, &call), WT_FFM_SUCCESS);
    EXPECT_INT(call.ret_int, WT_FFM_SUCCESS);
    EXPECT_INT((int)call.ret_version, (int)PSA_LIFECYCLE_SECURED);
}

int main(void)
{
    test_gate_equivalence();
    test_gate_would_block();
    test_gate_lifecycle();
    test_gate_doorbell_state_machine();
    test_doorbell_origination();
    test_gate_validates_buffers();
    test_gate_eoi_must_panic();
    test_gate_irq_enable();
    test_gate_connect_close_panic_class();
    test_gate_call_panic_class();
    test_gate_snapshot();
    test_keystore_pins();
    test_gate_server_misuse_panic_class();

    if (g_failures != 0U) {
        (void)fprintf(stderr, "FAIL: %u/%u checks failed\n", g_failures,
                      g_checks);
        return 1;
    }
    (void)printf("PASS: spm_gate (%u checks)\n", g_checks);
    return 0;
}
