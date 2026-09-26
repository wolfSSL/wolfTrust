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

/* Host proof of SERVICE_FWU (P6-S4, WT-FWU-0001 / WT-FWU-0003). Two layers:
 * the neutral state machine driven directly against a RAM staging backend
 * (every transition and negative — malformed, oversize, misaligned,
 * rolled-back, storage-failure, abort-restores-state), and the full FF-M IPC
 * round trip — a Non-secure client marshalling query/start/write/finish/
 * install/abort onto the SERVICE_FWU wire and the candidate landing in the
 * staged partition with the swap armed. The wolfBoot swap of the armed image
 * and its authenticated-launch/anti-rollback gate on the next boot ride the
 * full boot-and-update gate (P6-S6). */

#include "wolftrust/ffm.h"
#include "wolftrust/services/fwu_service.h"

#include <stdio.h>
#include <string.h>

#define TEST_FWU_PARTITION 8
#define TEST_FWU_SID       4101U
#define TEST_NS_GUEST0     (-1)

#define MOCK_CAPACITY 4096u
#define MOCK_ALIGN    16u

static int g_failures;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    } else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/* RAM staging backend mirroring the target flash + trigger seam. */
typedef struct mock_backend {
    uint8_t image[MOCK_CAPACITY];
    uint32_t begin_calls;
    uint32_t armed;
    uint32_t armed_size;
    uint32_t armed_version;
    uint32_t header_version;
    uint32_t write_calls;
    uint32_t fail_write_call;
    int fail_write;
    int fail_arm;
    int fail_disarm;
    int fail_verify;
} mock_backend_t;

static int mock_begin(void* ctx)
{
    mock_backend_t* b = (mock_backend_t*)ctx;

    (void)memset(b->image, 0xFF, sizeof(b->image));
    b->begin_calls++;
    return 0;
}

static int mock_write(void* ctx, uint32_t offset, const uint8_t* data,
                      uint32_t size)
{
    mock_backend_t* b = (mock_backend_t*)ctx;

    b->write_calls++;
    if (b->fail_write || b->write_calls == b->fail_write_call) {
        return -1;
    }
    if ((uint64_t)offset + size > sizeof(b->image)) {
        return -1;
    }
    (void)memcpy(b->image + offset, data, size);
    return 0;
}

static int mock_arm(void* ctx, uint32_t image_size, uint32_t version)
{
    mock_backend_t* b = (mock_backend_t*)ctx;

    if (b->fail_arm) {
        return -1;
    }
    b->armed = 1u;
    b->armed_size = image_size;
    b->armed_version = version;
    return 0;
}

static int mock_disarm(void* ctx)
{
    mock_backend_t* b = (mock_backend_t*)ctx;

    if (b->fail_disarm) {
        return -1;
    }
    b->armed = 0u;
    return 0;
}

static int mock_verify(void* ctx, uint32_t staged_size,
                       uint32_t* header_version)
{
    mock_backend_t* b = (mock_backend_t*)ctx;

    (void)staged_size;
    if (b->fail_verify) {
        return -1;
    }
    *header_version = b->header_version;
    return 0;
}

static void mock_backend_init(wt_fwu_backend_t* backend, mock_backend_t* mem)
{
    (void)memset(mem, 0, sizeof(*mem));
    (void)memset(backend, 0, sizeof(*backend));
    backend->begin = mock_begin;
    backend->write = mock_write;
    backend->arm = mock_arm;
    backend->disarm = mock_disarm;
    backend->capacity = MOCK_CAPACITY;
    backend->align = MOCK_ALIGN;
}

static void ctx_init(wt_fwu_service_ctx_t* ctx, const wt_fwu_backend_t* backend,
                     mock_backend_t* mem, uint32_t floor)
{
    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->transport = wt_spm_transport_direct;
    ctx->backend = backend;
    ctx->backend_ctx = mem;
    ctx->version_floor = floor;
    ctx->active_version = 2u;
    ctx->state = PSA_FWU_READY;
}

/* --- Layer 1: neutral state machine, driven directly. --- */
static void test_state_machine(void)
{
    wt_fwu_backend_t backend;
    mock_backend_t mem;
    wt_fwu_service_ctx_t ctx;
    psa_fwu_component_info_t info;
    uint8_t block[64];
    psa_status_t st;

    (void)memset(block, 0xA5, sizeof(block));

    /* Fresh component is READY. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 3u);
    check(wt_fwu_query(&ctx, WT_FWU_COMPONENT_PRIMARY, &info) == PSA_SUCCESS &&
              info.state == PSA_FWU_READY && info.max_size == MOCK_CAPACITY,
          "WT-FWU-0001 query reports READY and the component capacity");

    /* Bad component id is rejected. */
    check(wt_fwu_start(&ctx, 7u, 5u) == PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0001 start on an unknown component is rejected");

    /* Ops out of order fail closed with BAD_STATE, no partial effect. */
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block, 16u) ==
              PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 write before start is BAD_STATE");
    check(wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 finish before start is BAD_STATE");
    check(wt_fwu_install(&ctx) == PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 install before a candidate is BAD_STATE");
    check(wt_fwu_cancel(&ctx, WT_FWU_COMPONENT_PRIMARY) ==
              PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 cancel from READY is BAD_STATE");
    check(wt_fwu_clean(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 clean from READY is BAD_STATE");
    check(wt_fwu_reject(&ctx, PSA_ERROR_GENERIC_ERROR) == PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 reject from READY is BAD_STATE");

    /* Happy path: start erases, write stages, finish, install arms. */
    st = wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u);
    check(st == PSA_SUCCESS && ctx.state == PSA_FWU_WRITING &&
              mem.begin_calls == 1u,
          "WT-FWU-0002 start erases the update partition and enters WRITING");
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u) ==
              PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 a second start while WRITING is BAD_STATE");

    /* Oversize, wrapping, misaligned, and empty writes are refused. */
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, MOCK_CAPACITY - 8u,
                       block, 16u) == PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0003 an oversize write is refused before programming");
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0xFFFFFFF0u, block,
                       32u) == PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0003 a wrapping offset+size is refused");
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 1u, block, 16u) ==
              PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0003 a misaligned write is refused");
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block, 0u) ==
              PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0003 a zero-length write is refused");

    st = wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block, 32u);
    check(st == PSA_SUCCESS && mem.image[0] == 0xA5 && ctx.write_high == 32u,
          "WT-FWU-0002 an aligned write lands in the staged partition");
    st = wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 32u, block, 32u);
    check(st == PSA_SUCCESS && ctx.write_high == 64u,
          "WT-FWU-0002 a second block extends the staged image");

    st = wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY);
    check(st == PSA_SUCCESS && ctx.state == PSA_FWU_CANDIDATE,
          "WT-FWU-0002 finish moves the candidate to CANDIDATE");
    check(wt_fwu_query(&ctx, WT_FWU_COMPONENT_PRIMARY, &info) == PSA_SUCCESS &&
              info.state == PSA_FWU_CANDIDATE &&
              info.impl.staged_size == 64u && info.version.build == 2u,
          "WT-FWU-0001 query keeps the active image version public");

    st = wt_fwu_install(&ctx);
    check(st == PSA_SUCCESS_REBOOT && ctx.state == PSA_FWU_STAGED &&
              mem.armed == 1u && mem.armed_size == 64u &&
              mem.armed_version == 5u,
          "WT-FWU-0002 install arms the swap and asks for a reboot");

    /* Reject after arming disarms the trigger and records the error;
     * clean then restores READY (PSA FWU 1.0 STAGED -> FAILED -> READY). */
    st = wt_fwu_reject(&ctx, PSA_ERROR_GENERIC_ERROR);
    check(st == PSA_SUCCESS && ctx.state == PSA_FWU_FAILED && mem.armed == 0u,
          "WT-FWU-0003 reject clears an armed swap and marks FAILED");
    check(wt_fwu_query(&ctx, WT_FWU_COMPONENT_PRIMARY, &info) ==
              PSA_SUCCESS && info.state == PSA_FWU_FAILED &&
              info.error == PSA_ERROR_GENERIC_ERROR,
          "WT-FWU-0001 query reports the rejected component error");
    check(wt_fwu_clean(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS &&
              ctx.state == PSA_FWU_READY,
          "WT-FWU-0003 clean restores a FAILED component to READY");
    /* Cancel abandons an in-progress write; clean releases it. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 3u);
    (void)wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u);
    (void)wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block, 16u);
    check(wt_fwu_cancel(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS &&
              ctx.state == PSA_FWU_FAILED,
          "WT-FWU-0003 cancel abandons the WRITING candidate to FAILED");
    check(wt_fwu_clean(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS &&
              ctx.state == PSA_FWU_READY,
          "WT-FWU-0003 clean after cancel restores READY");

    /* Anti-rollback: a candidate below the floor is refused at start. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 10u);
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u) ==
              PSA_ERROR_NOT_PERMITTED && ctx.state == PSA_FWU_READY &&
              mem.begin_calls == 0u,
          "WT-FWU-0003 a rolled-back candidate is refused before staging");

    /* Anti-rollback re-checked if the floor advances after start. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 5u);
    (void)wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u);
    (void)wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block, 16u);
    ctx.version_floor = 6u;
    check(wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) ==
              PSA_ERROR_NOT_PERMITTED && ctx.state == PSA_FWU_FAILED,
          "WT-FWU-0003 finish rejects a candidate the floor now outranks");

    /* Empty candidate cannot be finished. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 0u);
    (void)wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 1u);
    check(wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) ==
              PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0003 finishing an empty candidate is refused");

    /* A storage failure fails the candidate; it can never arm. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 0u);
    mem.fail_write = 1;
    (void)wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 1u);
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block, 16u) ==
              PSA_ERROR_STORAGE_FAILURE && ctx.state == PSA_FWU_FAILED,
          "WT-FWU-0003 a failed program marks the candidate FAILED");
    check(wt_fwu_clean(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS &&
              ctx.state == PSA_FWU_READY,
          "WT-FWU-0003 clean recovers a FAILED candidate to READY");

    /* An arm failure leaves the candidate un-armed, not staged. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 0u);
    mem.fail_arm = 1;
    (void)wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 2u);
    (void)wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block, 16u);
    (void)wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY);
    check(wt_fwu_install(&ctx) == PSA_ERROR_STORAGE_FAILURE &&
              ctx.state == PSA_FWU_CANDIDATE && mem.armed == 0u,
          "WT-FWU-0003 a failed arm leaves the candidate un-armed");
}

static void test_unaligned_write(void)
{
    wt_fwu_backend_t backend;
    mock_backend_t mem;
    wt_fwu_service_ctx_t ctx;
    psa_fwu_component_info_t info;
    uint8_t block[17];
    size_t i;
    int tail_erased = 1;

    (void)memset(block, 0xA5, sizeof(block));
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 0u);
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 1u) == PSA_SUCCESS,
          "WT-FWU-0002 starts a padded candidate");
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
                       sizeof(block)) == PSA_SUCCESS &&
              mem.write_calls == 2u && ctx.write_high == sizeof(block) &&
              memcmp(mem.image, block, sizeof(block)) == 0,
          "WT-FWU-0002 padded write keeps the logical staged size");
    for (i = sizeof(block); i < 2u * MOCK_ALIGN; i++) {
        if (mem.image[i] != 0xFFu) {
            tail_erased = 0;
        }
    }
    check(tail_erased, "WT-FWU-0002 padded tail stays erased");
    check(wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS &&
              wt_fwu_query(&ctx, WT_FWU_COMPONENT_PRIMARY, &info) ==
                  PSA_SUCCESS && info.impl.staged_size == sizeof(block),
          "WT-FWU-0002 candidate excludes physical padding");

    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 0u);
    (void)wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 1u);
    mem.fail_write_call = 2u;
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
                       sizeof(block)) == PSA_ERROR_STORAGE_FAILURE &&
              mem.write_calls == 2u && ctx.state == PSA_FWU_FAILED &&
              ctx.write_high == 0u,
          "WT-FWU-0003 failed padded tail invalidates the candidate");

    mock_backend_init(&backend, &mem);
    backend.capacity = MOCK_CAPACITY - 1u;
    ctx_init(&ctx, &backend, &mem, 0u);
    (void)wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 1u);
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY,
                       MOCK_CAPACITY - MOCK_ALIGN, block,
                       MOCK_ALIGN - 1u) == PSA_ERROR_INVALID_ARGUMENT &&
              mem.write_calls == 0u && ctx.state == PSA_FWU_WRITING,
          "WT-FWU-0003 physical padding cannot exceed capacity");
}

/* --- Layer 2: the FF-M IPC round trip. --- */
static const wt_service_descriptor_t g_fwu_services[] = {
    {
        "SERVICE_FWU", TEST_FWU_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_FWU", TEST_FWU_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_fwu_services, 1U, NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "fwu-service-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

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
    (void)runtime;
    (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

static const wt_ffm_port_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    test_dispatch,
    test_panic
};

static psa_status_t fwu_call(wt_ffm_runtime_t* runtime, psa_handle_t handle,
                             int32_t op, uint32_t offset, uint32_t size,
                             uint32_t version, const void* data, size_t len,
                             void* out, size_t out_cap)
{
    uint8_t buffer[sizeof(wt_fwu_req_t) + 256U];
    wt_fwu_req_t req;
    psa_invec in_vec[1];
    psa_outvec out_vec[1];

    if (len > 256U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memset(&req, 0, sizeof(req));
    req.component = WT_FWU_COMPONENT_PRIMARY;
    req.offset = offset;
    req.size = size;
    req.version = version;
    (void)memcpy(buffer, &req, sizeof(req));
    if (data != NULL && len > 0U) {
        (void)memcpy(buffer + sizeof(req), data, len);
    }
    in_vec[0].base = buffer;
    in_vec[0].len = sizeof(req) + len;
    if (out != NULL) {
        out_vec[0].base = out;
        out_vec[0].len = out_cap;
        return wt_ffm_call(runtime, TEST_NS_GUEST0, handle, op, in_vec, 1U,
                           out_vec, 1U);
    }
    return wt_ffm_call(runtime, TEST_NS_GUEST0, handle, op, in_vec, 1U,
                       NULL, 0U);
}

static void test_ipc_round_trip(void)
{
    wt_fwu_backend_t backend;
    mock_backend_t mem;
    wt_fwu_service_ctx_t fwu_ctx;
    wt_ffm_runtime_t runtime;
    psa_fwu_component_info_t info;
    psa_handle_t handle;
    uint8_t blk0[32];
    uint8_t blk1[32];
    psa_status_t status;

    (void)memset(blk0, 0x11, sizeof(blk0));
    (void)memset(blk1, 0x22, sizeof(blk1));

    mock_backend_init(&backend, &mem);
    ctx_init(&fwu_ctx, &backend, &mem, 3u);

    if (wt_ffm_init(&runtime, &g_manifest, &g_port_ops, NULL) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "wt_ffm_init failed\n");
        g_failures++;
        return;
    }
    if (wt_ffm_register_partition(&runtime, TEST_FWU_PARTITION,
                                  wt_fwu_service_dispatch, &fwu_ctx) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "FWU register failed\n");
        g_failures++;
        return;
    }

    handle = wt_ffm_connect(&runtime, TEST_NS_GUEST0, TEST_FWU_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle),
          "WT-FWU-0001 NS client connects to SERVICE_FWU through the gate");
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return;
    }

    /* A write before start is refused over IPC with no partial effect. */
    status = fwu_call(&runtime, handle, WT_FWU_OP_WRITE, 0u, 32u, 0u, blk0,
                      sizeof(blk0), NULL, 0U);
    check(status == PSA_ERROR_BAD_STATE && mem.begin_calls == 0u,
          "WT-FWU-0003 IPC write before start is refused, nothing staged");

    /* A reboot without an armed STAGED candidate must never reach the
     * platform reset. */
    status = fwu_call(&runtime, handle, WT_FWU_OP_REBOOT, 0u, 0u, 0u, NULL,
                      0U, NULL, 0U);
    check(status == PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 reboot from READY is refused");

    /* A peer's doorbell is absorbed by the dispatcher, never handed to
     * psa_get where it would be a must-panic programmer error, and the
     * service keeps serving afterwards. */
    check(wt_ffm_notify(&runtime, TEST_FWU_PARTITION) == WT_FFM_SUCCESS,
          "WT-FFM-0031 doorbell asserted on the FWU partition");
    check(wt_fwu_service_dispatch(&fwu_ctx, &runtime, TEST_FWU_PARTITION) ==
              WT_FFM_SUCCESS,
          "WT-FFM-0031 dispatcher absorbs the doorbell without a panic");

    (void)memset(&info, 0, sizeof(info));
    status = fwu_call(&runtime, handle, WT_FWU_OP_QUERY, 0u, 0u, 0u, NULL, 0U,
                      &info, sizeof(info));
    check(status == PSA_SUCCESS && info.state == PSA_FWU_READY,
          "WT-FWU-0001 IPC query returns READY");

    status = fwu_call(&runtime, handle, WT_FWU_OP_START, 0u, 0u, 7u, NULL, 0U,
                      NULL, 0U);
    check(status == PSA_SUCCESS && mem.begin_calls == 1u,
          "WT-FWU-0002 IPC start erases the update partition");

    status = fwu_call(&runtime, handle, WT_FWU_OP_WRITE, 0u, 32u, 0u, blk0,
                      sizeof(blk0), NULL, 0U);
    check(status == PSA_SUCCESS,
          "WT-FWU-0002 IPC write stages the first block");
    status = fwu_call(&runtime, handle, WT_FWU_OP_WRITE, 32u, 16u, 0u, blk1,
                      sizeof(blk1), NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT && mem.image[32] != 0x22,
          "WT-FWU-0003 declared size below the vector tail is refused");
    status = fwu_call(&runtime, handle, WT_FWU_OP_WRITE, 32u, 48u, 0u, blk1,
                      sizeof(blk1), NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT && mem.image[32] != 0x22,
          "WT-FWU-0003 declared size above the vector tail is refused");
    status = fwu_call(&runtime, handle, WT_FWU_OP_REBOOT, 0u, 0u, 0u, NULL,
                      0U, NULL, 0U);
    check(status == PSA_ERROR_BAD_STATE,
          "WT-FWU-0003 reboot while WRITING is refused");
    status = fwu_call(&runtime, handle, WT_FWU_OP_WRITE, 32u, 32u, 0u, blk1,
                      sizeof(blk1), NULL, 0U);
    check(status == PSA_SUCCESS && mem.image[0] == 0x11 && mem.image[32] ==
              0x22,
          "WT-FWU-0002 IPC write stages the second block into flash");

    status = fwu_call(&runtime, handle, WT_FWU_OP_FINISH, 0u, 0u, 0u, NULL,
                      0U, NULL, 0U);
    check(status == PSA_SUCCESS, "WT-FWU-0002 IPC finish accepts the candidate");

    status = fwu_call(&runtime, handle, WT_FWU_OP_INSTALL, 0u, 0u, 0u, NULL,
                      0U, NULL, 0U);
    check(status == PSA_SUCCESS_REBOOT && mem.armed == 1u &&
              mem.armed_size == 64u && mem.armed_version == 7u,
          "WT-FWU-0002 IPC install arms the swap and returns SUCCESS_REBOOT");

    (void)memset(&info, 0, sizeof(info));
    status = fwu_call(&runtime, handle, WT_FWU_OP_QUERY, 0u, 0u, 0u, NULL, 0U,
                      &info, sizeof(info));
    check(status == PSA_SUCCESS && info.state == PSA_FWU_STAGED,
          "WT-FWU-0001 IPC query reports STAGED after install");

    /* A timed-out owner cannot be reclaimed while disarming the pending
     * update fails. A later retry can safely return the service to READY. */
    fwu_ctx.owner = 42;
    fwu_ctx.owner_tick = (uint32_t)(0U - WT_FWU_OWNER_IDLE_TIMEOUT_TICKS);
    mem.fail_disarm = 1;
    status = fwu_call(&runtime, handle, WT_FWU_OP_QUERY, 0u, 0u, 0u, NULL, 0U,
                      &info, sizeof(info));
    check(status == PSA_ERROR_STORAGE_FAILURE && fwu_ctx.armed == 1u &&
              mem.armed == 1u && fwu_ctx.owner == 42 &&
              fwu_ctx.state == PSA_FWU_STAGED,
          "WT-FWU-0003 failed disarm preserves the staged update and owner");
    mem.fail_disarm = 0;
    status = fwu_call(&runtime, handle, WT_FWU_OP_QUERY, 0u, 0u, 0u, NULL, 0U,
                      &info, sizeof(info));
    check(status == PSA_SUCCESS && info.state == PSA_FWU_READY &&
              mem.armed == 0u && fwu_ctx.owner == 0,
          "WT-FWU-0003 disarm retry reclaims the staged update");
}

/* WT-FWU-0002: the wolfBoot update trigger the FWU backend arms into the
 * UPDATE-partition trailer must be byte-exact, or wolfBoot will not detect the
 * pending update and the swap never happens. */
static void test_wolfboot_arm_trailer(void)
{
    uint8_t block[16];
    uint32_t magic;
    int i;
    int flags_erased;

    memset(block, 0x00, sizeof(block));
    check(wt_fwu_wolfboot_arm_trailer(block, sizeof(block)) == 0,
          "WT-FWU-0002 wolfBoot arm-trailer encodes");
    /* State byte IMG_STATE_UPDATING sits at partition_end-5 (index len-5). */
    check(block[sizeof(block) - 5u] == WT_WOLFBOOT_IMG_STATE_UPDATING,
          "WT-FWU-0002 trailer state = IMG_STATE_UPDATING (0x70)");
    memcpy(&magic, &block[sizeof(block) - 4u], sizeof(magic));
    check(magic == WT_WOLFBOOT_MAGIC_TRAIL,
          "WT-FWU-0002 trailer magic word = WOLFBOOT_MAGIC_TRAIL");
    check(block[sizeof(block) - 4u] == 0x42u &&
          block[sizeof(block) - 3u] == 0x4Fu &&
          block[sizeof(block) - 2u] == 0x4Fu &&
          block[sizeof(block) - 1u] == 0x54u,
          "WT-FWU-0002 trailer magic is little-endian 'BOOT'");
    flags_erased = 1;
    for (i = 0; i < (int)sizeof(block) - 5; i++) {
        if (block[i] != 0xFFu) {
            flags_erased = 0;
        }
    }
    check(flags_erased, "WT-FWU-0002 flag region left erased (0xFF)");
    check(wt_fwu_wolfboot_arm_trailer(NULL, sizeof(block)) == -1,
          "WT-FWU-0002 arm-trailer rejects NULL");
    check(wt_fwu_wolfboot_arm_trailer(block, 4u) == -1,
          "WT-FWU-0002 arm-trailer rejects an undersized block");
}

/* WT-FWU-0003: FINISH binds the declared candidate version to the staged
 * header and refuses a malformed or contradicting candidate before arm. */
static void test_staged_header_binding(void)
{
    wt_fwu_backend_t backend;
    mock_backend_t mem;
    wt_fwu_service_ctx_t ctx;
    uint8_t block[32];

    (void)memset(block, 0x5A, sizeof(block));
    mock_backend_init(&backend, &mem);
    backend.verify = mock_verify;
    ctx_init(&ctx, &backend, &mem, 3u);

    /* Header version below the declared one: refused, FAILED, never armed. */
    mem.header_version = 4u;
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u) == PSA_SUCCESS,
          "WT-FWU-0003 binding: start accepts version 5");
    check(wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
              sizeof(block)) == PSA_SUCCESS,
          "WT-FWU-0003 binding: block stages");
    check(wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) ==
              PSA_ERROR_NOT_PERMITTED && ctx.state == PSA_FWU_FAILED &&
              mem.armed == 0u,
          "WT-FWU-0003 header version contradicting the declared one fails");
    check(wt_fwu_clean(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS,
          "WT-FWU-0003 binding: clean recovers");

    /* An unparseable staged image never becomes CANDIDATE. */
    mem.fail_verify = 1;
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u) == PSA_SUCCESS &&
              wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
                  sizeof(block)) == PSA_SUCCESS &&
              wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) ==
                  PSA_ERROR_INVALID_ARGUMENT &&
              ctx.state == PSA_FWU_FAILED && mem.armed == 0u,
          "WT-FWU-0003 malformed staged image fails FINISH");
    check(wt_fwu_clean(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS,
          "WT-FWU-0003 binding: clean recovers again");

    /* A matching header version proceeds to CANDIDATE and arms. */
    mem.fail_verify = 0;
    mem.header_version = 5u;
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY, 5u) == PSA_SUCCESS &&
              wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
                  sizeof(block)) == PSA_SUCCESS &&
              wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS &&
              wt_fwu_install(&ctx) == PSA_SUCCESS_REBOOT &&
              mem.armed == 1u && mem.armed_version == 5u,
          "WT-FWU-0003 matching header version stages and arms");

    /* PSA FWU 1.0 no-manifest form: the version is adopted from the header. */
    mock_backend_init(&backend, &mem);
    backend.verify = mock_verify;
    ctx_init(&ctx, &backend, &mem, 3u);
    mem.header_version = 7u;
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY,
              WT_FWU_VERSION_UNDECLARED) == PSA_SUCCESS &&
              wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
                  sizeof(block)) == PSA_SUCCESS &&
              wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) == PSA_SUCCESS &&
              ctx.candidate_version == 7u &&
              wt_fwu_install(&ctx) == PSA_SUCCESS_REBOOT &&
              mem.armed == 1u && mem.armed_version == 7u,
          "WT-FWU-0003 undeclared version binds from the header and arms");

    /* The adopted header version is still subject to anti-rollback. */
    mock_backend_init(&backend, &mem);
    backend.verify = mock_verify;
    ctx_init(&ctx, &backend, &mem, 3u);
    mem.header_version = 2u;
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY,
              WT_FWU_VERSION_UNDECLARED) == PSA_SUCCESS &&
              wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
                  sizeof(block)) == PSA_SUCCESS &&
              wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) ==
                  PSA_ERROR_NOT_PERMITTED &&
              ctx.state == PSA_FWU_FAILED && mem.armed == 0u,
          "WT-FWU-0003 adopted header version below the floor is refused");

    /* Without a header parser an undeclared version cannot be bound. */
    mock_backend_init(&backend, &mem);
    ctx_init(&ctx, &backend, &mem, 0u);
    check(wt_fwu_start(&ctx, WT_FWU_COMPONENT_PRIMARY,
              WT_FWU_VERSION_UNDECLARED) == PSA_SUCCESS &&
              wt_fwu_write(&ctx, WT_FWU_COMPONENT_PRIMARY, 0u, block,
                  sizeof(block)) == PSA_SUCCESS &&
              wt_fwu_finish(&ctx, WT_FWU_COMPONENT_PRIMARY) ==
                  PSA_ERROR_NOT_PERMITTED &&
              ctx.state == PSA_FWU_FAILED && mem.armed == 0u,
          "WT-FWU-0003 undeclared version fails closed without a parser");
}

/* WT-FWU DoS guard: an owner idle past the timeout is reclaimable by a
 * different client; an active or same-client owner never is. */
static void test_owner_timeout(void)
{
    uint32_t t = WT_FWU_OWNER_IDLE_TIMEOUT_TICKS;

    check(wt_fwu_owner_expired(0, 100u, 100u + t + 5u, 7) == 0,
          "no owner is never reclaimed");
    check(wt_fwu_owner_expired(7, 100u, 100u + t + 5u, 7) == 0,
          "the owner itself never expires its own session");
    check(wt_fwu_owner_expired(7, 100u, 100u + t - 1u, 9) == 0,
          "a different client cannot reclaim before the timeout");
    check(wt_fwu_owner_expired(7, 100u, 100u + t, 9) == 1,
          "a different client reclaims an owner idle past the timeout");
    check(wt_fwu_owner_expired(7, 0xFFFFFFF0u,
                               (uint32_t)(0xFFFFFFF0u + t), 9) == 1,
          "timeout comparison is correct across tick wrap-around");
}

int main(void)
{
    test_state_machine();
    test_unaligned_write();
    test_ipc_round_trip();
    test_wolfboot_arm_trailer();
    test_staged_header_binding();
    test_owner_timeout();

    if (g_failures == 0) {
        (void)printf("SERVICE_FWU host suite: all checks passed\n");
        return 0;
    }
    (void)printf("SERVICE_FWU host suite: %d failure(s)\n", g_failures);
    return 1;
}
