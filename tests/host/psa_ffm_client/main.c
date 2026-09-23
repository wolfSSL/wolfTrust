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

/* Host proof for the OS-neutral PSA FF-M client core (P7-S1). The real
 * WolfTrust_FFM_* veneers are Armv8-M CMSE code, so this test supplies host
 * stubs that route them to the in-process FF-M runtime the port drives, then
 * exercises psa_connect/psa_call/psa_close from src/client/psa_ffm_client.c
 * against the registered SERVICE_HSM relay — the production single mediated
 * door (WT-FFM-0054). It proves the neutral client marshals psa_invec/
 * psa_outvec into the veneer iovec, writes the outvec lengths back, and
 * reaches the service without any operating-system dependency; a SHA-256
 * submit hook keeps the KAT round trip byte-exact. */

#include "wolftrust/ffm_boot.h"
#include "wolftrust/spm_sched.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/fwu_service.h"
#include "psa/update.h"
#include "psa_manifest/sid.h"
#include "wolftrust/ffm_veneer.h"
#include "psa/client.h"
#include "wolftrust/static_assert.h"

/* The advertised public maximum must be deliverable: one marshalled request
 * (header + block) fits the IPC transfer budget exactly at the boundary. */
WT_STATIC_ASSERT(sizeof(wt_fwu_req_t) + PSA_FWU_MAX_WRITE_SIZE <=
               WT_FFM_TRANSFER_BYTES,
               "PSA_FWU_MAX_WRITE_SIZE exceeds the IPC transfer budget");
#include "psa_manifest/pid.h"
#include "psa_manifest/sid.h"

#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/sha256.h>

#define TEST_HSM_SID    4102U
#define TEST_FWU_PARTITION 8
#define TEST_NS_CLIENT  (-1)

/* ---- platform + scheduler stubs the neutral boot core needs ---- */
void wt_platform_panic(void)
{
}

int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg)
{
    (void)runtime; (void)partition_id; (void)entry; (void)arg;
    return WT_FFM_SUCCESS;
}

int wt_spm_hsm_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

int wt_spm_vault_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

int wt_spm_its_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

int wt_spm_ps_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

/* ---- host memcheck standing in for the Armv8-M CMSE checker ---- */
static int test_ns_check_read(wt_guest_id_t guest_id, const void* address,
                              size_t size)
{
    (void)guest_id;
    return size == 0U || address != NULL;
}

static int test_ns_check_write(wt_guest_id_t guest_id, void* address,
                               size_t size)
{
    (void)guest_id;
    return size == 0U || address != NULL;
}

/* ---- host stubs for the Armv8-M NS->S veneers: route to the runtime ---- */
int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version)
{
    return (int32_t)wt_ffm_connect(wt_ffm_boot_runtime_mut(),
                                   TEST_NS_CLIENT, sid, version);
}

void WolfTrust_FFM_Close(int32_t handle)
{
    (void)wt_ffm_close(wt_ffm_boot_runtime_mut(), TEST_NS_CLIENT, handle);
}

int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                           wt_ffm_veneer_iovec_t* iv)
{
    psa_invec in[WT_FFM_VENEER_IOVEC_MAX];
    psa_outvec out[WT_FFM_VENEER_IOVEC_MAX];
    psa_status_t st;
    uint32_t i;

    if (iv->in_count > WT_FFM_VENEER_IOVEC_MAX ||
            iv->out_count > WT_FFM_VENEER_IOVEC_MAX) {
        wt_ffm_call_refuse(wt_ffm_boot_runtime_mut(), TEST_NS_CLIENT, handle);
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    for (i = 0u; i < iv->in_count; i++) {
        in[i].base = iv->in[i].base;
        in[i].len = iv->in[i].len;
    }
    for (i = 0u; i < iv->out_count; i++) {
        out[i].base = iv->out[i].base;
        out[i].len = iv->out[i].len;
    }
    st = wt_ffm_call(wt_ffm_boot_runtime_mut(), TEST_NS_CLIENT, handle, type,
                     in, iv->in_count, out, iv->out_count);
    for (i = 0u; i < iv->out_count; i++) {
        iv->out[i].len = (uint32_t)out[i].len;
    }
    return (int32_t)st;
}

uint32_t WolfTrust_FFM_FrameworkVersion(void)
{
    return PSA_FRAMEWORK_VERSION;
}

uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid)
{
    (void)sid;
    return 1u;
}

/* ---- SHA-256 submit hook: the relay hands the copied request packet to the
 * platform submit seam; hashing it back keeps the KAT round trip byte-exact
 * without a wolfHSM server in this fixture ---- */
static int test_sha_submit(void* submit_ctx, int32_t client_id,
                           const uint8_t* req, size_t req_len,
                           uint8_t* resp, size_t resp_cap, size_t* resp_len)
{
    wc_Sha256 sha;
    int rc;

    (void)submit_ctx;
    (void)client_id;
    if (resp_cap < WC_SHA256_DIGEST_SIZE) {
        return -1;
    }
    rc = wc_InitSha256(&sha);
    if (rc == 0) {
        rc = wc_Sha256Update(&sha, req, (word32)req_len);
    }
    if (rc == 0) {
        rc = wc_Sha256Final(&sha, resp);
    }
    wc_Sha256Free(&sha);
    if (rc != 0) {
        return -1;
    }
    *resp_len = WC_SHA256_DIGEST_SIZE;
    return 0;
}

/* ---- manifest fixture: the relay partition as production declares it ---- */
static const wt_service_descriptor_t g_services[] = {
    {
        "SERVICE_HSM", TEST_HSM_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const wt_service_descriptor_t g_fwu_services[] = {
    {
        "SERVICE_FWU", SERVICE_FWU_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x20U, 0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_HSM", PARTITION_HSM_ID, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    },
    {
        "PARTITION_FWU", TEST_FWU_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_fwu_services, sizeof(g_fwu_services) / sizeof(g_fwu_services[0]),
        NULL, 0U, NULL, 0U
    }
};

/* RAM staging backend for the public PSA FWU client round trip. */
typedef struct fwu_mock {
    uint8_t image[4096];
    uint32_t armed;
} fwu_mock_t;

static fwu_mock_t g_fwu_mock;

static int fwu_mock_begin(void* ctx)
{
    (void)memset(((fwu_mock_t*)ctx)->image, 0xFF,
                 sizeof(((fwu_mock_t*)ctx)->image));
    return 0;
}

static int fwu_mock_write(void* ctx, uint32_t offset, const uint8_t* data,
                          uint32_t size)
{
    fwu_mock_t* m = (fwu_mock_t*)ctx;

    if (offset + size > sizeof(m->image)) {
        return -1;
    }
    (void)memcpy(m->image + offset, data, size);
    return 0;
}

static int fwu_mock_arm(void* ctx, uint32_t image_size, uint32_t version)
{
    (void)image_size;
    (void)version;
    ((fwu_mock_t*)ctx)->armed = 1U;
    return 0;
}

static int fwu_mock_disarm(void* ctx)
{
    ((fwu_mock_t*)ctx)->armed = 0U;
    return 0;
}

static const wt_fwu_backend_t g_fwu_backend = {
    fwu_mock_begin, fwu_mock_write, fwu_mock_arm, fwu_mock_disarm,
    4096U, 16U, NULL
};

static wt_fwu_service_ctx_t g_fwu_ctx;

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "psa-ffm-client-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

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

int main(void)
{
    /* SHA-256("wolfTrust FF-M SERVICE_CRYPTO dispatch test") */
    static const uint8_t input[] =
        "wolfTrust FF-M SERVICE_CRYPTO dispatch test";
    static const uint8_t expected[32] = {
        0x20, 0x03, 0xdf, 0x15, 0x2a, 0x52, 0x8a, 0x06,
        0xc8, 0xd3, 0x48, 0xb8, 0xfa, 0x8b, 0x2f, 0x87,
        0xf7, 0x1f, 0xae, 0xc6, 0x24, 0x6c, 0x7e, 0x72,
        0x8e, 0x27, 0xa4, 0xb5, 0x0a, 0x49, 0x84, 0x66
    };
    uint8_t digest[32];
    uint32_t fwu_manifest = 5U;
    uint8_t fwu_block[32];
    static uint8_t fwu_max_block[PSA_FWU_MAX_WRITE_SIZE];
    psa_fwu_component_info_t fwu_info;
    psa_handle_t handle;
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t status;

    check(wt_ffm_boot_init(&g_manifest) == WT_FFM_SUCCESS,
          "P7-S1 boot core initializes from the manifest");
    wt_ffm_boot_set_memcheck(test_ns_check_read, test_ns_check_write);

    check(wt_ffm_register_partition(wt_ffm_boot_runtime_mut(),
                                    PARTITION_HSM_ID,
                                    wt_hsm_relay_dispatch,
                                    NULL) == WT_FFM_SUCCESS,
          "relay partition registers as the mediated door");
    wt_hsm_relay_set_submit(test_sha_submit, NULL);

    check(psa_framework_version() == PSA_FRAMEWORK_VERSION,
          "P7-S1 psa_framework_version reports 0x0100 through the neutral core");

    handle = psa_connect(TEST_HSM_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle),
          "P7-S1 psa_connect(SERVICE_HSM) returns a valid handle");

    in_vec.base = input;
    in_vec.len = sizeof(input) - 1U;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    memset(digest, 0, sizeof(digest));
    status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1U, &out_vec, 1U);
    check(status == PSA_SUCCESS,
          "P7-S1 psa_call round trip through the neutral client succeeds");
    check(memcmp(digest, expected, sizeof(expected)) == 0,
          "P7-S1 mediated SHA-256 KAT digest matches");
    check(out_vec.len == sizeof(expected),
          "P7-S1 psa_call writes the produced outvec length back");
    psa_close(handle);

    /* An iovec count above PSA_MAX_IOVEC is a caller programmer error and must
     * be refused before any veneer call. */
    status = psa_call(handle, PSA_IPC_CALL, &in_vec, 5U, &out_vec, 1U);
    check(status == PSA_ERROR_PROGRAMMER_ERROR,
          "P7-S1 psa_call rejects an over-count invec (PROGRAMMER_ERROR)");

    /* ---- PSA FWU 1.0 through the public client (SRC-PSA-FWU) ---- */
    (void)memset(&g_fwu_ctx, 0, sizeof(g_fwu_ctx));
    g_fwu_ctx.transport = wt_spm_transport_direct;
    g_fwu_ctx.backend = &g_fwu_backend;
    g_fwu_ctx.backend_ctx = &g_fwu_mock;
    g_fwu_ctx.version_floor = 3U;
    g_fwu_ctx.active_version = 4U;
    check(wt_ffm_register_partition(wt_ffm_boot_runtime_mut(),
                                    TEST_FWU_PARTITION,
                                    wt_fwu_service_dispatch,
                                    &g_fwu_ctx) == WT_FFM_SUCCESS,
          "WT-FWU-0001 FWU partition registers its dispatch");
    (void)memset(fwu_block, 0x5A, sizeof(fwu_block));
    check(psa_fwu_query(0U, &fwu_info) == PSA_SUCCESS &&
              fwu_info.state == PSA_FWU_READY,
          "WT-FWU-0001 psa_fwu_query reports READY through the public API");
    check(psa_fwu_start(0U, &fwu_manifest, 2U) == PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0003 psa_fwu_start refuses a malformed manifest");
    check(psa_fwu_start(0U, &fwu_manifest, sizeof(fwu_manifest)) ==
              PSA_SUCCESS,
          "WT-FWU-0002 psa_fwu_start opens the candidate (version manifest)");
    check(psa_fwu_write(0U, 0U, fwu_block, sizeof(fwu_block)) == PSA_SUCCESS,
          "WT-FWU-0002 psa_fwu_write stages a block through the public API");
    check(psa_fwu_finish(0U) == PSA_SUCCESS,
          "WT-FWU-0002 psa_fwu_finish completes the candidate");
    check(psa_fwu_query(0U, &fwu_info) == PSA_SUCCESS &&
              fwu_info.state == PSA_FWU_CANDIDATE &&
              fwu_info.version.build == 4U &&
              fwu_info.impl.staged_size == sizeof(fwu_block),
          "WT-FWU-0001 query reports CANDIDATE, version, and staged size");
    check(psa_fwu_install() == PSA_SUCCESS_REBOOT && g_fwu_mock.armed == 1U,
          "WT-FWU-0002 psa_fwu_install arms the swap and asks for reboot");
    check(psa_fwu_reject(PSA_ERROR_GENERIC_ERROR) == PSA_SUCCESS &&
              g_fwu_mock.armed == 0U,
          "WT-FWU-0003 psa_fwu_reject disarms the staged swap");
    check(psa_fwu_query(0U, &fwu_info) == PSA_SUCCESS &&
              fwu_info.state == PSA_FWU_FAILED &&
              fwu_info.error == PSA_ERROR_GENERIC_ERROR,
          "WT-FWU-0001 query reports the rejected component error");
    check(psa_fwu_clean(0U) == PSA_SUCCESS,
          "WT-FWU-0003 psa_fwu_clean restores READY");
    check(psa_fwu_accept() == PSA_ERROR_NOT_SUPPORTED,
          "WT-FWU-0002 psa_fwu_accept reports the committed-install deviation");

    /* A block of exactly PSA_FWU_MAX_WRITE_SIZE traverses the IPC transfer
     * (header + block == budget); one byte more is refused client-side. */
    (void)memset(fwu_max_block, 0xA7, sizeof(fwu_max_block));
    check(psa_fwu_start(0U, &fwu_manifest, sizeof(fwu_manifest)) ==
              PSA_SUCCESS,
          "WT-FWU-0002 psa_fwu_start reopens the candidate for the max write");
    check(psa_fwu_write(0U, 0U, fwu_max_block, PSA_FWU_MAX_WRITE_SIZE) ==
              PSA_SUCCESS,
          "WT-FWU-0002 psa_fwu_write delivers the advertised maximum block");
    check(psa_fwu_write(0U, PSA_FWU_MAX_WRITE_SIZE, fwu_max_block,
                        PSA_FWU_MAX_WRITE_SIZE + 1U) ==
              PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0002 psa_fwu_write refuses a block above the maximum");
    check(psa_fwu_cancel(0U) == PSA_SUCCESS && psa_fwu_clean(0U) == PSA_SUCCESS,
          "WT-FWU-0003 max-write candidate cancels and cleans back to READY");

    /* PSA FWU 1.0 no-manifest form (NULL, 0) enters the state machine; this
     * mock has no header parser, so the unbound version fails closed at
     * finish rather than arming. A NULL manifest with a size is malformed. */
    check(psa_fwu_start(0U, NULL, sizeof(fwu_manifest)) ==
              PSA_ERROR_INVALID_ARGUMENT,
          "WT-FWU-0003 psa_fwu_start refuses a NULL manifest with a size");
    check(psa_fwu_start(0U, NULL, 0U) == PSA_SUCCESS,
          "WT-FWU-0002 psa_fwu_start accepts the no-manifest call form");
    check(psa_fwu_write(0U, 0U, fwu_block, sizeof(fwu_block)) == PSA_SUCCESS &&
              psa_fwu_finish(0U) == PSA_ERROR_NOT_PERMITTED,
          "WT-FWU-0003 unbound version fails closed without a header parser");
    check(psa_fwu_clean(0U) == PSA_SUCCESS,
          "WT-FWU-0003 no-manifest candidate cleans back to READY");

    /* Clearing the port memcheck seam fails closed. */
    wt_ffm_boot_set_memcheck(NULL, NULL);
    handle = psa_connect(TEST_HSM_SID, 1U);
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1U, &out_vec, 1U);
    check(status != PSA_SUCCESS,
          "P7-S1 clearing the port memcheck fails the NS call closed");

    if (g_failures == 0) {
        printf("PASS: psa_ffm_client (OS-neutral PSA FF-M client core)\n");
        return 0;
    }
    printf("FAIL: psa_ffm_client (%d failures)\n", g_failures);
    return 1;
}
