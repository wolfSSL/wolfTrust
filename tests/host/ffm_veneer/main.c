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

/* Host proof for the MP4 S4 extraction (WT-FFM-0012): the neutral FF-M boot
 * core validates every NS memory window through the PORT-INSTALLED memcheck
 * seam (wt_ffm_boot_set_memcheck) and FAILS CLOSED when none is installed.
 * Drives the same wt_ffm_connect/wt_ffm_call path the Armv8-M
 * WolfTrust_FFM_* veneers use (via wt_ffm_boot_runtime_mut), with a counting
 * host memcheck standing in for the CMSE checker. */

#include "wolftrust/ffm_boot.h"
#include "wolftrust/spm_sched.h"
#include "wolftrust/services/hsm_relay.h"
#include "psa_manifest/pid.h"

#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/sha256.h>

#define TEST_HSM_SID    4102U
#define TEST_NS_CLIENT  (-1)

static int g_panics;
static int g_reads_seen;
static int g_writes_seen;
static wt_guest_id_t g_last_guest;

/* ---- platform stub for the symbol the neutral boot core needs ---- */
void wt_platform_panic(void)
{
    g_panics++;
}

/* Scheduler stubs: wt_ffm_boot_start_sched is not exercised here. */
int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg)
{
    (void)runtime; (void)partition_id; (void)entry; (void)arg;
    return WT_FFM_SUCCESS;
}

static int g_validate_calls;
static int g_start_all_calls;
static int g_start_all_after_validate;
static int g_start_all_ret;

int wt_spm_sched_validate(void)
{
    g_validate_calls++;
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_start_all(void)
{
    g_start_all_calls++;
    g_start_all_after_validate = (g_validate_calls > 0);
    return g_start_all_ret;
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

/* ---- the host memcheck standing in for the Armv8-M CMSE checker ---- */
static int test_ns_check_read(wt_guest_id_t guest_id, const void* address,
                              size_t size)
{
    g_reads_seen++;
    g_last_guest = guest_id;
    return size == 0U || address != NULL;
}

static int test_ns_check_write(wt_guest_id_t guest_id, void* address,
                               size_t size)
{
    g_writes_seen++;
    g_last_guest = guest_id;
    return size == 0U || address != NULL;
}

/* ---- SHA-256 submit hook: hashing the relayed request packet keeps the
 * KAT round trip byte-exact without a wolfHSM server in this fixture ---- */
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

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_HSM", PARTITION_HSM_ID, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "ffm-veneer-test",
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
    wt_ffm_runtime_t* rt;
    psa_handle_t handle;
    uint8_t digest[32];
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t status;

    check(wt_ffm_boot_init(&g_manifest) == WT_FFM_SUCCESS,
          "WT-FFM-0012 boot core initializes from the manifest");

    rt = wt_ffm_boot_runtime_mut();
    check(rt != NULL && rt == (wt_ffm_runtime_t*)wt_ffm_boot_runtime(),
          "runtime_mut exposes the boot runtime to the port veneers");

    /* The boot core seats the SERVICE_HSM relay on this partition; the
     * SHA submit hook completes the fixture's round trip. */
    wt_hsm_relay_set_submit(test_sha_submit, NULL);

    /* Fail-closed default: no memcheck installed, so an NS call with real
     * vectors must be rejected before any service work happens. */
    handle = wt_ffm_connect(rt, TEST_NS_CLIENT, TEST_HSM_SID, 1U);
    check(handle > 0, "NS client connects to SERVICE_HSM");

    in_vec.base = input;
    in_vec.len = sizeof(input) - 1U;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    memset(digest, 0, sizeof(digest));
    status = wt_ffm_call(rt, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         &in_vec, 1U, &out_vec, 1U);
    check(status != PSA_SUCCESS,
          "WT-FFM-0012 NS window REJECTED while no port memcheck installed");

    /* Install the host memcheck (the port seam) and prove the full round
     * trip: connect, call, digest KAT, caller resolved to guest 0. */
    wt_ffm_boot_set_memcheck(test_ns_check_read, test_ns_check_write);
    (void)wt_ffm_close(rt, TEST_NS_CLIENT, handle);
    handle = wt_ffm_connect(rt, TEST_NS_CLIENT, TEST_HSM_SID, 1U);
    check(handle > 0, "NS client reconnects after memcheck install");

    memset(digest, 0, sizeof(digest));
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    status = wt_ffm_call(rt, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         &in_vec, 1U, &out_vec, 1U);
    check(status == PSA_SUCCESS,
          "WT-FFM-0012 NS call succeeds through the installed memcheck");
    check(memcmp(digest, expected, sizeof(expected)) == 0,
          "mediated SHA-256 KAT digest matches");
    check(g_reads_seen > 0 && g_writes_seen > 0,
          "installed read+write checks actually gated the vectors");
    check(g_last_guest == (wt_guest_id_t)0,
          "NS caller -1 resolves to guest 0 for the port memcheck");
    (void)wt_ffm_close(rt, TEST_NS_CLIENT, handle);

    /* Clearing the seam restores fail-closed. */
    wt_ffm_boot_set_memcheck(NULL, NULL);
    handle = wt_ffm_connect(rt, TEST_NS_CLIENT, TEST_HSM_SID, 1U);
    status = wt_ffm_call(rt, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         &in_vec, 1U, &out_vec, 1U);
    check(status != PSA_SUCCESS,
          "WT-FFM-0012 clearing the memcheck seam fails closed again");

    /* FF-M start-up order: every partition runs to idle after the isolation
     * check and before the NSPE starts; a partition that cannot refuses boot. */
    g_validate_calls = 0;
    g_start_all_calls = 0;
    g_start_all_ret = WT_FFM_SUCCESS;
    check(wt_ffm_boot_start_sched() == WT_FFM_SUCCESS &&
              g_start_all_calls == 1 && g_start_all_after_validate,
          "WT-FFM-0013 boot runs every partition to idle after validation");
    g_start_all_calls = 0;
    g_start_all_ret = WT_FFM_ERROR_STATE;
    check(wt_ffm_boot_start_sched() == WT_FFM_ERROR_STATE &&
              g_start_all_calls == 1,
          "WT-FFM-0013 a partition that cannot reach idle refuses the boot");

    if (g_failures == 0) {
        printf("PASS: ffm_veneer (extracted NS gateway core)\n");
        return 0;
    }
    printf("FAIL: ffm_veneer (%d failures)\n", g_failures);
    return 1;
}
