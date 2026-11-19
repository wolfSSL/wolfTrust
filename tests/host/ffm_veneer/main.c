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
#include "wolftrust/ffm_gateway.h"
#include "wolftrust/spm_sched.h"
#include "wolftrust/services/hsm_relay.h"
#include "psa_manifest/pid.h"

#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/sha256.h>

#define TEST_HSM_SID    4102U
#define TEST_NS_CLIENT  (-1)

static int g_panics;
static int g_reads_seen;
static int g_writes_seen;
static wt_guest_id_t g_last_guest;

/* ---- arch seam the NS gateway reads: the caller is always guest 0 ---- */
extern volatile uint32_t g_wt_ffm_call_trace;

uint32_t wt_arch_active_guest_id(void);
int wt_arch_ns_check_writable(const void* address, size_t size);

uint32_t wt_arch_active_guest_id(void)
{
    return 0U;
}

int wt_arch_ns_check_writable(const void* address, size_t size)
{
    return size == 0U || address != NULL;
}

/* Nested-entry seam: the relay submit runs mid-dispatch, standing in for a
 * Non-secure exception that re-enters the gateway during an in-flight call. */
static int g_nest_armed;
static int g_panic_armed;
static jmp_buf g_panic_jmp;
static wt_ffm_veneer_iovec_t g_nest_iovec;

static void test_nested_gateway_entry(void)
{
    g_nest_armed = 0;
    (void)memset(&g_nest_iovec, 0, sizeof(g_nest_iovec));
    (void)wt_ffm_gateway_call(1, PSA_IPC_CALL, &g_nest_iovec);
}

static size_t test_live_connections(const wt_ffm_runtime_t* rt)
{
    size_t i;
    size_t n = 0U;

    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        n += (rt->connections[i].allocated != 0U) ? 1U : 0U;
    }
    return n;
}

/* ---- platform stub for the symbol the neutral boot core needs ---- */
void wt_platform_panic(void)
{
    g_panics++;
    if (g_panic_armed != 0) {
        g_panic_armed = 0;
        longjmp(g_panic_jmp, 1);
    }
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

int wt_arch_ns_check_read(wt_guest_id_t guest_id, const void* address,
                          size_t size);
int wt_arch_ns_check_write(wt_guest_id_t guest_id, void* address,
                           size_t size);

int wt_arch_ns_check_read(wt_guest_id_t guest_id, const void* address,
                          size_t size)
{
    return test_ns_check_read(guest_id, address, size);
}

int wt_arch_ns_check_write(wt_guest_id_t guest_id, void* address, size_t size)
{
    return test_ns_check_write(guest_id, address, size);
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
    if (g_nest_armed != 0) {
        test_nested_gateway_entry();
    }
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
    wt_ffm_veneer_iovec_t iov;
    size_t live;
    int panics;
    int kind;

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

    /* One NS entry at a time. The port masks Non-secure exceptions for an
     * entry, so an entry that still arrives while another is in flight stops
     * the system before it reaches the core. */
    wt_ffm_gateway_install();
    handle = (psa_handle_t)wt_ffm_gateway_connect(TEST_HSM_SID, 1U);
    check(handle > 0 && rt->ns_entry_caller == 0,
          "NS client opens a gateway connection");
    (void)memset(&iov, 0, sizeof(iov));
    (void)memset(digest, 0, sizeof(digest));
    iov.in[0].base = input;
    iov.in[0].len = sizeof(input) - 1U;
    iov.in_count = 1U;
    iov.out[0].base = digest;
    iov.out[0].len = sizeof(digest);
    iov.out_count = 1U;
    check(wt_ffm_gateway_call((int32_t)handle, PSA_IPC_CALL, &iov) ==
              PSA_SUCCESS &&
          memcmp(digest, expected, sizeof(expected)) == 0 &&
          rt->ns_entry_caller == 0,
          "WT-FFM-0012 a gateway call completes and releases the entry");
    live = test_live_connections(rt);
    panics = g_panics;
    g_nest_armed = 1;
    g_panic_armed = 1;
    if (setjmp(g_panic_jmp) == 0) {
        (void)wt_ffm_gateway_call((int32_t)handle, PSA_IPC_CALL, &iov);
    }
    g_nest_armed = 0;
    g_panic_armed = 0;
    check(g_panics == panics + 1 && test_live_connections(rt) == live,
          "WT-FFM-0012 an entry nested in a call stops the system");
    for (kind = 0; kind < 3; kind++) {
        panics = g_panics;
        rt->ns_entry_caller = TEST_NS_CLIENT;
        g_panic_armed = 1;
        if (setjmp(g_panic_jmp) == 0) {
            if (kind == 0) {
                (void)wt_ffm_gateway_connect(TEST_HSM_SID, 1U);
            }
            else if (kind == 1) {
                (void)wt_ffm_gateway_call((int32_t)handle, PSA_IPC_CALL, &iov);
            }
            else {
                wt_ffm_gateway_close((int32_t)handle);
            }
        }
        g_panic_armed = 0;
        check(g_panics == panics + 1 && test_live_connections(rt) == live,
              "WT-FFM-0012 connect, call and close never enter beside an "
              "in-flight entry");
    }

    /* A guest restarted mid-call never returns through the gateway; its
     * abnormal-termination cleanup must release the entry. */
    rt->ns_entry_caller = TEST_NS_CLIENT;
    (void)wt_ffm_fail_client_connections(rt, TEST_NS_CLIENT);
    panics = g_panics;
    handle = (psa_handle_t)wt_ffm_gateway_connect(TEST_HSM_SID, 1U);
    check(rt->ns_entry_caller == 0 && handle > 0 && g_panics == panics,
          "WT-FFM-0026 client restart cleanup releases the gateway entry");
    wt_ffm_gateway_close((int32_t)handle);

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
