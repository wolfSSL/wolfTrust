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

/* WT-FFA-0012 / WT-FFM-0066: the operating-system-neutral PSA client
 * (src/client/psa_ffm_client.c, the one every Armv8-M guest links) over the
 * AArch64 FF-A binding of its WolfTrust_FFM_* entry points, through the SMC seam
 * into the SPMC front-end, into the neutral FF-M gateway and core - the same
 * gateway the CMSE veneers feed, so the same services answer. The host stands in
 * for the port's caller identity and Non-secure window. */

#include "psa/client.h"
#include "psa_manifest/pid.h"

#include "wolftrust/arch.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/psa_ffa.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/ffm_gateway.h"
#include "wolftrust/ffm_veneer.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/spm_sched.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/sha256.h>

#define TEST_HSM_SID 4102U

static int checks;
static int failures;

/* A panic anywhere in these rows is a failure: report it and end the run. */
void wt_platform_panic(void)
{
    printf("  [check] FAIL  the core panicked\n");
    exit(1);
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

/* The AArch64 port's caller identity and Non-secure window checks, host-side:
 * the primary guest is 0 and the window is whatever wt_spm_psa_init recorded. */
uint32_t wt_arch_active_guest_id(void)
{
    return 0u;
}

int wt_arch_ns_check_read(wt_guest_id_t guest_id, const void* address,
                          size_t size)
{
    return (guest_id == (wt_guest_id_t)0) &&
           wt_spm_ns_window_ok((uintptr_t)address, size);
}

int wt_arch_ns_check_write(wt_guest_id_t guest_id, void* address, size_t size)
{
    return (guest_id == (wt_guest_id_t)0) &&
           wt_spm_ns_window_ok((uintptr_t)address, size);
}

int wt_arch_ns_check_writable(const void* address, size_t size)
{
    return wt_spm_ns_window_ok((uintptr_t)address, size);
}

/* The SMC seam: a direct request to the PSA endpoint lands in the SPMC
 * front-end; anything else is refused as the SPMD would. */
void wt_ffa_transport_smc(wt_ffa_regs_t* r)
{
    if (((uint32_t)r->x[0] == WT_FFA_MSG_SEND_DIRECT_REQ32) &&
        (wt_ffa_direct_receiver(r->x[1]) == WT_FFA_ID_PSA)) {
        (void)wt_spm_psa_framework(r);
        return;
    }
    r->x[0] = WT_FFA_ERROR;
    r->x[2] = (uint64_t)(uint32_t)WT_FFA_NOT_SUPPORTED;
}

/* SHA-256 submit hook: hashing the relayed request keeps the KAT round trip
 * byte-exact without a wolfHSM server in this fixture. */
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
    .generator_version = "psa-ffa-transport-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

/* Drive one crafted Call through the SPMC front-end with the given vector block
 * address and handle; returns the psa_status_t the guest would see. */
static psa_status_t crafted_call(uint64_t block, psa_handle_t handle)
{
    wt_ffa_regs_t r;

    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_MSG_SEND_DIRECT_REQ32;
    r.x[1] = ((uint64_t)WT_FFA_ID_NS_PRIMARY << 16) | WT_FFA_ID_PSA;
    r.x[3] = WT_PSA_FFA_OP_CALL;
    r.x[4] = block;
    r.x[5] = ((uint64_t)(uint32_t)PSA_IPC_CALL << 32) | (uint64_t)(uint32_t)handle;
    (void)wt_spm_psa_framework(&r);
    return (psa_status_t)(int32_t)(uint32_t)r.x[3];
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
    static uint8_t area[1024] __attribute__((aligned(16)));
    wt_ffm_veneer_iovec_t* block;
    wt_ffm_veneer_iovec_t local;
    psa_handle_t handle;
    psa_handle_t refused;
    psa_handle_t again;
    uint8_t digest[32];
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t st;

    printf("WT-FFA-0012 / WT-FFM-0066 (PSA client over FF-A into the FF-M gateway)\n");

    check(wt_ffm_boot_init(&g_manifest) == WT_FFM_SUCCESS,
          "the neutral boot core initializes from the manifest");
    wt_ffm_gateway_install();
    wt_hsm_relay_set_submit(test_sha_submit, NULL);

    in_vec.base = input;
    in_vec.len = sizeof(input) - 1u;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);

    /* Fail closed: with no Non-secure window recorded, a data-carrying call is
     * refused before any vector is read. */
    wt_spm_psa_init(0u, 0u);
    handle = psa_connect(TEST_HSM_SID, 1u);
    check(PSA_HANDLE_IS_VALID(handle),
          "psa_connect over FF-A reaches the gateway and returns a core handle");
    st = psa_call(handle, PSA_IPC_CALL, &in_vec, 1u, &out_vec, 1u);
    check(st == PSA_ERROR_PROGRAMMER_ERROR,
          "with no Non-secure window recorded a call is refused (fail closed)");
    psa_close(handle);

    wt_spm_psa_init(0u, ~(uint64_t)0);
    check(psa_framework_version() == PSA_FRAMEWORK_VERSION,
          "psa_framework_version comes from the core over the transport");
    check(psa_version(TEST_HSM_SID) == 1u,
          "psa_version of SERVICE_HSM is 1 through the gateway");
    check(psa_version(0x9999u) == PSA_VERSION_NONE,
          "psa_version of an unknown service is PSA_VERSION_NONE");

    handle = psa_connect(TEST_HSM_SID, 1u);
    check(PSA_HANDLE_IS_VALID(handle), "psa_connect to SERVICE_HSM succeeds");
    refused = psa_connect(0x9999u, 1u);
    check(!PSA_HANDLE_IS_VALID(refused), "psa_connect to an unknown service is refused");

    memset(digest, 0, sizeof(digest));
    out_vec.len = sizeof(digest);
    st = psa_call(handle, PSA_IPC_CALL, &in_vec, 1u, &out_vec, 1u);
    check(st == PSA_SUCCESS && memcmp(digest, expected, sizeof(expected)) == 0,
          "psa_call round-trips client -> FF-A -> front-end -> gateway -> core -> relay: SHA-256 KAT matches");
    check(out_vec.len == sizeof(digest),
          "the out-vec length is written back through the guest's vector block");

    st = psa_call((psa_handle_t)0x7777, PSA_IPC_CALL, &in_vec, 1u, &out_vec, 1u);
    check(st == PSA_ERROR_PROGRAMMER_ERROR,
          "a call on a handle the core never issued is a PROGRAMMER_ERROR");

    psa_close(handle);
    again = psa_connect(TEST_HSM_SID, 1u);
    check(PSA_HANDLE_IS_VALID(again), "a closed connection can be reopened");
    psa_close(again);

    /* Window-bounded rejections: the block sits inside the window, one vector
     * does not; then the block itself is outside. */
    wt_spm_psa_init((uint64_t)(uintptr_t)area,
                    (uint64_t)(uintptr_t)area + (uint64_t)sizeof(area));
    handle = psa_connect(TEST_HSM_SID, 1u);
    check(PSA_HANDLE_IS_VALID(handle), "connect needs no vectors and succeeds under a bounded window");
    block = (wt_ffm_veneer_iovec_t*)(void*)&area[0];
    memset(block, 0, sizeof(*block));
    block->in[0].base = input;
    block->in[0].len = (uint32_t)(sizeof(input) - 1u);
    block->out[0].base = &area[512];
    block->out[0].len = 32u;
    block->in_count = 1u;
    block->out_count = 1u;
    check(crafted_call((uint64_t)(uintptr_t)block, handle) == PSA_ERROR_PROGRAMMER_ERROR,
          "an in-vec outside the Non-secure window is refused by the core's memcheck");
    handle = psa_connect(TEST_HSM_SID, 1u);
    memset(&local, 0, sizeof(local));
    local.in[0].base = &area[256];
    local.in[0].len = 8u;
    local.in_count = 1u;
    check(crafted_call((uint64_t)(uintptr_t)&local, handle) == PSA_ERROR_PROGRAMMER_ERROR,
          "a vector block outside the Non-secure window is refused before it is read");
    wt_spm_psa_init(0u, ~(uint64_t)0);

    printf("psa_ffa_transport: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
