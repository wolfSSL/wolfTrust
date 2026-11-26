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

/* Host proof that Initial Attestation is reachable through real FF-M IPC:
 * wt_attestation_service_dispatch carries a challenge in and a token out over
 * a genuine psa_connect/psa_call round trip. The dispatch now drives every
 * wait/get/read/write/reply through the SPM transport seam (the same code path
 * the scheduled Secure Partition uses on target), exercised here with the
 * default direct transport. The token backend (wt_initial_attest_get_token) is
 * stubbed here -- its real HSM/COSE-backed implementation is proven on M33MU --
 * so this suite isolates the IPC routing: challenge delivery, caller-identity
 * derivation, and token return. */

#include "spm_host.h"
#include "wolftrust/ffm.h"
#include "wolftrust/services/attestation_service.h"
#include "wolftrust/services/initial_attestation.h"

#include <stdio.h>
#include <string.h>

#define TEST_ATTEST_PARTITION 3
#define TEST_ATTEST_SID       4096U
#define TEST_ATTEST_SIGNAL    0x10U
#define TEST_NS_CLIENT        (-1)

static const uint8_t g_expected_challenge[WT_ATTEST_CHALLENGE_SIZE_32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const uint8_t g_stub_token[] = {
    'W', 'T', '-', 'A', 'T', 'T', 'E', 'S', 'T', '-', 'T', 'O', 'K', 'E', 'N'
};

/* Stub backend: asserts the dispatch delivered the exact challenge and the
 * NS caller's derived guest id, then returns a fixed token. */
int wt_initial_attest_get_token(wt_guest_id_t guestId,
    const uint8_t* challenge, size_t challengeSize, uint8_t* token,
    size_t tokenCapacity, size_t* tokenSize)
{
    if (guestId != 0 || challenge == NULL || token == NULL ||
            tokenSize == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    if (challengeSize != WT_ATTEST_CHALLENGE_SIZE_32 ||
            memcmp(challenge, g_expected_challenge,
                   WT_ATTEST_CHALLENGE_SIZE_32) != 0) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    if (tokenCapacity < sizeof(g_stub_token)) {
        return WT_ATTEST_ERROR_BUFFER_TOO_SMALL;
    }
    (void)memcpy(token, g_stub_token, sizeof(g_stub_token));
    *tokenSize = sizeof(g_stub_token);
    return WT_ATTEST_SUCCESS;
}

int wt_initial_attest_get_token_size(size_t challengeSize, size_t* tokenSize)
{
    if (tokenSize == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    if (challengeSize != WT_ATTEST_CHALLENGE_SIZE_32 &&
            challengeSize != WT_ATTEST_CHALLENGE_SIZE_48 &&
            challengeSize != WT_ATTEST_CHALLENGE_SIZE_64) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    *tokenSize = sizeof(g_stub_token);
    return WT_ATTEST_SUCCESS;
}

int wt_initial_attest_get_iak_public_key(uint8_t* publicKey,
    size_t publicKeyCapacity, size_t* publicKeySize)
{
    size_t i;

    if (publicKey == NULL || publicKeySize == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    if (publicKeyCapacity < WT_ATTEST_IAK_PUBLIC_KEY_SIZE) {
        return WT_ATTEST_ERROR_BUFFER_TOO_SMALL;
    }
    publicKey[0] = 0x04u;
    for (i = 1u; i < WT_ATTEST_IAK_PUBLIC_KEY_SIZE; i++) {
        publicKey[i] = (uint8_t)i;
    }
    *publicKeySize = WT_ATTEST_IAK_PUBLIC_KEY_SIZE;
    return WT_ATTEST_SUCCESS;
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

static void test_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
}

static const wt_spm_host_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    wt_attestation_service_dispatch,
    test_panic
};

static const wt_service_descriptor_t g_services[] = {
    {
        "SERVICE_ATTEST", TEST_ATTEST_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        TEST_ATTEST_SIGNAL, 0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_ATTEST", TEST_ATTEST_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_services, sizeof(g_services) / sizeof(g_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "attestation-service-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

int main(void)
{
    psa_handle_t handle;
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t public_key[WT_ATTEST_IAK_PUBLIC_KEY_SIZE];
    uint32_t challenge32 = WT_ATTEST_CHALLENGE_SIZE_32;
    uint32_t token32 = 0u;
    psa_invec in_vec = { g_expected_challenge, sizeof(g_expected_challenge) };
    psa_outvec out_vec = { token, sizeof(token) };
    psa_invec size_in = { &challenge32, sizeof(challenge32) };
    psa_outvec size_out = { &token32, sizeof(token32) };
    psa_outvec key_out = { public_key, sizeof(public_key) };
    psa_outvec short_out = { token, 0U };
    psa_status_t status;

    if (wt_spm_host_init(&g_manifest, &g_port_ops, NULL) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "wt_ffm_init failed\n");
        return 1;
    }

    /* Pin the dispatch to the direct transport seam explicitly; NULL would
     * restore the same default. On target this becomes the SVC transport. */
    wt_attestation_service_set_transport(wt_spm_transport_direct);

    handle = wt_spm_host_connect(TEST_NS_CLIENT, TEST_ATTEST_SID, 1U);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        (void)fprintf(stderr, "psa_connect(SERVICE_ATTEST) failed\n");
        return 1;
    }

    status = wt_spm_host_call(TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         &in_vec, 1U, &out_vec, 1U);
    if (status != PSA_SUCCESS) {
        (void)fprintf(stderr, "psa_call(SERVICE_ATTEST) failed st=%d\n",
                      (int)status);
        return 1;
    }
    if (out_vec.len != sizeof(g_stub_token) ||
            memcmp(token, g_stub_token, sizeof(g_stub_token)) != 0) {
        (void)fprintf(stderr, "attestation token mismatch through dispatch\n");
        return 1;
    }

    /* Mediated token-size query (WT_ATTEST_OP_TOKEN_SIZE): the retired
     * direct veneer's semantics, now through the SPM. */
    status = wt_spm_host_call(TEST_NS_CLIENT, handle,
                         WT_ATTEST_OP_TOKEN_SIZE, &size_in, 1U,
                         &size_out, 1U);
    if (status != PSA_SUCCESS || token32 != sizeof(g_stub_token)) {
        (void)fprintf(stderr, "token-size query failed st=%d size=%u\n",
                      (int)status, (unsigned)token32);
        return 1;
    }
    (void)printf("PASS: mediated token-size query\n");

    challenge32 = 33u;
    status = wt_spm_host_call(TEST_NS_CLIENT, handle,
                         WT_ATTEST_OP_TOKEN_SIZE, &size_in, 1U,
                         &size_out, 1U);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        (void)fprintf(stderr, "bad challenge size not refused st=%d\n",
                      (int)status);
        return 1;
    }
    (void)printf("PASS: mediated token-size query refuses a bad size\n");

    /* Mediated IAK public-key query (WT_ATTEST_OP_PUBLIC_KEY). */
    (void)memset(public_key, 0, sizeof(public_key));
    status = wt_spm_host_call(TEST_NS_CLIENT, handle,
                         WT_ATTEST_OP_PUBLIC_KEY, NULL, 0U, &key_out, 1U);
    if (status != PSA_SUCCESS ||
            key_out.len != WT_ATTEST_IAK_PUBLIC_KEY_SIZE ||
            public_key[0] != 0x04u) {
        (void)fprintf(stderr, "public-key query failed st=%d len=%u\n",
                      (int)status, (unsigned)key_out.len);
        return 1;
    }
    (void)printf("PASS: mediated IAK public-key query\n");

    /* A token CALL whose output vector is shorter than the token must report
     * BUFFER_TOO_SMALL, not fault the partition into its panic trap: a short
     * out-vec previously reached wt_ffm_write and the gate mapped that to
     * must_panic, so a hostile guest could restart the attestation partition
     * (SEC review). The partition stays healthy for the next caller. */
    short_out.len = 0U;
    status = wt_spm_host_call(TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         &in_vec, 1U, &short_out, 1U);
    if (status != PSA_ERROR_BUFFER_TOO_SMALL) {
        (void)fprintf(stderr, "zero-length token out-vec not refused st=%d\n",
                      (int)status);
        return 1;
    }
    short_out.len = sizeof(g_stub_token) - 1U;
    status = wt_spm_host_call(TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         &in_vec, 1U, &short_out, 1U);
    if (status != PSA_ERROR_BUFFER_TOO_SMALL) {
        (void)fprintf(stderr, "short token out-vec not refused st=%d\n",
                      (int)status);
        return 1;
    }
    out_vec.base = token;
    out_vec.len = sizeof(token);
    status = wt_spm_host_call(TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         &in_vec, 1U, &out_vec, 1U);
    if (status != PSA_SUCCESS || out_vec.len != sizeof(g_stub_token)) {
        (void)fprintf(stderr,
                      "attestation partition unhealthy after short out-vec "
                      "st=%d\n", (int)status);
        return 1;
    }
    (void)printf("PASS: short attestation out-vec refused without panic\n");

    if (wt_spm_host_close(TEST_NS_CLIENT, handle) != WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "psa_close(SERVICE_ATTEST) failed\n");
        return 1;
    }

    (void)printf("PASS: SERVICE_ATTEST token through real FF-M dispatch\n");
    return 0;
}
