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

/* The attestation partition's registered restart hook with an HMAC key
 * (WT_ATTEST_KEY=hmac): a restart wipes the partition's data band, key
 * included, and the hook must load the key again before tokens resume. */

#include <stdio.h>
#include <string.h>

/* The partition table and the token encoder are production; the scheduler
 * and the attestation dispatch loop are simulated. */
#include "../../../src/spm_partitions.c"
#include "../../../src/services/initial_attestation.c"

#include "mac0_check.h"

static wt_spm_sp_restore_fn g_restore;
static int32_t g_restore_id;
static int g_added;
static int g_failures;
static wt_boot_handoff_t g_handoff;
static int g_handoff_kept = 1;
static uint8_t g_port_key[WT_ATTEST_HMAC_KEY_SIZE];
static int g_port_key_fail;
static int g_port_key_calls;

int wt_port_attest_hmac_key(uint8_t* key, size_t keySize)
{
    g_port_key_calls++;
    if ((g_port_key_fail != 0) || (keySize != sizeof(g_port_key))) {
        return -1;
    }
    (void)memcpy(key, g_port_key, sizeof(g_port_key));
    return 0;
}

const struct wt_boot_handoff* wt_boot_handoff_retained(void)
{
    return (g_handoff_kept != 0) ? &g_handoff : NULL;
}

int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg)
{
    (void)runtime;
    (void)partition_id;
    (void)entry;
    (void)arg;
    g_added++;
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_set_restore(int32_t partition_id,
                             wt_spm_sp_restore_fn restore)
{
    g_restore_id = partition_id;
    g_restore = restore;
    return WT_FFM_SUCCESS;
}

int wt_spm_svc_transport(wt_ffm_runtime_t* runtime, struct wt_spm_call* call)
{
    (void)runtime;
    (void)call;
    return WT_FFM_ERROR_STATE;
}

void wt_attestation_service_set_transport(wt_spm_transport_fn transport)
{
    (void)transport;
}

int wt_attestation_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                    int32_t partition_id)
{
    (void)context;
    (void)runtime;
    (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

size_t wt_guest_measurement_count(void)
{
    return 0u;
}

const wt_guest_measurement_t* wt_guest_measurement_get(size_t index,
                                                       const char** name)
{
    (void)index;
    (void)name;
    return NULL;
}

static void check(int ok, const char* what)
{
    (void)printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

/* What the SPM does to the partition's data band before its restart hook. */
static void band_reset(void)
{
    (void)memset(&g_boot_handoff, 0, sizeof(g_boot_handoff));
    (void)memset(g_ueid, 0, sizeof(g_ueid));
    (void)memset(g_boot_seed, 0, sizeof(g_boot_seed));
    (void)memset(g_implementation_id, 0, sizeof(g_implementation_id));
    (void)memset(g_signer_id, 0, sizeof(g_signer_id));
    (void)memset(g_attest_hmac_key, 0, sizeof(g_attest_hmac_key));
    g_handoff_ready = false;
    g_attest_ready = false;
}

/* 0 when a token is issued and verifies under key; the status otherwise. */
static int token_under(const uint8_t* key)
{
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_32];
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    size_t tokenSize = 0u;
    int ret;

    (void)memset(challenge, 0x2a, sizeof(challenge));
    ret = wt_initial_attest_get_token(0u, challenge, sizeof(challenge), token,
                                      sizeof(token), &tokenSize);
    if (ret == WT_ATTEST_SUCCESS) {
        ret = mac0_verify(key, WT_ATTEST_HMAC_KEY_SIZE, token, tokenSize);
    }
    return ret;
}

int main(void)
{
    uint8_t first[WT_ATTEST_HMAC_KEY_SIZE];

    (void)memset(&g_handoff, 0, sizeof(g_handoff));
    g_handoff.magic = WT_BOOT_HANDOFF_MAGIC;
    g_handoff.version = WT_BOOT_HANDOFF_VERSION;
    g_handoff.lifecycle = 0x3000u;
    g_handoff.hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    g_handoff.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    (void)memset(g_handoff.measurement, 0xAB, WT_BOOT_HANDOFF_DIGEST_SIZE);
    (void)memset(g_port_key, 0x61, sizeof(g_port_key));
    (void)memcpy(first, g_port_key, sizeof(first));

    /* Boot: the privileged path takes the handoff, then starts the partition. */
    check(wt_initial_attest_init(&g_handoff) == WT_ATTEST_SUCCESS &&
          g_port_key_calls == 1, "boot loads the key through the port hook");
    check(wt_spm_attest_start(NULL, PARTITION_ATTEST_ID) == WT_FFM_SUCCESS &&
          g_added == 1 && g_restore != NULL &&
          g_restore_id == PARTITION_ATTEST_ID,
          "the attestation partition registers a restart hook");
    check(token_under(first) == 0, "a token verifies under the device key");

    band_reset();
    check(token_under(first) == WT_ATTEST_ERROR_NOT_READY,
          "a wiped band issues no token");
    check(g_restore != NULL &&
          g_restore(PARTITION_ATTEST_ID) == WT_FFM_SUCCESS &&
          g_port_key_calls == 2, "the restart hook loads the key again");
    check(token_under(first) == 0,
          "a token verifies again after the restart");

    /* A restart the port cannot serve leaves attestation closed, not stale. */
    band_reset();
    g_port_key_fail = 1;
    check(g_restore != NULL &&
          g_restore(PARTITION_ATTEST_ID) == WT_FFM_SUCCESS &&
          token_under(first) == WT_ATTEST_ERROR_NOT_READY,
          "a restart with no key restarts the partition and issues no token");
    g_port_key_fail = 0;
    band_reset();
    g_handoff_kept = 0;
    check(g_restore != NULL &&
          g_restore(PARTITION_ATTEST_ID) == WT_FFM_SUCCESS &&
          token_under(first) == WT_ATTEST_ERROR_NOT_READY,
          "a restart with no retained handoff issues no token");

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: attestation partition restart hook (HMAC key)\n");
    return 0;
}
