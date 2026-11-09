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

/* Host proof of the ITS partition (P4-S2): the FULL storage chain — a
 * Non-secure client calling SERVICE_ITS, the ITS dispatch forwarding over
 * SP-to-SP FF-M IPC to SERVICE_VAULT (two-pass begin/finish through the
 * gate), the real wt_hsm_vault backend, the real wolfHSM NVM stack on the
 * RAM flash simulator. Proves WT-FFM-0044 at END-CLIENT granularity (the
 * delegated sub_owner namespacing), WT-FFM-0045 through the ITS face, and
 * WT-FFM-0047 (ITS reaches the vault only via its dependencies[] grant;
 * direct NS access to the vault stays refused). */

#include "wolftrust/ffm.h"
#include "wolftrust/services/storage_service.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/hsm.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include <stdio.h>
#include <string.h>

#define TEST_VAULT_PARTITION 5
#define TEST_VAULT_SID       4098U
#define TEST_ITS_PARTITION   6
#define TEST_ITS_SID         4099U
#define TEST_NS_GUEST0       (-1)
#define TEST_NS_GUEST1       (-2)

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];

static int g_failures;
static int g_panics;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    } else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
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
    g_panics++;
}

/* Fallback port dispatch: never used — both partitions register their own. */
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

static const wt_service_descriptor_t g_vault_services[] = {
    {
        "SERVICE_VAULT", TEST_VAULT_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 0U, 1U
    }
};

static const wt_service_descriptor_t g_its_services[] = {
    {
        "SERVICE_ITS", TEST_ITS_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const uint32_t g_its_deps[] = { TEST_VAULT_SID };

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_VAULT", TEST_VAULT_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_vault_services, 1U, NULL, 0U, NULL, 0U
    },
    {
        "PARTITION_ITS", TEST_ITS_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_its_services, 1U, g_its_deps, 1U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "storage-service-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

/* ITS client-face helpers: [wt_its_req_t][data] in one input vector. */
static psa_status_t its_set(wt_ffm_runtime_t* runtime, int32_t caller,
                            psa_handle_t handle, uint64_t uid, uint32_t flags,
                            const void* data, size_t len)
{
    uint8_t buffer[sizeof(wt_its_req_t) + 128U];
    wt_its_req_t req;
    psa_invec in_vec[1];

    if (len > 128U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    req.flags = flags;
    (void)memcpy(buffer, &req, sizeof(req));
    (void)memcpy(buffer + sizeof(req), data, len);
    in_vec[0].base = buffer;
    in_vec[0].len = sizeof(req) + len;
    return wt_ffm_call(runtime, caller, handle, WT_ITS_OP_SET,
                       in_vec, 1U, NULL, 0U);
}

/* A SET of len filler bytes, sized past the 128-byte helper above. */
static psa_status_t its_set_large(wt_ffm_runtime_t* runtime, int32_t caller,
                                  psa_handle_t handle, uint64_t uid,
                                  size_t len)
{
    static uint8_t buffer[sizeof(wt_its_req_t) + WT_FFM_TRANSFER_BYTES];
    wt_its_req_t req;
    psa_invec in_vec[1];

    if (len > WT_FFM_TRANSFER_BYTES - sizeof(req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    (void)memcpy(buffer, &req, sizeof(req));
    (void)memset(buffer + sizeof(req), 0x6B, len);
    in_vec[0].base = buffer;
    in_vec[0].len = sizeof(req) + len;
    return wt_ffm_call(runtime, caller, handle, WT_ITS_OP_SET,
                       in_vec, 1U, NULL, 0U);
}

static psa_status_t its_get(wt_ffm_runtime_t* runtime, int32_t caller,
                            psa_handle_t handle, uint64_t uid,
                            uint32_t offset, void* data, size_t size,
                            size_t* out_len)
{
    wt_its_req_t req;
    psa_invec in_vec[1];
    psa_outvec out_vec[1];
    psa_status_t status;

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    req.offset = offset;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    out_vec[0].base = data;
    out_vec[0].len = size;
    status = wt_ffm_call(runtime, caller, handle, WT_ITS_OP_GET,
                         in_vec, 1U, out_vec, 1U);
    if (out_len != NULL) {
        *out_len = out_vec[0].len;
    }
    return status;
}

static psa_status_t its_get_info(wt_ffm_runtime_t* runtime, int32_t caller,
                                 psa_handle_t handle, uint64_t uid,
                                 wt_vault_info_t* info)
{
    wt_its_req_t req;
    psa_invec in_vec[1];
    psa_outvec out_vec[1];

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    out_vec[0].base = info;
    out_vec[0].len = sizeof(*info);
    return wt_ffm_call(runtime, caller, handle, WT_ITS_OP_GET_INFO,
                       in_vec, 1U, out_vec, 1U);
}

static psa_status_t its_remove(wt_ffm_runtime_t* runtime, int32_t caller,
                               psa_handle_t handle, uint64_t uid)
{
    wt_its_req_t req;
    psa_invec in_vec[1];

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    return wt_ffm_call(runtime, caller, handle, WT_ITS_OP_REMOVE,
                       in_vec, 1U, NULL, 0U);
}

int main(void)
{
    static const uint8_t data_g0[] = "its-secret-guest0";
    static const uint8_t data_g1[] = "its-secret-guest1";
    whFlashRamsimCfg ramsim_cfg;
    whFlashRamsimCtx ramsim_ctx;
    static const whFlashCb ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
    whNvmFlashConfig nvm_flash_cfg;
    whNvmFlashContext nvm_flash_ctx;
    static const whNvmCb nvm_cb[1] = {WH_NVM_FLASH_CB};
    whNvmConfig nvm_cfg;
    whNvmContext nvm_ctx;
    wt_ffm_runtime_t runtime;
    wt_storage_service_ctx_t its_ctx;
    psa_handle_t handle_g0;
    psa_handle_t handle_g1;
    psa_handle_t handle_direct;
    wt_vault_info_t info;
    uint8_t buffer[64];
    size_t got = 0U;
    psa_status_t status;

    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    (void)memset(&ramsim_cfg, 0, sizeof(ramsim_cfg));
    ramsim_cfg.memory = g_flash_memory;
    ramsim_cfg.size = RAMSIM_SIZE;
    ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    ramsim_cfg.pageSize = RAMSIM_PAGE;
    ramsim_cfg.erasedByte = 0xFF;
    (void)memset(&ramsim_ctx, 0, sizeof(ramsim_ctx));
    (void)memset(&nvm_flash_cfg, 0, sizeof(nvm_flash_cfg));
    nvm_flash_cfg.cb = ramsim_cb;
    nvm_flash_cfg.context = &ramsim_ctx;
    nvm_flash_cfg.config = &ramsim_cfg;
    (void)memset(&nvm_flash_ctx, 0, sizeof(nvm_flash_ctx));
    (void)memset(&nvm_cfg, 0, sizeof(nvm_cfg));
    nvm_cfg.cb = (whNvmCb*)nvm_cb;
    nvm_cfg.context = &nvm_flash_ctx;
    nvm_cfg.config = &nvm_flash_cfg;
    (void)memset(&nvm_ctx, 0, sizeof(nvm_ctx));
    if (wh_Nvm_Init(&nvm_ctx, &nvm_cfg) != WH_ERROR_OK) {
        (void)fprintf(stderr, "wh_Nvm_Init failed\n");
        return 1;
    }
    if (wt_hsm_vault_init(&nvm_ctx) != 0) {
        (void)fprintf(stderr, "wt_hsm_vault_init failed\n");
        return 1;
    }
    wt_vault_service_set_backend(&wt_hsm_vault_backend);

    if (wt_ffm_init(&runtime, &g_manifest, &g_port_ops, NULL) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "wt_ffm_init failed\n");
        return 1;
    }
    if (wt_ffm_register_partition(&runtime, TEST_VAULT_PARTITION,
                                  wt_vault_service_dispatch, NULL) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "vault register failed\n");
        return 1;
    }
    (void)memset(&its_ctx, 0, sizeof(its_ctx));
    its_ctx.transport = wt_spm_transport_direct;
    its_ctx.vault_sid = TEST_VAULT_SID;
    its_ctx.vault_handle = 0;
    its_ctx.client_flags_mask = WT_VAULT_FLAG_WRITE_ONCE;
    if (wt_ffm_register_partition(&runtime, TEST_ITS_PARTITION,
                                  wt_storage_service_dispatch, &its_ctx) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "ITS register failed\n");
        return 1;
    }

    /* WT-FFM-0047: the vault stays SP-only even with ITS in front of it. */
    handle_direct = wt_ffm_connect(&runtime, TEST_NS_GUEST0, TEST_VAULT_SID,
                                   1U);
    check(!PSA_HANDLE_IS_VALID(handle_direct),
          "WT-FFM-0047 direct NS access to SERVICE_VAULT still refused");

    handle_g0 = wt_ffm_connect(&runtime, TEST_NS_GUEST0, TEST_ITS_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle_g0),
          "NS guest0 connects to SERVICE_ITS");
    handle_g1 = wt_ffm_connect(&runtime, TEST_NS_GUEST1, TEST_ITS_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle_g1),
          "NS guest1 connects to SERVICE_ITS");
    if (!PSA_HANDLE_IS_VALID(handle_g0) || !PSA_HANDLE_IS_VALID(handle_g1)) {
        return 1;
    }

    /* The full chain: NS -> ITS -> (SP-to-SP gate) -> vault -> NVM. */
    status = its_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x1111ULL, 0U,
                     data_g0, sizeof(data_g0));
    check(status == PSA_SUCCESS,
          "WT-FFM-0047 guest0 its_set reaches the vault through the gate");
    (void)memset(buffer, 0, sizeof(buffer));
    status = its_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x1111ULL, 0U,
                     buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(data_g0) &&
          memcmp(buffer, data_g0, sizeof(data_g0)) == 0,
          "guest0 its_get returns the stored object");
    status = its_get_info(&runtime, TEST_NS_GUEST0, handle_g0, 0x1111ULL,
                          &info);
    check(status == PSA_SUCCESS && info.size == sizeof(data_g0),
          "guest0 its_get_info reports the object size");

    /* WT-FFM-0044 at end-client granularity: same uid, different guests. */
    status = its_get(&runtime, TEST_NS_GUEST1, handle_g1, 0x1111ULL, 0U,
                     buffer, sizeof(buffer), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST,
          "WT-FFM-0044 guest1 cannot see guest0's uid");
    status = its_set(&runtime, TEST_NS_GUEST1, handle_g1, 0x1111ULL, 0U,
                     data_g1, sizeof(data_g1));
    check(status == PSA_SUCCESS,
          "WT-FFM-0044 guest1 owns the same uid independently");
    (void)memset(buffer, 0, sizeof(buffer));
    status = its_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x1111ULL, 0U,
                     buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS &&
          memcmp(buffer, data_g0, sizeof(data_g0)) == 0,
          "WT-FFM-0044 guest0's object unchanged by guest1's set");

    /* WT-FFM-0045 through the ITS face. */
    status = its_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x2222ULL,
                     WT_VAULT_FLAG_WRITE_ONCE, data_g0, sizeof(data_g0));
    check(status == PSA_SUCCESS, "guest0 its_set(WRITE_ONCE)");
    status = its_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x2222ULL, 0U,
                     data_g1, sizeof(data_g1));
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WT-FFM-0045 WRITE_ONCE uid refuses a second its_set");
    status = its_remove(&runtime, TEST_NS_GUEST0, handle_g0, 0x2222ULL);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WT-FFM-0045 WRITE_ONCE uid refuses its_remove");

    /* Remove lifecycle + offset read. */
    status = its_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x1111ULL, 4U,
                     buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(data_g0) - 4U &&
          memcmp(buffer, data_g0 + 4U, got) == 0,
          "guest0 its_get(offset 4) returns the tail");
    status = its_remove(&runtime, TEST_NS_GUEST0, handle_g0, 0x1111ULL);
    check(status == PSA_SUCCESS, "guest0 its_remove");
    status = its_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x1111ULL, 0U,
                     buffer, sizeof(buffer), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST, "removed uid is gone");

    /* PSA Storage: uid 0 is invalid for every operation. */
    status = its_set(&runtime, TEST_NS_GUEST0, handle_g0, 0ULL, 0U,
                     data_g0, sizeof(data_g0));
    check(status == PSA_ERROR_INVALID_ARGUMENT, "its_set(uid 0) rejected");
    status = its_get(&runtime, TEST_NS_GUEST0, handle_g0, 0ULL, 0U,
                     buffer, sizeof(buffer), &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT, "its_get(uid 0) rejected");
    status = its_remove(&runtime, TEST_NS_GUEST0, handle_g0, 0ULL);
    check(status == PSA_ERROR_INVALID_ARGUMENT, "its_remove(uid 0) rejected");

    /* The vault hop carries its own request header in the same transfer
     * budget: the largest payload that fits is stored, one byte more is an
     * insufficient-storage condition, not an argument error. */
    status = its_set_large(&runtime, TEST_NS_GUEST0, handle_g0, 0x4444ULL,
                           WT_FFM_TRANSFER_BYTES - sizeof(wt_vault_req_t));
    check(status == PSA_SUCCESS,
          "its_set of the largest payload the vault hop carries succeeds");
    status = its_set_large(&runtime, TEST_NS_GUEST0, handle_g0, 0x4445ULL,
                           WT_FFM_TRANSFER_BYTES - sizeof(wt_vault_req_t) +
                               1U);
    check(status == PSA_ERROR_INSUFFICIENT_STORAGE,
          "its_set past the vault hop budget reports insufficient storage");
    status = its_set_large(&runtime, TEST_NS_GUEST0, handle_g0, 0x4446ULL,
                           WT_FFM_TRANSFER_BYTES - sizeof(wt_its_req_t));
    check(status == PSA_ERROR_INSUFFICIENT_STORAGE,
          "its_set of a full transfer reports insufficient storage");
    (void)its_remove(&runtime, TEST_NS_GUEST0, handle_g0, 0x4444ULL);

    /* A vault restart between requests must not strand the front end. */
    status = its_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x3333ULL, 0U,
                     data_g0, sizeof(data_g0));
    check(status == PSA_SUCCESS, "guest0 its_set before the vault restart");
    check(wt_ffm_partition_restarted(&runtime, TEST_VAULT_PARTITION,
                                     PSA_ERROR_COMMUNICATION_FAILURE) ==
              WT_FFM_SUCCESS,
          "vault partition restart recorded");
    (void)memset(buffer, 0, sizeof(buffer));
    status = its_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x3333ULL, 0U,
                     buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(data_g0) &&
          memcmp(buffer, data_g0, sizeof(data_g0)) == 0,
          "WT-FFM-0026 its_get served after the vault restarted");
    check(g_panics == 0, "no partition panicked across the vault restart");

    if (wt_ffm_close(&runtime, TEST_NS_GUEST0, handle_g0) != WT_FFM_SUCCESS ||
            wt_ffm_close(&runtime, TEST_NS_GUEST1, handle_g1) !=
                WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "psa_close(SERVICE_ITS) failed\n");
        return 1;
    }

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: ITS partition chain through the gated vault\n");
    return 0;
}
