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

/* Host proof of the gated wolfHSM vault (P4-S1): SERVICE_VAULT dispatch runs
 * against the REAL wt_hsm_vault backend over the REAL wolfHSM NVM stack
 * (wh_nvm + wh_nvm_flash on the RAM flash simulator), through real
 * wt_ffm_connect/wt_ffm_call round trips. Proves WT-FFM-0044 (per-owner
 * namespacing from the SPM-stamped caller id), WT-FFM-0045 (WRITE_ONCE
 * refuses modify/remove), and the WT-FFM-0047 authorization gate
 * (dependencies[] admits, absence refuses, Non-secure refused). */

#include "wolftrust/ffm.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/hsm.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include <stdio.h>
#include <string.h>

#define TEST_VAULT_PARTITION  5
#define TEST_VAULT_SID        4098U
#define TEST_CLIENT_A         6
#define TEST_CLIENT_B         7
#define TEST_CLIENT_C         8
#define TEST_NS_CLIENT        (-1)

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];

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

static const wt_ffm_port_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    wt_vault_service_dispatch,
    test_panic
};

static const wt_service_descriptor_t g_vault_services[] = {
    {
        "SERVICE_VAULT", TEST_VAULT_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 0U, 1U
    }
};

static const wt_service_descriptor_t g_client_a_services[] = {
    { "CLIENT_A_DUMMY", 4200U, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 1U, 1U }
};

static const wt_service_descriptor_t g_client_b_services[] = {
    { "CLIENT_B_DUMMY", 4201U, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 1U, 1U }
};

static const wt_service_descriptor_t g_client_c_services[] = {
    { "CLIENT_C_DUMMY", 4202U, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 1U, 1U }
};

static const uint32_t g_vault_dep[] = { TEST_VAULT_SID };

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_VAULT", TEST_VAULT_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_vault_services, 1U, NULL, 0U, NULL, 0U
    },
    {
        "CLIENT_A", TEST_CLIENT_A, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_client_a_services, 1U, g_vault_dep, 1U, NULL, 0U
    },
    {
        "CLIENT_B", TEST_CLIENT_B, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_client_b_services, 1U, g_vault_dep, 1U, NULL, 0U
    },
    {
        "CLIENT_C", TEST_CLIENT_C, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_client_c_services, 1U, NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "vault-service-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static psa_status_t vault_set(wt_ffm_runtime_t* runtime, int32_t caller,
                              psa_handle_t handle, uint64_t uid,
                              uint32_t flags, const void* data, size_t len)
{
    wt_vault_req_t req;
    psa_invec in_vec[2];

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    req.flags = flags;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    in_vec[1].base = data;
    in_vec[1].len = len;
    return wt_ffm_call(runtime, caller, handle, WT_VAULT_OP_SET,
                       in_vec, 2U, NULL, 0U);
}

static psa_status_t vault_get(wt_ffm_runtime_t* runtime, int32_t caller,
                              psa_handle_t handle, uint64_t uid,
                              uint32_t offset, void* data, size_t size,
                              size_t* out_len)
{
    wt_vault_req_t req;
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
    status = wt_ffm_call(runtime, caller, handle, WT_VAULT_OP_GET,
                         in_vec, 1U, out_vec, 1U);
    if (out_len != NULL) {
        *out_len = out_vec[0].len;
    }
    return status;
}

static psa_status_t vault_get_info(wt_ffm_runtime_t* runtime, int32_t caller,
                                   psa_handle_t handle, uint64_t uid,
                                   wt_vault_info_t* info)
{
    wt_vault_req_t req;
    psa_invec in_vec[1];
    psa_outvec out_vec[1];

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    out_vec[0].base = info;
    out_vec[0].len = sizeof(*info);
    return wt_ffm_call(runtime, caller, handle, WT_VAULT_OP_GET_INFO,
                       in_vec, 1U, out_vec, 1U);
}

static psa_status_t vault_remove(wt_ffm_runtime_t* runtime, int32_t caller,
                                 psa_handle_t handle, uint64_t uid)
{
    wt_vault_req_t req;
    psa_invec in_vec[1];

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    return wt_ffm_call(runtime, caller, handle, WT_VAULT_OP_REMOVE,
                       in_vec, 1U, NULL, 0U);
}

/* WT-FFM-0044 capacity honesty on the target flash geometry (16K region,
 * 8K sectors): a full data pool reports INSUFFICIENT_STORAGE without a
 * doomed partial write, and remove + refill is deterministic. */
static void test_capacity_gate(void)
{
    static uint8_t small_flash[16U * 1024U];
    static whFlashRamsimCfg small_cfg;
    static whFlashRamsimCtx small_ctx;
    static const whFlashCb small_cb[1] = {WH_FLASH_RAMSIM_CB};
    static whNvmFlashConfig small_nvm_flash_cfg;
    static whNvmFlashContext small_nvm_flash_ctx;
    static const whNvmCb small_nvm_cb[1] = {WH_NVM_FLASH_CB};
    static whNvmConfig small_nvm_cfg;
    static whNvmContext small_nvm_ctx;
    static uint8_t big[512];
    psa_status_t status = PSA_SUCCESS;
    uint64_t uid;
    uint64_t filled = 0U;
    uint64_t refilled = 0U;

    (void)memset(small_flash, 0xFF, sizeof(small_flash));
    (void)memset(&small_cfg, 0, sizeof(small_cfg));
    small_cfg.memory = small_flash;
    small_cfg.size = sizeof(small_flash);
    small_cfg.sectorSize = 8U * 1024U;
    small_cfg.pageSize = 8U;
    small_cfg.erasedByte = 0xFF;
    (void)memset(&small_ctx, 0, sizeof(small_ctx));
    (void)memset(&small_nvm_flash_cfg, 0, sizeof(small_nvm_flash_cfg));
    small_nvm_flash_cfg.cb = small_cb;
    small_nvm_flash_cfg.context = &small_ctx;
    small_nvm_flash_cfg.config = &small_cfg;
    (void)memset(&small_nvm_flash_ctx, 0, sizeof(small_nvm_flash_ctx));
    (void)memset(&small_nvm_cfg, 0, sizeof(small_nvm_cfg));
    small_nvm_cfg.cb = (whNvmCb*)small_nvm_cb;
    small_nvm_cfg.context = &small_nvm_flash_ctx;
    small_nvm_cfg.config = &small_nvm_flash_cfg;
    (void)memset(&small_nvm_ctx, 0, sizeof(small_nvm_ctx));
    if (wh_Nvm_Init(&small_nvm_ctx, &small_nvm_cfg) != WH_ERROR_OK ||
            wt_hsm_vault_init(&small_nvm_ctx) != 0) {
        check(0, "WT-FFM-0044 capacity harness init");
        return;
    }

    (void)memset(big, 0xA5, sizeof(big));
    for (uid = 1U; uid <= 40U; uid++) {
        status = wt_hsm_vault_backend.set(TEST_CLIENT_A, 0, uid, 0U, big,
                                          sizeof(big));
        if (status != PSA_SUCCESS) {
            break;
        }
        filled++;
    }
    check(filled > 0U && status == PSA_ERROR_INSUFFICIENT_STORAGE,
          "WT-FFM-0044 full pool reports INSUFFICIENT_STORAGE");
    for (uid = 1U; uid <= filled; uid++) {
        if (wt_hsm_vault_backend.remove(TEST_CLIENT_A, 0, uid) !=
                PSA_SUCCESS) {
            check(0, "WT-FFM-0044 remove during recovery");
            return;
        }
    }
    for (uid = 1U; uid <= 40U; uid++) {
        status = wt_hsm_vault_backend.set(TEST_CLIENT_A, 0, uid, 0U, big,
                                          sizeof(big));
        if (status != PSA_SUCCESS) {
            break;
        }
        refilled++;
    }
    check(refilled == filled && status == PSA_ERROR_INSUFFICIENT_STORAGE,
          "WT-FFM-0044 remove-all then refill is deterministic");
}

int main(void)
{
    static const uint8_t data_a[] = "vault-secret-owner-A";
    static const uint8_t data_b[] = "vault-secret-owner-B";
    static const uint8_t data_seq[] = "0123456789";
    whFlashRamsimCfg ramsim_cfg;
    whFlashRamsimCtx ramsim_ctx;
    static const whFlashCb ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
    whNvmFlashConfig nvm_flash_cfg;
    whNvmFlashContext nvm_flash_ctx;
    static const whNvmCb nvm_cb[1] = {WH_NVM_FLASH_CB};
    whNvmConfig nvm_cfg;
    whNvmContext nvm_ctx;
    whNvmMetadata key_meta;
    whNvmId key_id = WH_NVM_ID_INVALID;
    wt_ffm_runtime_t runtime;
    psa_handle_t handle_a;
    psa_handle_t handle_b;
    psa_handle_t handle_ns;
    psa_handle_t handle_c;
    wt_vault_info_t info;
    uint8_t buffer[64];
    uint8_t short_req[4];
    psa_invec bad_vec;
    size_t got = 0U;
    psa_status_t status;

    /* Real wolfHSM NVM over the RAM flash simulator. */
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

    /* WT-FFM-0047: only manifest-authorized Secure Partitions reach the
     * vault. NS clients and dependency-less partitions are refused. */
    handle_ns = wt_ffm_connect(&runtime, TEST_NS_CLIENT, TEST_VAULT_SID, 1U);
    check(!PSA_HANDLE_IS_VALID(handle_ns),
          "WT-FFM-0047 Non-secure client refused by SERVICE_VAULT");
    handle_c = wt_ffm_connect(&runtime, TEST_CLIENT_C, TEST_VAULT_SID, 1U);
    check(!PSA_HANDLE_IS_VALID(handle_c),
          "WT-FFM-0047 partition without dependencies[] refused");
    handle_a = wt_ffm_connect(&runtime, TEST_CLIENT_A, TEST_VAULT_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle_a),
          "WT-FFM-0047 dependencies[] admits CLIENT_A through the gate");
    handle_b = wt_ffm_connect(&runtime, TEST_CLIENT_B, TEST_VAULT_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle_b),
          "WT-FFM-0047 dependencies[] admits CLIENT_B through the gate");
    if (!PSA_HANDLE_IS_VALID(handle_a) || !PSA_HANDLE_IS_VALID(handle_b)) {
        return 1;
    }

    /* SET/GET round trip through the real NVM backend. */
    status = vault_set(&runtime, TEST_CLIENT_A, handle_a, 0x11ULL, 0U,
                       data_a, sizeof(data_a));
    check(status == PSA_SUCCESS, "owner A set(uid 0x11)");
    (void)memset(buffer, 0, sizeof(buffer));
    status = vault_get(&runtime, TEST_CLIENT_A, handle_a, 0x11ULL, 0U,
                       buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(data_a) &&
          memcmp(buffer, data_a, sizeof(data_a)) == 0,
          "owner A get(uid 0x11) returns the stored object");
    status = vault_get_info(&runtime, TEST_CLIENT_A, handle_a, 0x11ULL,
                            &info);
    check(status == PSA_SUCCESS && info.size == sizeof(data_a) &&
          info.flags == 0U,
          "owner A get_info(uid 0x11) reports size and flags");

    /* WT-FFM-0044: the SPM-stamped owner namespaces every object. */
    status = vault_get(&runtime, TEST_CLIENT_B, handle_b, 0x11ULL, 0U,
                       buffer, sizeof(buffer), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST,
          "WT-FFM-0044 owner B cannot see owner A's uid");
    status = vault_set(&runtime, TEST_CLIENT_B, handle_b, 0x11ULL, 0U,
                       data_b, sizeof(data_b));
    check(status == PSA_SUCCESS,
          "WT-FFM-0044 owner B owns the same uid independently");
    (void)memset(buffer, 0, sizeof(buffer));
    status = vault_get(&runtime, TEST_CLIENT_A, handle_a, 0x11ULL, 0U,
                       buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS &&
          memcmp(buffer, data_a, sizeof(data_a)) == 0,
          "WT-FFM-0044 owner A's object unchanged by owner B's set");

    /* WT-FFM-0045: WRITE_ONCE refuses modify and remove. */
    status = vault_set(&runtime, TEST_CLIENT_A, handle_a, 0x22ULL,
                       WT_VAULT_FLAG_WRITE_ONCE, data_a, sizeof(data_a));
    check(status == PSA_SUCCESS, "owner A set(uid 0x22, WRITE_ONCE)");
    status = vault_set(&runtime, TEST_CLIENT_A, handle_a, 0x22ULL, 0U,
                       data_b, sizeof(data_b));
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WT-FFM-0045 WRITE_ONCE object refuses a second set");
    status = vault_remove(&runtime, TEST_CLIENT_A, handle_a, 0x22ULL);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WT-FFM-0045 WRITE_ONCE object refuses remove");
    status = vault_get_info(&runtime, TEST_CLIENT_A, handle_a, 0x22ULL,
                            &info);
    check(status == PSA_SUCCESS &&
          info.flags == WT_VAULT_FLAG_WRITE_ONCE,
          "WT-FFM-0045 WRITE_ONCE flag is reported by get_info");

    /* Offset read + remove lifecycle. */
    status = vault_set(&runtime, TEST_CLIENT_A, handle_a, 0x33ULL, 0U,
                       data_seq, sizeof(data_seq) - 1U);
    check(status == PSA_SUCCESS, "owner A set(uid 0x33) sequence");
    (void)memset(buffer, 0, sizeof(buffer));
    status = vault_get(&runtime, TEST_CLIENT_A, handle_a, 0x33ULL, 4U,
                       buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == 6U &&
          memcmp(buffer, "456789", 6U) == 0,
          "owner A get(uid 0x33, offset 4) returns the tail");
    status = vault_remove(&runtime, TEST_CLIENT_A, handle_a, 0x33ULL);
    check(status == PSA_SUCCESS, "owner A remove(uid 0x33)");
    status = vault_get(&runtime, TEST_CLIENT_A, handle_a, 0x33ULL, 0U,
                       buffer, sizeof(buffer), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST,
          "removed uid is gone");

    status = wt_hsm_vault_lookup(TEST_CLIENT_A, 0, 0x44ULL, NULL, NULL,
                                 &key_id);
    check(status == PSA_ERROR_DOES_NOT_EXIST &&
          key_id != WH_NVM_ID_INVALID, "found a slot for a key object");
    if (key_id == WH_NVM_ID_INVALID) {
        return 1;
    }
    (void)memset(&key_meta, 0, sizeof(key_meta));
    key_meta.id = key_id;
    key_meta.access = WH_NVM_ACCESS_ANY;
    key_meta.flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE;
    key_meta.len = (whNvmSize)sizeof(data_a);
    wt_hsm_vault_make_label(key_meta.label, TEST_CLIENT_A, 0, 0x44ULL,
                            WT_VAULT_FLAG_KEY | WT_VAULT_KEY_USAGE_VERIFY);
    check(wh_Nvm_AddObject(&nvm_ctx, &key_meta, key_meta.len, data_a) ==
          WH_ERROR_OK, "created key object in shared vault window");
    status = vault_remove(&runtime, TEST_CLIENT_A, handle_a, 0x44ULL);
    check(status == PSA_ERROR_NOT_PERMITTED &&
          wh_Nvm_GetMetadata(&nvm_ctx, key_id, &key_meta) == WH_ERROR_OK,
          "storage remove cannot delete a key object");

    /* Malformed request header is refused, not misparsed. */
    (void)memset(short_req, 0, sizeof(short_req));
    bad_vec.base = short_req;
    bad_vec.len = sizeof(short_req);
    status = wt_ffm_call(&runtime, TEST_CLIENT_A, handle_a,
                         WT_VAULT_OP_GET, &bad_vec, 1U, NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "undersized request header refused");

    if (wt_ffm_close(&runtime, TEST_CLIENT_A, handle_a) != WT_FFM_SUCCESS ||
            wt_ffm_close(&runtime, TEST_CLIENT_B, handle_b) !=
                WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "psa_close(SERVICE_VAULT) failed\n");
        return 1;
    }

    test_capacity_gate();

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: gated wolfHSM vault through real FF-M dispatch\n");
    return 0;
}
