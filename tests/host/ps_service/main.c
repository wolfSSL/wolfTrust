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

/* Host proof of the PS partition (P4-S3, WT-FFM-0048): the full sealed
 * storage chain — a Non-secure client calling SERVICE_PS, the PS dispatch
 * forcing WT_VAULT_FLAG_SEALED and forwarding over SP-to-SP FF-M IPC to
 * SERVICE_VAULT, the real wt_hsm_vault backend AES-GCM-sealing every object
 * under the device-unique wolfHSM key with the persisted rollback counter as
 * nonce, over the real wolfHSM NVM stack on the RAM flash simulator.
 * Negative evidence: plaintext never at rest, a rolled-back ciphertext fails
 * authentication, and key + counters survive a simulated reboot. */

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
#define TEST_PS_PARTITION    7
#define TEST_PS_SID          4100U
#define TEST_NS_GUEST0       (-1)
#define TEST_NS_GUEST1       (-2)

#define TEST_VAULT_ID_BASE  0x0100U
#define TEST_VAULT_ID_COUNT 32U
#define TEST_VAULT_STAGE_ID 0x0123U

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];
static uint8_t g_flash_snapshot[RAMSIM_SIZE];

static whFlashRamsimCfg g_ramsim_cfg;
static whFlashRamsimCtx g_ramsim_ctx;
static const whFlashCb g_ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
static whNvmFlashConfig g_nvm_flash_cfg;
static whNvmFlashContext g_nvm_flash_ctx;
static whNvmCb g_nvm_cb[1] = {WH_NVM_FLASH_CB};
static whNvmConfig g_nvm_cfg;
static whNvmContext g_nvm_ctx;

static int g_failures;
static whNvmId g_fail_add_id = WH_NVM_ID_INVALID;
static unsigned int g_fail_add_skips;

static int test_nvm_add(void* context, whNvmMetadata* meta,
                        whNvmSize data_len, const uint8_t* data)
{
    if (meta != NULL && meta->id == g_fail_add_id) {
        if (g_fail_add_skips > 0U) {
            g_fail_add_skips--;
        }
        else {
            g_fail_add_id = WH_NVM_ID_INVALID;
            return WH_ERROR_ABORTED;
        }
    }
    return wh_NvmFlash_AddObject(context, meta, data_len, data);
}

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

static const wt_service_descriptor_t g_ps_services[] = {
    {
        "SERVICE_PS", TEST_PS_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const uint32_t g_ps_deps[] = { TEST_VAULT_SID };

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_VAULT", TEST_VAULT_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_vault_services, 1U, NULL, 0U, NULL, 0U
    },
    {
        "PARTITION_PS", TEST_PS_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_ps_services, 1U, g_ps_deps, 1U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "ps-service-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

/* Bring up (or re-bring-up) the NVM stack over the SAME flash contents and
 * bind the vault backend + sealer — the "reboot" seam for persistence.
 * whFlashRamsim_Init erases its memory unless initData is provided, so a
 * reboot re-seeds the sim from a snapshot of the pre-reset flash image. */
static int test_nvm_up(int reboot)
{
    g_fail_add_id = WH_NVM_ID_INVALID;
    g_fail_add_skips = 0U;
    g_nvm_cb[0].AddObject = test_nvm_add;
    (void)memset(&g_ramsim_cfg, 0, sizeof(g_ramsim_cfg));
    g_ramsim_cfg.memory = g_flash_memory;
    g_ramsim_cfg.size = RAMSIM_SIZE;
    g_ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    g_ramsim_cfg.pageSize = RAMSIM_PAGE;
    g_ramsim_cfg.erasedByte = 0xFF;
    if (reboot != 0) {
        (void)memcpy(g_flash_snapshot, g_flash_memory, RAMSIM_SIZE);
        g_ramsim_cfg.initData = g_flash_snapshot;
    }
    (void)memset(&g_ramsim_ctx, 0, sizeof(g_ramsim_ctx));
    (void)memset(&g_nvm_flash_cfg, 0, sizeof(g_nvm_flash_cfg));
    g_nvm_flash_cfg.cb = g_ramsim_cb;
    g_nvm_flash_cfg.context = &g_ramsim_ctx;
    g_nvm_flash_cfg.config = &g_ramsim_cfg;
    (void)memset(&g_nvm_flash_ctx, 0, sizeof(g_nvm_flash_ctx));
    (void)memset(&g_nvm_cfg, 0, sizeof(g_nvm_cfg));
    g_nvm_cfg.cb = (whNvmCb*)g_nvm_cb;
    g_nvm_cfg.context = &g_nvm_flash_ctx;
    g_nvm_cfg.config = &g_nvm_flash_cfg;
    (void)memset(&g_nvm_ctx, 0, sizeof(g_nvm_ctx));
    if (wh_Nvm_Init(&g_nvm_ctx, &g_nvm_cfg) != WH_ERROR_OK) {
        return -1;
    }
    if (wt_hsm_vault_init(&g_nvm_ctx) != 0) {
        return -1;
    }
    wt_vault_service_set_backend(&wt_hsm_vault_backend);
    if (wt_hsm_seal_init(&g_nvm_ctx) != 0) {
        return -1;
    }
    wt_hsm_vault_set_sealer(&wt_hsm_sealer);
    return 0;
}

static int test_runtime_up(wt_ffm_runtime_t* runtime,
                           wt_storage_service_ctx_t* ps_ctx)
{
    if (wt_ffm_init(runtime, &g_manifest, &g_port_ops, NULL) !=
            WT_FFM_SUCCESS) {
        return -1;
    }
    if (wt_ffm_register_partition(runtime, TEST_VAULT_PARTITION,
                                  wt_vault_service_dispatch, NULL) !=
            WT_FFM_SUCCESS) {
        return -1;
    }
    (void)memset(ps_ctx, 0, sizeof(*ps_ctx));
    ps_ctx->transport = wt_spm_transport_direct;
    ps_ctx->vault_sid = TEST_VAULT_SID;
    ps_ctx->vault_handle = 0;
    ps_ctx->client_flags_mask = WT_VAULT_FLAG_WRITE_ONCE |
                                WT_VAULT_FLAG_NO_CONFIDENTIALITY |
                                WT_VAULT_FLAG_NO_REPLAY;
    ps_ctx->vault_flags = WT_VAULT_FLAG_SEALED;
    ps_ctx->caps = 0U;
    if (wt_ffm_register_partition(runtime, TEST_PS_PARTITION,
                                  wt_storage_service_dispatch, ps_ctx) !=
            WT_FFM_SUCCESS) {
        return -1;
    }
    return 0;
}

/* PS client-face helpers: [wt_its_req_t][data] in one input vector. */
static psa_status_t ps_set(wt_ffm_runtime_t* runtime, int32_t caller,
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

static psa_status_t ps_get(wt_ffm_runtime_t* runtime, int32_t caller,
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

static psa_status_t ps_get_info(wt_ffm_runtime_t* runtime, int32_t caller,
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

static psa_status_t ps_remove(wt_ffm_runtime_t* runtime, int32_t caller,
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

static psa_status_t ps_create(wt_ffm_runtime_t* runtime, int32_t caller,
                              psa_handle_t handle, uint64_t uid)
{
    wt_its_req_t req;
    psa_invec in_vec[1];

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    return wt_ffm_call(runtime, caller, handle, WT_PS_OP_CREATE,
                       in_vec, 1U, NULL, 0U);
}

static psa_status_t ps_get_support(wt_ffm_runtime_t* runtime, int32_t caller,
                                   psa_handle_t handle, uint32_t* caps)
{
    psa_outvec out_vec[1];

    out_vec[0].base = caps;
    out_vec[0].len = sizeof(*caps);
    return wt_ffm_call(runtime, caller, handle, WT_PS_OP_GET_SUPPORT,
                       NULL, 0U, out_vec, 1U);
}

static int test_flash_contains(const uint8_t* needle, size_t needle_len)
{
    size_t i;

    for (i = 0U; i + needle_len <= sizeof(g_flash_memory); i++) {
        if (memcmp(g_flash_memory + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Locate the stored NVM object for a sealed payload of plain length
 * plain_len by scanning the vault id window — the at-rest inspection seam. */
static int test_find_stored(size_t plain_len, whNvmId* out_id,
                            whNvmMetadata* out_meta)
{
    whNvmMetadata meta;
    whNvmId id;
    uint32_t i;
    int rc;

    for (i = 0U; i < TEST_VAULT_ID_COUNT; i++) {
        id = (whNvmId)(TEST_VAULT_ID_BASE + i);
        rc = wh_Nvm_GetMetadata(&g_nvm_ctx, id, &meta);
        if (rc == WH_ERROR_OK &&
                meta.len == plain_len + WT_VAULT_SEAL_TAG_LEN) {
            *out_id = id;
            *out_meta = meta;
            return 0;
        }
    }
    return -1;
}

static int test_fill_to_available(whNvmId target)
{
    static whNvmId next_id = 0x0200U;
    whNvmMetadata meta;
    whNvmId available;
    int rc;

    rc = wh_Nvm_DestroyObjects(&g_nvm_ctx, 0U, NULL);
    if (rc != WH_ERROR_OK) {
        return -1;
    }
    do {
        rc = wh_Nvm_GetAvailable(&g_nvm_ctx, NULL, &available, NULL, NULL);
        if (rc != WH_ERROR_OK || available < target) {
            return -1;
        }
        if (available > target) {
            (void)memset(&meta, 0, sizeof(meta));
            meta.id = next_id++;
            meta.access = WH_NVM_ACCESS_ANY;
            rc = wh_Nvm_AddObject(&g_nvm_ctx, &meta, 0U, NULL);
            if (rc != WH_ERROR_OK) {
                return -1;
            }
        }
    } while (available > target);

    return 0;
}

static void test_unsealed_replacement(void)
{
    static const uint8_t original[] = "sealed value";
    static const uint8_t updated[] = "plain value";
    whNvmMetadata old_meta;
    whNvmId id;
    uint8_t old_ct[sizeof(original) + WT_VAULT_SEAL_TAG_LEN];
    uint8_t buffer[sizeof(original)];
    size_t got;
    unsigned int step;
    psa_status_t status;

    for (step = 0U; step < 6U; step++) {
        check(test_nvm_up(0) == 0, "initialized vault transition test");
        status = wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
            0x6001ULL, WT_VAULT_FLAG_SEALED, original, sizeof(original));
        check(status == PSA_SUCCESS, "created sealed transition source");
        if (status != PSA_SUCCESS) {
            return;
        }
        if (test_find_stored(sizeof(original), &id, &old_meta) != 0) {
            check(0, "located sealed transition source");
            return;
        }
        check(wh_Nvm_Read(&g_nvm_ctx, id, 0U, old_meta.len, old_ct) ==
                  WH_ERROR_OK, "saved sealed transition source");
        if (step == 5U) {
            old_ct[0] ^= 1U;
            check(wh_Nvm_AddObject(&g_nvm_ctx, &old_meta, old_meta.len,
                      old_ct) == WH_ERROR_OK,
                  "prepared invalid sealed transition source");
            old_ct[0] ^= 1U;
        }
        if (step < 4U) {
            g_fail_add_id = step == 0U ? 0x0123U :
                           step == 2U ? id : WT_HSM_VAULT_TABLE_ID;
            g_fail_add_skips = step == 3U ? 1U : 0U;
        }
        status = wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
            0x6001ULL, WT_VAULT_FLAG_WRITE_ONCE, updated, sizeof(updated));
        check(status == (step < 4U ? PSA_ERROR_STORAGE_FAILURE : PSA_SUCCESS),
              "unsealed replacement reports its transaction result");
        check(test_nvm_up(1) == 0, "rebooted after unsealed replacement");
        status = wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST0,
            0x6001ULL, 0U, buffer, sizeof(buffer), &got);
        if (step < 4U) {
            check(status == PSA_SUCCESS && got == sizeof(original) &&
                  memcmp(buffer, original, sizeof(original)) == 0,
                  "WT-FFM-0048 failed unsealed replacement preserves source");
        }
        else {
            check(status == PSA_SUCCESS && got == sizeof(updated) &&
                  memcmp(buffer, updated, sizeof(updated)) == 0,
                  "committed unsealed replacement survives reboot");
            check(wh_Nvm_AddObjectWithReclaim(&g_nvm_ctx, &old_meta,
                      old_meta.len, old_ct) == WH_ERROR_OK,
                  "restored prior sealed object for counter check");
            status = wt_hsm_vault_backend.get(TEST_PS_PARTITION,
                TEST_NS_GUEST0, 0x6001ULL, 0U, buffer, sizeof(buffer), &got);
            check(status == PSA_ERROR_INVALID_SIGNATURE,
                  "WT-FFM-0048 unsealed replacement retires sealed counter");
            status = wt_hsm_vault_backend.set(TEST_PS_PARTITION,
                TEST_NS_GUEST0, 0x6001ULL, WT_VAULT_FLAG_SEALED,
                updated, sizeof(updated));
            check(status == PSA_SUCCESS,
                  "a retired sealed object can be rewritten");
            status = wt_hsm_vault_backend.get(TEST_PS_PARTITION,
                TEST_NS_GUEST0, 0x6001ULL, 0U, buffer, sizeof(buffer), &got);
            check(status == PSA_SUCCESS && got == sizeof(updated) &&
                  memcmp(buffer, updated, sizeof(updated)) == 0,
                  "rewritten retired object is readable");
        }
    }
}

static void test_recovery_containment(void)
{
    static const uint8_t original[] = "committed source";
    static const uint8_t updated[] = "replacement";
    whNvmMetadata meta;
    whNvmId id;
    whNvmId stage_id = 0x0123U;
    wt_vault_info_t info;
    uint8_t buffer[sizeof(original) + WT_VAULT_SEAL_TAG_LEN];
    size_t got;
    unsigned int scenario;
    uint32_t flags;
    psa_status_t status;

    for (scenario = 0U; scenario < 12U; scenario++) {
        check(test_nvm_up(0) == 0, "initialized recovery containment test");
        check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
                  0x7001ULL, WT_VAULT_FLAG_SEALED, original,
                  sizeof(original)) == PSA_SUCCESS,
              "created recovery source");
        if (test_find_stored(sizeof(original), &id, &meta) != 0) {
            check(0, "located recovery source");
            return;
        }
        check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST1,
                  0x7002ULL, WT_VAULT_FLAG_SEALED, original,
                  sizeof(original)) == PSA_SUCCESS,
              "created unrelated object");
        g_fail_add_id = scenario < 3U ? id : WT_HSM_VAULT_TABLE_ID;
        g_fail_add_skips = scenario < 3U ? 0U : 1U;
        flags = scenario / 3U == 2U ? WT_VAULT_FLAG_WRITE_ONCE :
                                     WT_VAULT_FLAG_SEALED;
        check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
                  0x7001ULL, flags, updated, sizeof(updated)) ==
                  PSA_ERROR_STORAGE_FAILURE,
              "interrupted the replacement");
        if (scenario >= 9U) {
            check(wh_Nvm_DestroyObjects(&g_nvm_ctx, 1U, &id) == WH_ERROR_OK,
                  "removed incomplete target");
        }
        if (scenario % 3U == 0U) {
            check(wh_Nvm_DestroyObjects(&g_nvm_ctx, 1U, &stage_id) ==
                      WH_ERROR_OK, "removed unavailable recovery copy");
        }
        else {
            check(wh_Nvm_Read(&g_nvm_ctx, stage_id, 0U, meta.len, buffer) ==
                      WH_ERROR_OK, "read recovery copy");
            if (scenario % 3U == 1U) {
                buffer[0] ^= 1U;
            }
            else {
                meta.flags |= WH_NVM_FLAGS_NONEXPORTABLE;
            }
            meta.id = stage_id;
            check(wh_Nvm_AddObject(&g_nvm_ctx, &meta, meta.len, buffer) ==
                      WH_ERROR_OK, "invalidated recovery copy");
        }
        check(test_nvm_up(1) == 0, "rebooted before recovery containment");
        if (scenario >= 3U && scenario < 9U) {
            g_fail_add_id = WT_HSM_VAULT_TABLE_ID;
            check(wt_hsm_vault_backend.get(TEST_PS_PARTITION,
                      TEST_NS_GUEST1, 0x7002ULL, 0U, buffer, sizeof(buffer),
                      &got) == PSA_ERROR_STORAGE_FAILURE,
                  "interrupted recovery cleanup reports a write failure");
            check(test_nvm_up(1) == 0, "rebooted during recovery cleanup");
        }
        status = wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST1,
            0x7002ULL, 0U, buffer, sizeof(buffer), &got);
        check(status == PSA_SUCCESS && got == sizeof(original) &&
              memcmp(buffer, original, sizeof(original)) == 0,
              "WT-FFM-0048 recovery failure leaves unrelated data readable");
        check(wh_Nvm_GetMetadata(&g_nvm_ctx, TEST_VAULT_STAGE_ID, &meta) ==
                  WH_ERROR_NOTFOUND,
              "completed recovery destroys its recovery stage");
        status = wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST0,
            0x7001ULL, 0U, buffer, sizeof(buffer), &got);
        check(scenario < 3U ?
                  status == PSA_SUCCESS && got == sizeof(original) &&
                      memcmp(buffer, original, sizeof(original)) == 0 :
                  status == PSA_ERROR_DOES_NOT_EXIST,
              "recovery keeps only an authenticated committed object");
        check(wt_hsm_vault_backend.get_info(TEST_PS_PARTITION,
                  TEST_NS_GUEST1, 0x7002ULL, &info) == PSA_SUCCESS &&
                  info.size == sizeof(original),
              "unrelated metadata remains available");
        check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST1,
                  0x7002ULL, WT_VAULT_FLAG_SEALED, updated,
                  sizeof(updated)) == PSA_SUCCESS,
              "unrelated sealed replacements remain available");
        check(wt_hsm_vault_backend.remove(TEST_PS_PARTITION, TEST_NS_GUEST1,
                  0x7002ULL) == PSA_SUCCESS,
              "unrelated removal remains available");
        check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
                  0x7001ULL, WT_VAULT_FLAG_SEALED, updated,
                  sizeof(updated)) == PSA_SUCCESS,
              "affected slot can be rewritten after recovery");
    }
}

static void test_authenticated_recovery(void)
{
    static const uint8_t original[] = "authenticated source";
    static const uint8_t updated[] = "uncommitted value";
    whNvmMetadata meta;
    whNvmId id;
    uint8_t buffer[sizeof(original) + WT_VAULT_SEAL_TAG_LEN];
    size_t got;
    psa_status_t status;

    check(test_nvm_up(0) == 0, "initialized authenticated recovery test");
    check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0x9001ULL, WT_VAULT_FLAG_SEALED, original, sizeof(original)) ==
              PSA_SUCCESS, "created authenticated recovery source");
    if (test_find_stored(sizeof(original), &id, &meta) != 0) {
        check(0, "located authenticated recovery source");
        return;
    }
    g_fail_add_id = WT_HSM_VAULT_TABLE_ID;
    g_fail_add_skips = 1U;
    check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0x9001ULL, WT_VAULT_FLAG_SEALED, updated, sizeof(updated)) ==
              PSA_ERROR_STORAGE_FAILURE,
          "interrupted replacement retains authenticated recovery copy");
    check(wh_Nvm_GetMetadata(&g_nvm_ctx, id, &meta) == WH_ERROR_OK &&
          wh_Nvm_Read(&g_nvm_ctx, id, 0U, meta.len, buffer) == WH_ERROR_OK,
          "read uncommitted target");
    meta.label[8] ^= 1U;
    check(wh_Nvm_AddObject(&g_nvm_ctx, &meta, meta.len, buffer) == WH_ERROR_OK,
          "invalidated uncommitted target identity");
    check(test_nvm_up(1) == 0, "rebooted with invalid target identity");
    status = wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST0,
        0x9001ULL, 0U, buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(original) &&
          memcmp(buffer, original, sizeof(original)) == 0,
          "WT-FFM-0048 authenticated recovery ignores invalid live identity");
}

static void test_recovery_counter_binding(void)
{
    static const uint8_t original[] = "committed source";
    static const uint8_t other[] = "other identity";
    whNvmMetadata meta;
    whNvmId id;
    uint8_t buffer[sizeof(original) + WT_VAULT_SEAL_TAG_LEN];
    size_t got;

    check(test_nvm_up(0) == 0, "initialized recovery counter test");
    check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0xA001ULL, WT_VAULT_FLAG_SEALED, original, sizeof(original)) ==
              PSA_SUCCESS, "created recovery counter source");
    if (test_find_stored(sizeof(original), &id, &meta) != 0) {
        check(0, "located recovery counter source");
        return;
    }
    check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST1,
              0xA002ULL, WT_VAULT_FLAG_SEALED, other, sizeof(other)) ==
              PSA_SUCCESS, "created distinct recovery identity");
    g_fail_add_id = id;
    check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0xA001ULL, WT_VAULT_FLAG_SEALED, other, sizeof(other)) ==
              PSA_ERROR_STORAGE_FAILURE,
          "interrupted replacement before target write");
    if (test_find_stored(sizeof(other), &id, &meta) != 0) {
        check(0, "located distinct recovery identity");
        return;
    }
    check(wh_Nvm_Read(&g_nvm_ctx, id, 0U, meta.len, buffer) == WH_ERROR_OK,
          "read distinct sealed object");
    meta.id = 0x0123U;
    check(wh_Nvm_AddObject(&g_nvm_ctx, &meta, meta.len, buffer) == WH_ERROR_OK,
          "staged distinct sealed object");
    check(test_nvm_up(1) == 0, "rebooted with distinct recovery identity");
    check(wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0xA001ULL, 0U, buffer, sizeof(buffer), &got) == PSA_SUCCESS &&
              got == sizeof(original) &&
              memcmp(buffer, original, sizeof(original)) == 0,
          "WT-FFM-0048 recovery counter rejects another sealed identity");
    check(wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST1,
              0xA002ULL, 0U, buffer, sizeof(buffer), &got) == PSA_SUCCESS &&
              got == sizeof(other) && memcmp(buffer, other, sizeof(other)) == 0,
          "distinct sealed identity remains unchanged");
}

static void test_invalid_sealed_length(void)
{
    static const uint8_t original[] = "valid value";
    static const uint8_t invalid[WT_VAULT_OBJECT_MAX + WT_VAULT_SEAL_TAG_LEN + 1U];
    whNvmMetadata meta;
    whNvmId id;
    uint8_t buffer[sizeof(original)];
    size_t got;
    unsigned int oversized;

    for (oversized = 0U; oversized < 2U; oversized++) {
        check(test_nvm_up(0) == 0, "initialized sealed length test");
        check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
                  0x8001ULL, WT_VAULT_FLAG_SEALED, original,
                  sizeof(original)) == PSA_SUCCESS,
              "created sealed length source");
        if (test_find_stored(sizeof(original), &id, &meta) != 0) {
            check(0, "located sealed length source");
            return;
        }
        meta.len = oversized != 0U ? (whNvmSize)sizeof(invalid) : 0U;
        check(wh_Nvm_AddObject(&g_nvm_ctx, &meta, meta.len, invalid) ==
                  WH_ERROR_OK, "stored invalid sealed length");
        check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
                  0x8001ULL, WT_VAULT_FLAG_SEALED, original,
                  sizeof(original)) == PSA_SUCCESS,
              "invalid sealed length does not prevent a rewrite");
        check(wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST0,
                  0x8001ULL, 0U, buffer, sizeof(buffer), &got) == PSA_SUCCESS &&
                  got == sizeof(original) &&
                  memcmp(buffer, original, sizeof(original)) == 0,
              "rewritten malformed object is readable");
    }
}

static void test_replacement_stage_cleanup(void)
{
    static const uint8_t original[] = "staged source";
    static const uint8_t updated[] = "staged replacement";
    whNvmMetadata meta;
    whNvmId id;
    uint8_t buffer[sizeof(updated) + WT_VAULT_SEAL_TAG_LEN];
    size_t got;

    check(test_nvm_up(0) == 0, "initialized stage cleanup test");
    check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0xB001ULL, WT_VAULT_FLAG_SEALED, original, sizeof(original)) ==
              PSA_SUCCESS, "created stage cleanup source");
    check(wt_hsm_vault_backend.set(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0xB001ULL, WT_VAULT_FLAG_SEALED, updated, sizeof(updated)) ==
              PSA_SUCCESS, "committed staged replacement");
    check(wh_Nvm_GetMetadata(&g_nvm_ctx, TEST_VAULT_STAGE_ID, &meta) ==
              WH_ERROR_NOTFOUND,
          "committed replacement destroys its recovery stage");
    if (test_find_stored(sizeof(updated), &id, &meta) != 0) {
        check(0, "located committed stage cleanup object");
        return;
    }
    check(wh_Nvm_Read(&g_nvm_ctx, id, 0U, meta.len, buffer) == WH_ERROR_OK,
          "read committed object for orphan cleanup test");
    meta.id = TEST_VAULT_STAGE_ID;
    meta.flags = WH_NVM_FLAGS_SENSITIVE;
    check(wh_Nvm_AddObject(&g_nvm_ctx, &meta, meta.len, buffer) == WH_ERROR_OK,
          "created orphan recovery stage");
    check(wt_hsm_vault_backend.get(TEST_PS_PARTITION, TEST_NS_GUEST0,
              0xB001ULL, 0U, buffer, sizeof(buffer), &got) == PSA_SUCCESS &&
              got == sizeof(updated) &&
              memcmp(buffer, updated, sizeof(updated)) == 0,
          "orphan stage cleanup preserves the committed object");
    check(wh_Nvm_GetMetadata(&g_nvm_ctx, TEST_VAULT_STAGE_ID, &meta) ==
              WH_ERROR_NOTFOUND,
          "next operation destroys an orphan recovery stage");
}

int main(void)
{
    static const uint8_t secret_v1[] = "ps-secret-version-one";
    static const uint8_t secret_v2[] = "ps-secret-version-TWO";
    static const uint8_t secret_v3[] = "ps-secret-version-THR";
    static const uint8_t secret_wo[] = "ps-write-once-secret";
    uint8_t old_ct[sizeof(secret_v1) + WT_VAULT_SEAL_TAG_LEN];
    whNvmMetadata old_meta;
    whNvmMetadata meta;
    whNvmCb incompatible_cb = WH_NVM_FLASH_CB;
    whNvmContext incompatible_nvm;
    whNvmId stored_id = 0U;
    wt_ffm_runtime_t runtime;
    wt_storage_service_ctx_t ps_ctx;
    psa_handle_t handle_g0;
    psa_handle_t handle_g1;
    psa_handle_t handle_direct;
    wt_vault_info_t info;
    uint8_t buffer[64];
    uint32_t caps = 0xFFFFFFFFU;
    size_t got = 0U;
    psa_status_t status;

    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    if (test_nvm_up(0) != 0) {
        (void)fprintf(stderr, "NVM/sealer bring-up failed\n");
        return 1;
    }
    incompatible_nvm = g_nvm_ctx;
    incompatible_cb.GetAvailable = NULL;
    incompatible_nvm.cb = &incompatible_cb;
    check(wt_hsm_vault_init(&incompatible_nvm) != 0,
          "vault rejects an incompatible NVM capacity contract");
    check(wt_hsm_vault_init(&g_nvm_ctx) == 0,
          "vault accepts the flash backend with a RAM simulator");
    if (test_runtime_up(&runtime, &ps_ctx) != 0) {
        (void)fprintf(stderr, "runtime bring-up failed\n");
        return 1;
    }

    /* WT-FFM-0047: the vault stays SP-only with PS in front of it. */
    handle_direct = wt_ffm_connect(&runtime, TEST_NS_GUEST0, TEST_VAULT_SID,
                                   1U);
    check(!PSA_HANDLE_IS_VALID(handle_direct),
          "WT-FFM-0047 direct NS access to SERVICE_VAULT still refused");

    handle_g0 = wt_ffm_connect(&runtime, TEST_NS_GUEST0, TEST_PS_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle_g0), "NS guest0 connects to SERVICE_PS");
    handle_g1 = wt_ffm_connect(&runtime, TEST_NS_GUEST1, TEST_PS_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle_g1), "NS guest1 connects to SERVICE_PS");
    if (!PSA_HANDLE_IS_VALID(handle_g0) || !PSA_HANDLE_IS_VALID(handle_g1)) {
        return 1;
    }

    /* The sealed chain: NS -> PS -> gate -> vault -> AES-GCM -> NVM. */
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    secret_v1, sizeof(secret_v1));
    check(status == PSA_SUCCESS,
          "WT-FFM-0048 guest0 ps_set seals through the gate");
    (void)memset(buffer, 0, sizeof(buffer));
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret_v1) &&
          memcmp(buffer, secret_v1, sizeof(secret_v1)) == 0,
          "guest0 ps_get unseals the stored object");

    /* WT-FFM-0048: plaintext is never at rest — the stored NVM object is
     * ciphertext + tag, and the secret bytes appear nowhere in flash. */
    check(test_find_stored(sizeof(secret_v1), &stored_id, &meta) == 0,
          "stored object is plain length + GCM tag");
    if (stored_id != 0U) {
        check(test_flash_contains(secret_v1, sizeof(secret_v1)) == 0,
              "WT-FFM-0048 secret plaintext absent from flash at rest");
    }

    status = ps_get_info(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL,
                         &info);
    check(status == PSA_SUCCESS && info.size == sizeof(secret_v1) &&
          info.flags == 0U,
          "ps_get_info reports plaintext size and client-visible flags");

    /* Offset read decrypts the whole object, then slices. */
    (void)memset(buffer, 0, sizeof(buffer));
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 4U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret_v1) - 4U &&
          memcmp(buffer, secret_v1 + 4U, got) == 0,
          "guest0 ps_get(offset 4) returns the tail");

    /* WT-FFM-0044 at end-client granularity on the PS face. */
    status = ps_get(&runtime, TEST_NS_GUEST1, handle_g1, 0x5001ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST,
          "WT-FFM-0044 guest1 cannot see guest0's sealed uid");

    /* Rollback protection: capture the v1 ciphertext, update to v2, then
     * replay the v1 bytes at the NVM layer — authentication must fail. */
    old_meta = meta;
    check(wh_Nvm_Read(&g_nvm_ctx, stored_id, 0U, old_meta.len, old_ct) ==
              WH_ERROR_OK, "captured v1 ciphertext for replay");
    g_fail_add_id = stored_id;
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    secret_v2, sizeof(secret_v2));
    check(status == PSA_ERROR_STORAGE_FAILURE,
          "failed replacement reports storage failure");
    (void)memset(buffer, 0, sizeof(buffer));
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret_v1) &&
          memcmp(buffer, secret_v1, sizeof(secret_v1)) == 0,
          "failed replacement rolls back to the prior object");

    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    secret_v2, sizeof(secret_v2));
    check(status == PSA_SUCCESS, "guest0 ps_set commits v2");
    g_fail_add_id = WT_HSM_VAULT_TABLE_ID;
    g_fail_add_skips = 1U;
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    secret_v3, sizeof(secret_v3));
    check(status == PSA_ERROR_STORAGE_FAILURE,
          "interrupted replacement reports storage failure");
    check(wh_Nvm_AddObject(&g_nvm_ctx, &old_meta, old_meta.len, old_ct) ==
              WH_ERROR_OK, "replayed stale ciphertext before recovery");
    check(test_nvm_up(1) == 0,
          "reinitialized NVM with an incomplete replacement");
    (void)memset(buffer, 0, sizeof(buffer));
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret_v2) &&
          memcmp(buffer, secret_v2, sizeof(secret_v2)) == 0,
          "reboot restores the authenticated prior object");
    check(wh_Nvm_AddObjectWithReclaim(&g_nvm_ctx, &old_meta, old_meta.len,
                                      old_ct) == WH_ERROR_OK,
          "replayed v1 ciphertext into the NVM object");
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_ERROR_INVALID_SIGNATURE,
          "WT-FFM-0048 rolled-back ciphertext fails authentication");
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    secret_v2, sizeof(secret_v2));
    check(status == PSA_SUCCESS, "guest0 recovers by rewriting v2");

    /* WT-FFM-0045 on the sealed face. */
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5002ULL,
                    WT_VAULT_FLAG_WRITE_ONCE, secret_wo, sizeof(secret_wo));
    check(status == PSA_SUCCESS, "guest0 ps_set(WRITE_ONCE) sealed");
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5002ULL, 0U,
                    secret_v1, sizeof(secret_v1));
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WT-FFM-0045 sealed WRITE_ONCE uid refuses a second ps_set");
    status = ps_remove(&runtime, TEST_NS_GUEST0, handle_g0, 0x5002ULL);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WT-FFM-0045 sealed WRITE_ONCE uid refuses ps_remove");

    /* Optional-feature gating: nothing advertised, nothing silently faked. */
    status = ps_get_support(&runtime, TEST_NS_GUEST0, handle_g0, &caps);
    check(status == PSA_SUCCESS && caps == 0U,
          "psa_ps_get_support advertises no optional features");
    status = ps_create(&runtime, TEST_NS_GUEST0, handle_g0, 0x5003ULL);
    check(status == PSA_ERROR_NOT_SUPPORTED,
          "psa_ps_create refused NOT_SUPPORTED");

    /* Reboot persistence: tear the runtime + NVM stack down, re-init over
     * the same flash — device key and rollback counters must survive. */
    if (wt_ffm_close(&runtime, TEST_NS_GUEST0, handle_g0) != WT_FFM_SUCCESS ||
            wt_ffm_close(&runtime, TEST_NS_GUEST1, handle_g1) !=
                WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "psa_close(SERVICE_PS) failed\n");
        return 1;
    }
    if (test_nvm_up(1) != 0 || test_runtime_up(&runtime, &ps_ctx) != 0) {
        (void)fprintf(stderr, "reboot bring-up failed\n");
        return 1;
    }
    handle_g0 = wt_ffm_connect(&runtime, TEST_NS_GUEST0, TEST_PS_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle_g0),
          "guest0 reconnects to SERVICE_PS after reboot");
    (void)memset(buffer, 0, sizeof(buffer));
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret_v2) &&
          memcmp(buffer, secret_v2, sizeof(secret_v2)) == 0,
          "WT-FFM-0048 sealed object unseals after reboot (key + counters persist)");
    (void)memset(buffer, 0, sizeof(buffer));
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5002ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS &&
          memcmp(buffer, secret_wo, sizeof(secret_wo)) == 0,
          "WT-FFM-0045 WRITE_ONCE sealed object survives reboot");

    check(test_fill_to_available(4U) == 0,
          "prepared exact replacement transaction capacity");
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    secret_v3, sizeof(secret_v3));
    check(status == PSA_SUCCESS,
          "sealed replacement uses exact transaction capacity");
    check(test_fill_to_available(4U) == 0,
          "prepared exact rollback transaction capacity");
    g_fail_add_id = WT_HSM_VAULT_TABLE_ID;
    g_fail_add_skips = 1U;
    status = ps_set(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    secret_v2, sizeof(secret_v2));
    check(status == PSA_ERROR_STORAGE_FAILURE,
          "near-capacity interrupted replacement reports failure");
    (void)memset(buffer, 0, sizeof(buffer));
    status = ps_get(&runtime, TEST_NS_GUEST0, handle_g0, 0x5001ULL, 0U,
                    buffer, sizeof(buffer), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret_v3) &&
          memcmp(buffer, secret_v3, sizeof(secret_v3)) == 0,
          "near-capacity recovery preserves the prior object");

    if (wt_ffm_close(&runtime, TEST_NS_GUEST0, handle_g0) != WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "psa_close after reboot failed\n");
        return 1;
    }

    test_unsealed_replacement();
    test_recovery_containment();
    test_authenticated_recovery();
    test_recovery_counter_binding();
    test_invalid_sealed_length();
    test_replacement_stage_cleanup();

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: PS partition sealed chain through the gated vault\n");
    return 0;
}
