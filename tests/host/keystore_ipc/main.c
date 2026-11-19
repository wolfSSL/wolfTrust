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

/* Isolation level 3 doors (WT-FFM-0011): the crypto partition's NVM view is
 * a set of FF-M calls into SERVICE_VAULT's keystore object door, and the
 * attestation partition's signer is a set of FF-M calls into SERVICE_HSM's
 * attestation door. Both are driven here through real wt_ffm round trips so
 * the door policy, the copied transfers, and the client shims run exactly as
 * the scheduled partitions drive them on target:
 *
 *   D1  a wolfHSM keystore object (type nibble set) round-trips through the
 *       door: add, metadata, read, destroy
 *   D2  a key-flagged vault-window object round-trips and is found by the
 *       store-parameterised directory lookup
 *   D3  a storage front end's object is invisible: metadata blanked, read
 *       and destroy refused, its slot neither matched nor reused
 *   D4  the directory table, seal key, rollback table, and stage ids are
 *       unreachable; a window add without the key flag is refused
 *   D5  reclaim (destroy of nothing) is allowed
 *   D6  a partition other than the registered crypto partition is refused
 *   D7  the vault's own storage faces still never serve a key object
 *   A1  before binding, the attestation partition has no signer
 *   A2  bound to SERVICE_HSM, the public key and every token signature come
 *       through the door, and the token carries the door's signature
 *   A3  Non-secure clients, other partitions, and a malformed digest are
 *       refused at the attestation door
 *   R1  the vault restarts under an idle keystore door: the next operation
 *       closes the dropped connection and reconnects, no panic
 *   R2  the vault faults under a request in flight: that request fails with
 *       a defined error, the next reconnects
 *   R3  every dropped connection is closed, so more restarts than there are
 *       connection slots never exhaust them
 *   R4  the crypto partition restarts under the idle attestation door
 *   R5  the crypto partition faults under a token signature in flight
 *   L1  an add whose declared length differs from the object is refused
 *   N1  a zero-length read through the door returns what the direct store
 *       returns: present, absent, zero-length object, offset at and past
 *       the end; a hidden object is refused like any other read of it
 *   C1  bind, use, cleanup cycles release their connection slots
 *   Z1  the vault's copied transfer buffer is zeroed before its frame is
 *       released, after an add and a read through the keystore door
 *   Z2  and after a set and a get through the storage face
 *   S1  Non-secure clients cannot take the pool slots kept for the
 *       partitions' own doors
 *   V1  the vault's RANDOM face fails closed until its DRBG is seeded and
 *       serves once it is re-seeded
 *   K1  the crypto partition is refused every vault request outside the
 *       keystore door, storage and RANDOM included
 *   K2  Secure Partitions, the attestation partition included, are refused
 *       on SERVICE_HSM's ordinary crypto wire; Non-secure clients are served */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wolftrust/ffm.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/initial_attestation.h"
#include "wolftrust/services/nvm_client.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/boot_handoff.h"

#include <stdio.h>
#include <string.h>

#define TEST_ATTEST_PARTITION 3
#define TEST_HSM_PARTITION    4
#define TEST_VAULT_PARTITION  5
#define TEST_ROGUE_PARTITION  6
#define TEST_ATTEST_SID       4096U
#define TEST_VAULT_SID        4098U
#define TEST_HSM_SID          4102U
#define TEST_ROGUE_SID        4200U
#define TEST_NS_CLIENT        (-1)

#define TEST_KEYSTORE_ID  ((whNvmId)WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0xFU, 0xF0U))
#define TEST_WINDOW_BASE  ((whNvmId)0x0100U)
#define TEST_TABLE_ID     ((whNvmId)0x0121U)
#define TEST_STAGE_ID     ((whNvmId)0x0123U)

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];
static whFlashRamsimCfg g_ramsim_cfg;
static whFlashRamsimCtx g_ramsim_ctx;
static const whFlashCb g_ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
static whNvmFlashConfig g_nvm_flash_cfg;
static whNvmFlashContext g_nvm_flash_ctx;
static const whNvmCb g_nvm_cb[1] = {WH_NVM_FLASH_CB};
static whNvmConfig g_nvm_cfg;
static whNvmContext g_store;

static wt_ffm_runtime_t g_runtime;
static int g_failures;
static unsigned int g_panics;
static int32_t g_fault_partition;
static wt_nvm_client_t* g_fault_client;
static uint8_t g_probe_pattern[48];
static unsigned int g_wipe_checks;
static unsigned int g_wipe_dirty;
static unsigned int g_submit_calls;

/* WT_VAULT_WIPE_PROBE seam: runs inside the vault's call frame right after
 * the copied transfer buffers are wiped, while they are still live. */
void wt_vault_wipe_probe(const uint8_t* buf, size_t len)
{
    size_t i;
    uint8_t acc = 0U;

    for (i = 0U; i < len; i++) {
        acc |= buf[i];
    }
    g_wipe_checks++;
    if (acc != 0U) {
        g_wipe_dirty++;
    }
}

/* The engine behind SERVICE_HSM's ordinary wire: counts what reaches it. */
static int test_relay_submit(void* submit_ctx, int32_t client_id,
                             const uint8_t* req, size_t req_len,
                             uint8_t* resp, size_t resp_cap, size_t* resp_len)
{
    (void)submit_ctx; (void)client_id; (void)req; (void)req_len;
    if (resp_cap < 1U) {
        return -1;
    }
    g_submit_calls++;
    resp[0] = 0x5AU;
    *resp_len = 1U;
    return 0;
}

static unsigned int g_sign_calls;
static uint8_t g_last_digest[WT_HSM_ATTEST_DIGEST_LEN];
static uint8_t g_door_public_key[WT_HSM_ATTEST_PUBLIC_KEY_LEN];

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    } else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/* The engine's local signer, which the bound attestation partition must never
 * reach: report no key so a fallback shows up as NOT_READY. */
int wt_hsm_attest_sign(const uint8_t* digest, size_t digestSize,
                       uint8_t* signature, size_t signatureCapacity,
                       size_t* signatureSize)
{
    (void)digest; (void)digestSize; (void)signature; (void)signatureCapacity;
    if (signatureSize != NULL) {
        *signatureSize = 0U;
    }
    return WH_ERROR_NOTREADY;
}

int wt_hsm_attest_public_key(uint8_t* publicKey, size_t publicKeyCapacity,
                             size_t* publicKeySize)
{
    (void)publicKey; (void)publicKeyCapacity;
    if (publicKeySize != NULL) {
        *publicKeySize = WT_HSM_ATTEST_PUBLIC_KEY_LEN;
    }
    return WH_ERROR_NOTREADY;
}

/* The crypto partition's signer behind the door: deterministic bytes so the
 * token can be checked for the door's signature. */
static int test_door_sign(const uint8_t* digest, size_t digest_len,
                          uint8_t* signature, size_t signature_capacity,
                          size_t* signature_len)
{
    size_t i;

    if (digest_len != WT_HSM_ATTEST_DIGEST_LEN ||
            signature_capacity < WT_HSM_ATTEST_SIGNATURE_LEN) {
        return WH_ERROR_BADARGS;
    }
    g_sign_calls++;
    (void)memcpy(g_last_digest, digest, sizeof(g_last_digest));
    for (i = 0U; i < WT_HSM_ATTEST_SIGNATURE_LEN; i++) {
        signature[i] = (uint8_t)(0xA0U + i);
    }
    *signature_len = WT_HSM_ATTEST_SIGNATURE_LEN;
    return 0;
}

static int test_door_public_key(uint8_t* public_key,
                                size_t public_key_capacity,
                                size_t* public_key_len)
{
    if (public_key_capacity < WT_HSM_ATTEST_PUBLIC_KEY_LEN) {
        return WH_ERROR_BADARGS;
    }
    (void)memcpy(public_key, g_door_public_key, sizeof(g_door_public_key));
    *public_key_len = WT_HSM_ATTEST_PUBLIC_KEY_LEN;
    return 0;
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

/* A partition's fault recovery as the SPM runs it on target
 * (wt_spm_fault_release + wt_spm_fault_messages): every connection to the
 * partition drops to the error state and its dependants' cached doors are
 * told the partition restarted. */
static void test_partition_restart(int32_t partition_id)
{
    (void)wt_ffm_fail_partition_messages(&g_runtime, partition_id,
                                         PSA_ERROR_COMMUNICATION_FAILURE);
    if (partition_id == TEST_VAULT_PARTITION) {
        wt_nvm_client_vault_restarted(g_fault_client);
    }
    if (partition_id == TEST_HSM_PARTITION) {
        wt_initial_attest_hsm_restarted();
    }
}

/* The scheduler stand-in for a Secure Partition client: like
 * wt_spm_transport_direct, except that a partition armed in
 * g_fault_partition faults under the next request instead of serving it,
 * and every must-panic classification is counted (on target the SPM would
 * fault the calling partition for it). */
static int test_sp_transport(wt_ffm_runtime_t* runtime, wt_spm_call_t* call)
{
    int status = wt_spm_gate(runtime, NULL, call);
    unsigned int guard = 0U;

    while (status == WT_FFM_SUCCESS && call->pending_valid != 0U &&
            call->ret_int == WT_FFM_ERROR_NOT_READY && guard < 8U) {
        if (g_fault_partition != 0 && call->op == WT_SPM_OP_CALL) {
            test_partition_restart(g_fault_partition);
            g_fault_partition = 0;
        }
        else {
            (void)wt_ffm_dispatch_pending(runtime, call->pending_msg);
        }
        status = wt_spm_gate(runtime, NULL, call);
        guard++;
    }
    if (call->must_panic != 0U) {
        g_panics++;
    }
    return status;
}

static const wt_service_descriptor_t g_vault_services[] = {
    { "SERVICE_VAULT", TEST_VAULT_SID, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 0U, 1U }
};
static const wt_service_descriptor_t g_hsm_services[] = {
    { "SERVICE_HSM", TEST_HSM_SID, 1U, WT_SERVICE_VERSION_RELAXED,
      0x20U, 0U, 1U, 1U }
};
static const wt_service_descriptor_t g_attest_services[] = {
    { "SERVICE_ATTEST", TEST_ATTEST_SID, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 1U, 1U }
};
static const wt_service_descriptor_t g_rogue_services[] = {
    { "SERVICE_ROGUE", TEST_ROGUE_SID, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 1U, 1U }
};
static const uint32_t g_hsm_deps[] = { TEST_VAULT_SID };
static const uint32_t g_attest_deps[] = { TEST_HSM_SID };
static const uint32_t g_rogue_deps[] = { TEST_VAULT_SID, TEST_HSM_SID };

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_VAULT", TEST_VAULT_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_vault_services, 1U, NULL, 0U, NULL, 0U
    },
    {
        "PARTITION_HSM", TEST_HSM_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_hsm_services, 1U, g_hsm_deps, 1U, NULL, 0U
    },
    {
        "PARTITION_ATTEST", TEST_ATTEST_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_attest_services, 1U, g_attest_deps, 1U, NULL, 0U
    },
    {
        "PARTITION_ROGUE", TEST_ROGUE_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_rogue_services, 1U, g_rogue_deps, 2U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "keystore-ipc-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static int store_up(void)
{
    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    (void)memset(&g_ramsim_cfg, 0, sizeof(g_ramsim_cfg));
    g_ramsim_cfg.memory = g_flash_memory;
    g_ramsim_cfg.size = RAMSIM_SIZE;
    g_ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    g_ramsim_cfg.pageSize = RAMSIM_PAGE;
    g_ramsim_cfg.erasedByte = 0xFF;
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
    (void)memset(&g_store, 0, sizeof(g_store));
    if (wh_Nvm_Init(&g_store, &g_nvm_cfg) != WH_ERROR_OK) {
        return -1;
    }
    if (wt_hsm_vault_init(&g_store) != 0) {
        return -1;
    }
    wt_vault_service_set_backend(&wt_hsm_vault_backend);
    wt_vault_service_set_nvm_backend(&wt_hsm_vault_nvm_backend);
    wt_vault_service_set_keystore_client(TEST_HSM_PARTITION);
    return 0;
}

static int attest_dispatch(void* context, wt_ffm_runtime_t* runtime,
                           int32_t partition_id)
{
    (void)context;
    (void)runtime;
    (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

static int runtime_up(void)
{
    if (wt_ffm_init(&g_runtime, &g_manifest, &g_port_ops, NULL) !=
            WT_FFM_SUCCESS) {
        return -1;
    }
    if (wt_ffm_register_partition(&g_runtime, TEST_VAULT_PARTITION,
                                  wt_vault_service_dispatch, NULL) !=
            WT_FFM_SUCCESS) {
        return -1;
    }
    if (wt_ffm_register_partition(&g_runtime, TEST_HSM_PARTITION,
                                  wt_hsm_relay_dispatch, NULL) !=
            WT_FFM_SUCCESS) {
        return -1;
    }
    if (wt_ffm_register_partition(&g_runtime, TEST_ATTEST_PARTITION,
                                  attest_dispatch, NULL) != WT_FFM_SUCCESS) {
        return -1;
    }
    if (wt_ffm_register_partition(&g_runtime, TEST_ROGUE_PARTITION,
                                  attest_dispatch, NULL) != WT_FFM_SUCCESS) {
        return -1;
    }
    wt_hsm_relay_set_attest_ops(TEST_ATTEST_PARTITION, test_door_sign,
                                test_door_public_key);
    return 0;
}

static void meta_init(whNvmMetadata* meta, whNvmId id, whNvmSize len)
{
    (void)memset(meta, 0, sizeof(*meta));
    meta->id = id;
    meta->access = WH_NVM_ACCESS_ANY;
    meta->flags = WH_NVM_FLAGS_SENSITIVE;
    meta->len = len;
}

/* N1: a zero-length read through the door against the direct store. */
static void zero_read_row(whNvmContext* view, whNvmId id, whNvmSize offset,
                          int expected, const char* what)
{
    uint8_t scratch[1] = { 0x5AU };
    int door;
    int direct;

    door = wh_Nvm_Read(view, id, offset, 0U, scratch);
    direct = wh_Nvm_Read(&g_store, id, offset, 0U, scratch);
    check(door == expected && direct == expected, what);
}

static void test_nvm_door(void)
{
    static const uint8_t key_bytes[48] = "the crypto partition's key object";
    static const uint8_t its_bytes[16] = "its-secret-blob";
    wt_nvm_client_t client;
    wt_nvm_client_t rogue;
    wt_nvm_client_t cycle;
    whNvmContext view;
    whNvmContext rogue_view;
    whNvmContext cycle_view;
    wt_vault_nvm_req_t nreq;
    wt_vault_req_t vreq;
    psa_invec in_vec[2];
    psa_outvec out_vec[1];
    psa_handle_t handle;
    psa_status_t status;
    whNvmMetadata meta;
    whNvmMetadata got;
    whNvmId id = WH_NVM_ID_INVALID;
    whNvmId free_id = WH_NVM_ID_INVALID;
    whNvmId its_id = WH_NVM_ID_INVALID;
    whNvmId window_key_id = WH_NVM_ID_INVALID;
    uint8_t out[64];
    uint32_t avail_size = 0U;
    uint32_t reclaim_size = 0U;
    whNvmId avail_objects = 0U;
    whNvmId reclaim_objects = 0U;
    size_t got_len = 0U;
    size_t i;
    int rc;

    check(wt_nvm_client_bind(&client, &view, test_sp_transport,
                             &g_runtime, TEST_HSM_PARTITION,
                             TEST_VAULT_SID) == 0,
          "crypto partition binds its store view to SERVICE_VAULT");
    g_fault_client = &client;

    /* D1: wolfHSM keystore namespace. */
    meta_init(&meta, TEST_KEYSTORE_ID, (whNvmSize)sizeof(key_bytes));
    (void)memcpy(meta.label, "IAK", 3);
    rc = wh_Nvm_AddObject(&view, &meta, (whNvmSize)sizeof(key_bytes),
                          key_bytes);
    check(rc == WH_ERROR_OK, "D1 keystore object added through the door");
    rc = wh_Nvm_GetMetadata(&view, TEST_KEYSTORE_ID, &got);
    check(rc == WH_ERROR_OK && got.len == sizeof(key_bytes) &&
          got.flags == WH_NVM_FLAGS_SENSITIVE &&
          memcmp(got.label, "IAK", 3) == 0,
          "D1 keystore object metadata reads back through the door");
    (void)memset(out, 0, sizeof(out));
    rc = wh_Nvm_Read(&view, TEST_KEYSTORE_ID, 0U,
                     (whNvmSize)sizeof(key_bytes), out);
    check(rc == WH_ERROR_OK && memcmp(out, key_bytes, sizeof(key_bytes)) == 0,
          "D1 keystore object data reads back through the door");
    (void)memset(out, 0, sizeof(out));
    rc = wh_Nvm_Read(&view, TEST_KEYSTORE_ID, 8U, 16U, out);
    check(rc == WH_ERROR_OK && memcmp(out, key_bytes + 8, 16U) == 0,
          "D1 offset read through the door");
    rc = wh_Nvm_Read(&view, TEST_KEYSTORE_ID, 40U, 16U, out);
    check(rc == WH_ERROR_BADARGS, "D1 read past the object is refused");
    rc = wh_Nvm_GetAvailable(&view, &avail_size, &avail_objects,
                             &reclaim_size, &reclaim_objects);
    check(rc == WH_ERROR_OK && avail_size > 0U && avail_objects > 0U,
          "D1 pool availability reads through the door");
    rc = wh_Nvm_GetMetadata(&view, (whNvmId)(TEST_KEYSTORE_ID + 1U), &got);
    check(rc == WH_ERROR_NOTFOUND,
          "D1 an absent keystore id reports not found");
    rc = wh_Nvm_GetMetadata(&view, TEST_KEYSTORE_ID, NULL);
    check(rc == WH_ERROR_OK,
          "D1 an existence probe without metadata sees a present id");
    rc = wh_Nvm_GetMetadata(&view, (whNvmId)(TEST_KEYSTORE_ID + 1U), NULL);
    check(rc == WH_ERROR_NOTFOUND,
          "D1 an existence probe without metadata reports an absent id");
    meta_init(&meta, (whNvmId)(TEST_KEYSTORE_ID + 2U), 0U);
    rc = wh_Nvm_AddObject(&view, &meta, 0U, NULL);
    check(rc == WH_ERROR_OK && g_panics == 0U,
          "D1 a zero-length keystore object adds through the door, no panic");
    rc = wh_Nvm_GetMetadata(&view, (whNvmId)(TEST_KEYSTORE_ID + 2U), &got);
    check(rc == WH_ERROR_OK && got.len == 0U,
          "D1 the zero-length object's metadata reads back");
    zero_read_row(&view, TEST_KEYSTORE_ID, 0U, WH_ERROR_OK,
                  "N1 zero-length read of a present object matches the store");
    zero_read_row(&view, TEST_KEYSTORE_ID, 47U, WH_ERROR_OK,
                  "N1 zero-length read at the last byte matches the store");
    zero_read_row(&view, (whNvmId)(TEST_KEYSTORE_ID + 1U), 0U,
                  WH_ERROR_NOTFOUND,
                  "N1 zero-length read of an absent id matches the store");
    zero_read_row(&view, (whNvmId)(TEST_KEYSTORE_ID + 2U), 0U,
                  WH_ERROR_BADARGS,
                  "N1 zero-length read of a zero-length object matches the store");
    zero_read_row(&view, TEST_KEYSTORE_ID, (whNvmSize)sizeof(key_bytes),
                  WH_ERROR_BADARGS,
                  "N1 zero-length read at offset == length matches the store");
    zero_read_row(&view, TEST_KEYSTORE_ID,
                  (whNvmSize)(sizeof(key_bytes) + 1U), WH_ERROR_BADARGS,
                  "N1 zero-length read past the end matches the store");
    id = (whNvmId)(TEST_KEYSTORE_ID + 2U);
    rc = wh_Nvm_DestroyObjects(&view, 1U, &id);
    check(rc == WH_ERROR_OK, "D1 the zero-length object is destroyed");

    /* D2: key-flagged vault-window object (native keyvault style). */
    check(wt_hsm_vault_lookup_in(&view, 4, -1, 0x55ULL, NULL, NULL,
                                 &free_id) == PSA_ERROR_DOES_NOT_EXIST &&
          free_id == TEST_WINDOW_BASE,
          "D2 the window lookup over the door finds the first free slot");
    check(wt_hsm_vault_reserve_object_in(&view, 32U) == PSA_SUCCESS,
          "D2 reservation runs over the door");
    meta_init(&meta, free_id, 32U);
    wt_hsm_vault_make_label(meta.label, 4, -1, 0x55ULL,
                            WT_VAULT_FLAG_KEY | WT_VAULT_KEY_USAGE_SIGN);
    rc = wh_Nvm_AddObject(&view, &meta, 32U, key_bytes);
    check(rc == WH_ERROR_OK, "D2 key-flagged window object added");
    window_key_id = free_id;
    check(wt_hsm_vault_lookup_in(&view, 4, -1, 0x55ULL, &id, &got, NULL) ==
              PSA_SUCCESS && id == window_key_id && got.len == 32U,
          "D2 the window lookup over the door finds the key object");
    rc = wh_Nvm_Read(&view, window_key_id, 0U, 32U, out);
    check(rc == WH_ERROR_OK && memcmp(out, key_bytes, 32U) == 0,
          "D2 key-flagged window object reads back");

    /* D3: a storage front end's object is invisible. */
    check(wt_hsm_vault_backend.set(TEST_ROGUE_PARTITION, 0, 0x77ULL, 0U,
                                   its_bytes, sizeof(its_bytes)) ==
              PSA_SUCCESS,
          "D3 a storage front end stores an object in the window");
    check(wt_hsm_vault_lookup(TEST_ROGUE_PARTITION, 0, 0x77ULL, &its_id,
                              NULL, NULL) == PSA_SUCCESS &&
          its_id != window_key_id,
          "D3 the vault's own lookup finds it");
    rc = wh_Nvm_GetMetadata(&view, its_id, &got);
    check(rc == WH_ERROR_OK && got.id == its_id && got.len == 0U &&
          got.flags == 0U && got.label[0] == 0U,
          "D3 its metadata is blanked through the door");
    rc = wh_Nvm_Read(&view, its_id, 0U, 16U, out);
    check(rc == WH_ERROR_ACCESS, "D3 reading it through the door is refused");
    rc = wh_Nvm_Read(&view, its_id, 0U, 0U, out);
    check(rc == WH_ERROR_ACCESS,
          "N1 a zero-length read of it through the door is refused too");
    rc = wh_Nvm_DestroyObjects(&view, 1U, &its_id);
    check(rc == WH_ERROR_ACCESS,
          "D3 destroying it through the door is refused");
    meta_init(&meta, its_id, 32U);
    wt_hsm_vault_make_label(meta.label, 4, -1, 0x66ULL, WT_VAULT_FLAG_KEY);
    rc = wh_Nvm_AddObject(&view, &meta, 32U, key_bytes);
    check(rc == WH_ERROR_ACCESS,
          "D3 overwriting it with a key object is refused");
    check(wt_hsm_vault_lookup_in(&view, TEST_ROGUE_PARTITION, 0, 0x77ULL,
                                 NULL, NULL, &free_id) ==
              PSA_ERROR_DOES_NOT_EXIST && free_id != its_id &&
          free_id != window_key_id,
          "D3 its slot is neither matched nor offered as free");
    check(wt_hsm_vault_backend.get(TEST_ROGUE_PARTITION, 0, 0x77ULL, 0U, out,
                                   sizeof(out), &got_len) == PSA_SUCCESS &&
          got_len == sizeof(its_bytes),
          "D3 the storage object is intact for its owner");

    /* D4: reserved ids and unflagged window adds. */
    rc = wh_Nvm_GetMetadata(&view, TEST_TABLE_ID, &got);
    check(rc == WH_ERROR_ACCESS, "D4 the directory table id is unreachable");
    rc = wh_Nvm_Read(&view, (whNvmId)WT_HSM_SEAL_KEY_ID, 0U, 32U, out);
    check(rc == WH_ERROR_ACCESS, "D4 the seal key id is unreachable");
    meta_init(&meta, (whNvmId)WT_HSM_ROLLBACK_TABLE_ID, 32U);
    rc = wh_Nvm_AddObject(&view, &meta, 32U, key_bytes);
    check(rc == WH_ERROR_ACCESS, "D4 the rollback table id is unreachable");
    rc = wh_Nvm_GetMetadata(&view, TEST_STAGE_ID, &got);
    check(rc == WH_ERROR_ACCESS, "D4 the stage id is unreachable");
    rc = wh_Nvm_GetMetadata(&view, (whNvmId)0x0001U, &got);
    check(rc == WH_ERROR_ACCESS, "D4 an id outside every window is unreachable");
    meta_init(&meta, (whNvmId)(TEST_WINDOW_BASE + 5U), 32U);
    wt_hsm_vault_make_label(meta.label, 4, -1, 0x88ULL, 0U);
    rc = wh_Nvm_AddObject(&view, &meta, 32U, key_bytes);
    check(rc == WH_ERROR_ACCESS,
          "D4 a window add without the key flag is refused");

    /* D5: reclaim, and destroying the crypto partition's own objects. */
    rc = wh_Nvm_DestroyObjects(&view, 0U, NULL);
    check(rc == WH_ERROR_OK, "D5 reclaim through the door is allowed");
    rc = wh_Nvm_DestroyObjectsChecked(&view, 1U, &window_key_id);
    check(rc == WH_ERROR_OK, "D5 the key-flagged window object is destroyed");
    check(wt_hsm_vault_lookup_in(&view, 4, -1, 0x55ULL, NULL, NULL, NULL) ==
              PSA_ERROR_DOES_NOT_EXIST,
          "D5 the destroyed key object is gone");
    id = TEST_KEYSTORE_ID;
    rc = wh_Nvm_DestroyObjects(&view, 1U, &id);
    check(rc == WH_ERROR_OK, "D5 the keystore object is destroyed");
    rc = wh_Nvm_GetMetadata(&view, TEST_KEYSTORE_ID, &got);
    check(rc == WH_ERROR_NOTFOUND, "D5 the destroyed keystore object is gone");

    /* D6: only the registered crypto partition passes the door. */
    check(wt_nvm_client_bind(&rogue, &rogue_view, wt_spm_transport_direct,
                             &g_runtime, TEST_ROGUE_PARTITION,
                             TEST_VAULT_SID) == 0,
          "D6 another partition binds a store view");
    meta_init(&meta, TEST_KEYSTORE_ID, 48U);
    rc = wh_Nvm_AddObject(&rogue_view, &meta, 48U, key_bytes);
    check(rc == WH_ERROR_ACCESS, "D6 its add is refused at the door");
    rc = wh_Nvm_GetMetadata(&rogue_view, TEST_KEYSTORE_ID, &got);
    check(rc == WH_ERROR_ACCESS, "D6 its metadata read is refused at the door");
    rc = wh_Nvm_GetAvailable(&rogue_view, &avail_size, &avail_objects,
                             &reclaim_size, &reclaim_objects);
    check(rc == WH_ERROR_ACCESS, "D6 its availability query is refused");

    /* D7: storage faces never serve key objects. */
    meta_init(&meta, TEST_WINDOW_BASE + 3U, 32U);
    wt_hsm_vault_make_label(meta.label, TEST_ROGUE_PARTITION, 0, 0x99ULL,
                            WT_VAULT_FLAG_KEY);
    rc = wh_Nvm_AddObject(&view, &meta, 32U, key_bytes);
    check(rc == WH_ERROR_OK, "D7 a key object under a storage owner's ids");
    check(wt_hsm_vault_backend.get(TEST_ROGUE_PARTITION, 0, 0x99ULL, 0U, out,
                                   sizeof(out), &got_len) ==
              PSA_ERROR_NOT_PERMITTED,
          "D7 the storage face refuses to serve the key object");

    /* R1: the vault restarts while the door connection is idle. */
    test_partition_restart(TEST_VAULT_PARTITION);
    meta_init(&meta, TEST_KEYSTORE_ID, (whNvmSize)sizeof(key_bytes));
    rc = wh_Nvm_AddObject(&view, &meta, (whNvmSize)sizeof(key_bytes),
                          key_bytes);
    check(rc == WH_ERROR_OK && g_panics == 0U,
          "R1 after a vault restart the idle door reconnects without a panic");
    rc = wh_Nvm_GetMetadata(&view, TEST_KEYSTORE_ID, &got);
    check(rc == WH_ERROR_OK && got.len == sizeof(key_bytes),
          "R1 the reconnected door serves reads");

    /* R2: the vault faults under a request in flight. */
    g_fault_partition = TEST_VAULT_PARTITION;
    rc = wh_Nvm_Read(&view, TEST_KEYSTORE_ID, 0U, 16U, out);
    check(rc == WH_ERROR_ABORTED && g_fault_partition == 0 &&
          g_panics == 0U,
          "R2 a request torn by a vault fault fails with a defined error");
    (void)memset(out, 0, sizeof(out));
    rc = wh_Nvm_Read(&view, TEST_KEYSTORE_ID, 0U, 16U, out);
    check(rc == WH_ERROR_OK && memcmp(out, key_bytes, 16U) == 0 &&
          g_panics == 0U,
          "R2 the next request reconnects and is served");

    /* R3: dropped connections are closed, not leaked. */
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS + 2U; i++) {
        test_partition_restart(TEST_VAULT_PARTITION);
        rc = wh_Nvm_GetMetadata(&view, TEST_KEYSTORE_ID, &got);
        if (rc != WH_ERROR_OK) {
            break;
        }
    }
    check(rc == WH_ERROR_OK && g_panics == 0U,
          "R3 the door outlives more restarts than there are connection slots");
    id = TEST_KEYSTORE_ID;
    rc = wh_Nvm_DestroyObjects(&view, 1U, &id);
    check(rc == WH_ERROR_OK, "R3 the keystore object is destroyed");
    g_fault_client = NULL;

    /* L1: the declared length must match the transferred object. */
    handle = wt_ffm_connect(&g_runtime, TEST_HSM_PARTITION, TEST_VAULT_SID,
                            1U);
    check(PSA_HANDLE_IS_VALID(handle), "L1 the crypto partition connects");
    (void)memset(&nreq, 0, sizeof(nreq));
    nreq.id = (whNvmId)(TEST_KEYSTORE_ID + 3U);
    nreq.access = WH_NVM_ACCESS_ANY;
    in_vec[0].base = &nreq;
    in_vec[0].len = sizeof(nreq);
    in_vec[1].base = key_bytes;
    in_vec[1].len = sizeof(key_bytes);
    nreq.len = (uint32_t)sizeof(key_bytes) - 1U;
    status = wt_ffm_call(&g_runtime, TEST_HSM_PARTITION, handle,
                         WT_VAULT_OP_NVM_ADD_OBJECT, in_vec, 2U, NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "L1 a declared length shorter than the object is refused");
    nreq.len = (uint32_t)sizeof(key_bytes) + 1U;
    status = wt_ffm_call(&g_runtime, TEST_HSM_PARTITION, handle,
                         WT_VAULT_OP_NVM_ADD_OBJECT, in_vec, 2U, NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "L1 a declared length longer than the object is refused");
    nreq.len = (uint32_t)sizeof(key_bytes);
    status = wt_ffm_call(&g_runtime, TEST_HSM_PARTITION, handle,
                         WT_VAULT_OP_NVM_ADD_OBJECT, in_vec, 2U, NULL, 0U);
    check(status == PSA_SUCCESS, "L1 the matching declared length is accepted");
    (void)wt_ffm_close(&g_runtime, TEST_HSM_PARTITION, handle);
    id = (whNvmId)(TEST_KEYSTORE_ID + 3U);
    rc = wh_Nvm_DestroyObjects(&view, 1U, &id);
    check(rc == WH_ERROR_OK, "L1 the object is destroyed");

    /* C1: cleanup releases the connection, so rebinding never exhausts
     * the crypto partition's connection slots. */
    rc = WH_ERROR_ABORTED;
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS + 2U; i++) {
        if (wt_nvm_client_bind(&cycle, &cycle_view, test_sp_transport,
                               &g_runtime, TEST_HSM_PARTITION,
                               TEST_VAULT_SID) != 0) {
            rc = WH_ERROR_ABORTED;
            break;
        }
        rc = wh_Nvm_GetAvailable(&cycle_view, &avail_size, &avail_objects,
                                 &reclaim_size, &reclaim_objects);
        (void)wh_Nvm_Cleanup(&cycle_view);
        if (rc != WH_ERROR_OK) {
            break;
        }
    }
    check(rc == WH_ERROR_OK && g_panics == 0U,
          "C1 bind, use, and cleanup cycles do not consume connection slots");

    /* Z1/Z2: the vault wipes its copied transfer buffers before release. */
    for (i = 0U; i < sizeof(g_probe_pattern); i++) {
        g_probe_pattern[i] = (uint8_t)(0xC3U ^ (i * 7U));
    }
    meta_init(&meta, TEST_KEYSTORE_ID, (whNvmSize)sizeof(g_probe_pattern));
    g_wipe_checks = 0U;
    g_wipe_dirty = 0U;
    rc = wh_Nvm_AddObject(&view, &meta, (whNvmSize)sizeof(g_probe_pattern),
                          g_probe_pattern);
    status = (wh_Nvm_Read(&view, TEST_KEYSTORE_ID, 0U,
                          (whNvmSize)sizeof(g_probe_pattern), out) ==
              WH_ERROR_OK) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
    check(rc == WH_ERROR_OK && status == PSA_SUCCESS &&
          memcmp(out, g_probe_pattern, sizeof(g_probe_pattern)) == 0,
          "Z1 the probe object round-trips through the keystore door");
    check(g_wipe_checks >= 2U && g_wipe_dirty == 0U,
          "Z1 the keystore door's copied buffer is zeroed before release");
    id = TEST_KEYSTORE_ID;
    rc = wh_Nvm_DestroyObjects(&view, 1U, &id);
    check(rc == WH_ERROR_OK, "Z1 the probe object is destroyed");

    handle = wt_ffm_connect(&g_runtime, TEST_ROGUE_PARTITION,
                            TEST_VAULT_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle), "Z2 a storage owner connects");
    (void)memset(&vreq, 0, sizeof(vreq));
    vreq.uid = 0x5A5AULL;
    in_vec[0].base = &vreq;
    in_vec[0].len = sizeof(vreq);
    in_vec[1].base = g_probe_pattern;
    in_vec[1].len = sizeof(g_probe_pattern);
    g_wipe_checks = 0U;
    g_wipe_dirty = 0U;
    status = wt_ffm_call(&g_runtime, TEST_ROGUE_PARTITION, handle,
                         WT_VAULT_OP_SET, in_vec, 2U, NULL, 0U);
    (void)memset(out, 0, sizeof(out));
    out_vec[0].base = out;
    out_vec[0].len = sizeof(g_probe_pattern);
    rc = (wt_ffm_call(&g_runtime, TEST_ROGUE_PARTITION, handle,
                      WT_VAULT_OP_GET, in_vec, 1U, out_vec, 1U) ==
          PSA_SUCCESS) ? WH_ERROR_OK : WH_ERROR_ABORTED;
    check(status == PSA_SUCCESS && rc == WH_ERROR_OK &&
          memcmp(out, g_probe_pattern, sizeof(g_probe_pattern)) == 0,
          "Z2 the probe object round-trips through the storage face");
    check(g_wipe_checks >= 4U && g_wipe_dirty == 0U,
          "Z2 the storage face's copied buffers are zeroed before release");
    (void)wt_ffm_close(&g_runtime, TEST_ROGUE_PARTITION, handle);
    check(wt_hsm_vault_backend.remove(TEST_ROGUE_PARTITION, 0,
                                      0x5A5AULL) == PSA_SUCCESS,
          "Z2 the probe object is removed");
}

static int token_carries_door_signature(const uint8_t* token, size_t len)
{
    uint8_t expected[WT_HSM_ATTEST_SIGNATURE_LEN];
    size_t i;

    for (i = 0U; i < sizeof(expected); i++) {
        expected[i] = (uint8_t)(0xA0U + i);
    }
    if (len < sizeof(expected)) {
        return 0;
    }
    for (i = 0U; i + sizeof(expected) <= len; i++) {
        if (memcmp(token + i, expected, sizeof(expected)) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_attest_door(void)
{
    wt_boot_handoff_t handoff;
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_32];
    uint8_t token[WT_ATTEST_MAX_TOKEN_SIZE];
    uint8_t public_key[WT_ATTEST_IAK_PUBLIC_KEY_SIZE];
    uint8_t digest[WT_HSM_ATTEST_DIGEST_LEN];
    uint8_t signature[WT_HSM_ATTEST_SIGNATURE_LEN];
    psa_invec in_vec[1];
    psa_outvec out_vec[1];
    psa_handle_t handle;
    size_t token_len = 0U;
    size_t public_key_len = 0U;
    size_t i;
    psa_status_t status;

    for (i = 0U; i < sizeof(g_door_public_key); i++) {
        g_door_public_key[i] = (uint8_t)(i == 0U ? 0x04U : i);
    }
    for (i = 0U; i < sizeof(challenge); i++) {
        challenge[i] = (uint8_t)(0x30U + i);
    }
    (void)memset(&handoff, 0, sizeof(handoff));
    handoff.magic = WT_BOOT_HANDOFF_MAGIC;
    handoff.version = WT_BOOT_HANDOFF_VERSION;
    handoff.lifecycle = 0x3000U;
    handoff.hash_algorithm = WT_BOOT_HANDOFF_HASH_SHA256;
    handoff.measurement_size = WT_BOOT_HANDOFF_DIGEST_SIZE;
    (void)memset(handoff.measurement, 0xAB, sizeof(handoff.measurement));
    check(wt_initial_attest_init(&handoff) == WT_ATTEST_SUCCESS,
          "attestation state initialised from the boot handoff");

    /* A1 */
    check(wt_initial_attest_get_iak_public_key(public_key,
              sizeof(public_key), &public_key_len) == WT_ATTEST_ERROR_NOT_READY,
          "A1 unbound, the attestation partition has no signer");

    /* A2 */
    check(wt_initial_attest_bind_hsm(test_sp_transport, &g_runtime,
                                     TEST_ATTEST_PARTITION, TEST_HSM_SID) ==
              WT_ATTEST_SUCCESS,
          "A2 attestation binds its signer to SERVICE_HSM");
    check(wt_initial_attest_get_iak_public_key(public_key,
              sizeof(public_key), &public_key_len) == WT_ATTEST_SUCCESS &&
          public_key_len == sizeof(g_door_public_key) &&
          memcmp(public_key, g_door_public_key, sizeof(public_key)) == 0,
          "A2 the IAK public key comes through the door");
    g_sign_calls = 0U;
    check(wt_initial_attest_get_token(0U, challenge, sizeof(challenge), token,
                                      sizeof(token), &token_len) ==
              WT_ATTEST_SUCCESS && token_len > 0U,
          "A2 a token is issued");
    check(g_sign_calls == 1U, "A2 exactly one signature crossed the door");
    check(token_carries_door_signature(token, token_len),
          "A2 the token carries the door's signature");
    check(wt_initial_attest_get_token_size(sizeof(challenge), &token_len) ==
              WT_ATTEST_SUCCESS && token_len > 0U,
          "A2 the token size query runs through the door");

    /* R4: the crypto partition restarts while the door connection is idle. */
    test_partition_restart(TEST_HSM_PARTITION);
    (void)memset(public_key, 0, sizeof(public_key));
    check(wt_initial_attest_get_iak_public_key(public_key,
              sizeof(public_key), &public_key_len) == WT_ATTEST_SUCCESS &&
          memcmp(public_key, g_door_public_key, sizeof(public_key)) == 0 &&
          g_panics == 0U,
          "R4 after a crypto partition restart the idle door reconnects");

    /* R5: the crypto partition faults under a token signature in flight. */
    g_fault_partition = TEST_HSM_PARTITION;
    check(wt_initial_attest_get_token(0U, challenge, sizeof(challenge), token,
                                      sizeof(token), &token_len) !=
              WT_ATTEST_SUCCESS && g_fault_partition == 0 && g_panics == 0U,
          "R5 a token torn by a crypto partition fault fails, no panic");
    g_sign_calls = 0U;
    check(wt_initial_attest_get_token(0U, challenge, sizeof(challenge), token,
                                      sizeof(token), &token_len) ==
              WT_ATTEST_SUCCESS && token_len > 0U && g_sign_calls == 1U &&
          token_carries_door_signature(token, token_len) && g_panics == 0U,
          "R5 the next token reconnects and carries the door's signature");

    /* A3 */
    (void)memset(digest, 0x11, sizeof(digest));
    in_vec[0].base = digest;
    in_vec[0].len = sizeof(digest);
    out_vec[0].base = signature;
    out_vec[0].len = sizeof(signature);
    handle = wt_ffm_connect(&g_runtime, TEST_NS_CLIENT, TEST_HSM_SID, 1U);
    check(PSA_HANDLE_IS_VALID(handle), "A3 a Non-secure client reaches SERVICE_HSM");
    status = wt_ffm_call(&g_runtime, TEST_NS_CLIENT, handle,
                         WT_HSM_OP_ATTEST_SIGN, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "A3 a Non-secure client is refused at the attestation door");
    status = wt_ffm_call(&g_runtime, TEST_NS_CLIENT, handle,
                         WT_HSM_OP_ATTEST_PUBLIC_KEY, NULL, 0U, out_vec, 1U);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "A3 a Non-secure client cannot read the public key door");
    (void)wt_ffm_close(&g_runtime, TEST_NS_CLIENT, handle);

    handle = wt_ffm_connect(&g_runtime, TEST_ROGUE_PARTITION, TEST_HSM_SID,
                            1U);
    check(PSA_HANDLE_IS_VALID(handle), "A3 another partition reaches SERVICE_HSM");
    status = wt_ffm_call(&g_runtime, TEST_ROGUE_PARTITION, handle,
                         WT_HSM_OP_ATTEST_SIGN, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "A3 another partition is refused at the attestation door");
    (void)wt_ffm_close(&g_runtime, TEST_ROGUE_PARTITION, handle);

    handle = wt_ffm_connect(&g_runtime, TEST_ATTEST_PARTITION, TEST_HSM_SID,
                            1U);
    check(PSA_HANDLE_IS_VALID(handle), "A3 the attestation partition connects");
    in_vec[0].len = sizeof(digest) - 1U;
    status = wt_ffm_call(&g_runtime, TEST_ATTEST_PARTITION, handle,
                         WT_HSM_OP_ATTEST_SIGN, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "A3 a malformed digest is refused at the attestation door");
    in_vec[0].len = sizeof(digest);
    out_vec[0].len = sizeof(signature) - 1U;
    status = wt_ffm_call(&g_runtime, TEST_ATTEST_PARTITION, handle,
                         WT_HSM_OP_ATTEST_SIGN, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "A3 a short signature buffer is refused at the attestation door");
    out_vec[0].len = sizeof(signature);
    g_sign_calls = 0U;
    status = wt_ffm_call(&g_runtime, TEST_ATTEST_PARTITION, handle,
                         WT_HSM_OP_ATTEST_SIGN, in_vec, 1U, out_vec, 1U);
    check(status == PSA_SUCCESS && g_sign_calls == 1U &&
          memcmp(g_last_digest, digest, sizeof(digest)) == 0,
          "A3 the attestation partition's own request is served");
    (void)wt_ffm_close(&g_runtime, TEST_ATTEST_PARTITION, handle);
}

static void test_pool_reserve(void)
{
    psa_handle_t ns_handles[WT_FFM_MAX_CONNECTIONS];
    wt_nvm_client_t client;
    whNvmContext view;
    psa_handle_t handle = PSA_NULL_HANDLE;
    uint32_t avail_size = 0U;
    uint32_t reclaim_size = 0U;
    whNvmId avail_objects = 0U;
    whNvmId reclaim_objects = 0U;
    size_t taken = 0U;
    size_t i;

    /* S1: two Non-secure clients take everything the pool lets them. */
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        handle = wt_ffm_connect(&g_runtime,
                                (i & 1U) != 0U ? -2 : TEST_NS_CLIENT,
                                TEST_HSM_SID, 1U);
        if (!PSA_HANDLE_IS_VALID(handle)) {
            break;
        }
        ns_handles[taken++] = handle;
    }
    check(taken == WT_FFM_MAX_NS_CONNECTIONS &&
          handle == (psa_handle_t)PSA_ERROR_CONNECTION_BUSY,
          "S1 Non-secure clients are refused once their share is taken");
    check(wt_nvm_client_bind(&client, &view, test_sp_transport, &g_runtime,
                             TEST_HSM_PARTITION, TEST_VAULT_SID) == 0 &&
          wh_Nvm_GetAvailable(&view, &avail_size, &avail_objects,
                              &reclaim_size, &reclaim_objects) ==
              WH_ERROR_OK && g_panics == 0U,
          "S1 the keystore door still connects for the crypto partition");
    handle = wt_ffm_connect(&g_runtime, TEST_ATTEST_PARTITION, TEST_HSM_SID,
                            1U);
    check(PSA_HANDLE_IS_VALID(handle),
          "S1 the attestation partition still reaches SERVICE_HSM");
    (void)wt_ffm_close(&g_runtime, TEST_ATTEST_PARTITION, handle);
    (void)wh_Nvm_Cleanup(&view);
    for (i = 0U; i < taken; i++) {
        (void)wt_ffm_close(&g_runtime, (i & 1U) != 0U ? -2 : TEST_NS_CLIENT,
                           ns_handles[i]);
    }
}

static void test_vault_random_face(void)
{
    uint8_t out[32];
    wt_vault_req_t req;
    psa_invec in_vec[1];
    psa_outvec out_vec[1];
    psa_handle_t handle;
    psa_status_t status;
    size_t i;
    int nonzero = 0;

    /* V1: the face is installed before its DRBG is seeded (as the engines
     * install it at boot) and fails closed, not unsupported, until then. */
    wt_vault_service_set_rng(wt_hsm_vault_random);
    handle = wt_ffm_connect(&g_runtime, TEST_ROGUE_PARTITION, TEST_VAULT_SID,
                            1U);
    check(PSA_HANDLE_IS_VALID(handle), "V1 a partition reaches SERVICE_VAULT");
    (void)memset(&req, 0, sizeof(req));
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    (void)memset(out, 0, sizeof(out));
    out_vec[0].base = out;
    out_vec[0].len = sizeof(out);
    status = wt_ffm_call(&g_runtime, TEST_ROGUE_PARTITION, handle,
                         WT_VAULT_OP_RANDOM, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_BAD_STATE,
          "V1 RANDOM fails closed while the vault DRBG is unseeded");
    check(wt_hsm_vault_rng_init() == 0, "V1 the band bring-up seeds the DRBG");
    out_vec[0].len = sizeof(out);
    status = wt_ffm_call(&g_runtime, TEST_ROGUE_PARTITION, handle,
                         WT_VAULT_OP_RANDOM, in_vec, 1U, out_vec, 1U);
    for (i = 0U; i < sizeof(out); i++) {
        nonzero |= out[i];
    }
    check(status == PSA_SUCCESS && out_vec[0].len == sizeof(out) &&
          nonzero != 0, "V1 RANDOM serves once the DRBG is seeded");
    (void)wt_ffm_close(&g_runtime, TEST_ROGUE_PARTITION, handle);
    wt_vault_service_set_rng(NULL);
}

static void test_door_confinement(void)
{
    static const uint8_t blob[16] = "confined-object";
    uint8_t out[32];
    uint8_t packet[8];
    wt_vault_req_t req;
    psa_invec in_vec[2];
    psa_outvec out_vec[1];
    psa_handle_t handle;
    psa_status_t status;
    size_t got_len = 0U;

    /* K1: the crypto partition holds a vault connection for the keystore
     * door only; every ordinary face refuses it. */
    wt_vault_service_set_rng(wt_hsm_vault_random);
    handle = wt_ffm_connect(&g_runtime, TEST_HSM_PARTITION, TEST_VAULT_SID,
                            1U);
    check(PSA_HANDLE_IS_VALID(handle),
          "K1 the crypto partition connects to SERVICE_VAULT");
    (void)memset(&req, 0, sizeof(req));
    req.uid = 0x4B31ULL;
    in_vec[0].base = &req;
    in_vec[0].len = sizeof(req);
    in_vec[1].base = blob;
    in_vec[1].len = sizeof(blob);
    status = wt_ffm_call(&g_runtime, TEST_HSM_PARTITION, handle,
                         WT_VAULT_OP_SET, in_vec, 2U, NULL, 0U);
    check(status == PSA_ERROR_NOT_PERMITTED &&
          wt_hsm_vault_backend.get(TEST_HSM_PARTITION, 0, 0x4B31ULL, 0U, out,
                                   sizeof(out), &got_len) ==
              PSA_ERROR_DOES_NOT_EXIST,
          "K1 a storage set from the crypto partition is refused, no object");
    out_vec[0].base = out;
    out_vec[0].len = sizeof(out);
    status = wt_ffm_call(&g_runtime, TEST_HSM_PARTITION, handle,
                         WT_VAULT_OP_GET, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "K1 a storage get from the crypto partition is refused");
    out_vec[0].len = sizeof(out);
    status = wt_ffm_call(&g_runtime, TEST_HSM_PARTITION, handle,
                         WT_VAULT_OP_RANDOM, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "K1 RANDOM from the crypto partition is refused");
    status = wt_ffm_call(&g_runtime, TEST_HSM_PARTITION, handle,
                         WT_VAULT_OP_KEY_GENERATE, in_vec, 1U, NULL, 0U);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "K1 a key face request from the crypto partition is refused");
    (void)wt_ffm_close(&g_runtime, TEST_HSM_PARTITION, handle);
    wt_vault_service_set_rng(NULL);

    /* K2: SERVICE_HSM's ordinary wire is for Non-secure clients. */
    wt_hsm_relay_set_submit(test_relay_submit, NULL);
    (void)memset(packet, 0x11, sizeof(packet));
    in_vec[0].base = packet;
    in_vec[0].len = sizeof(packet);
    out_vec[0].base = out;
    out_vec[0].len = sizeof(out);
    g_submit_calls = 0U;
    handle = wt_ffm_connect(&g_runtime, TEST_ATTEST_PARTITION, TEST_HSM_SID,
                            1U);
    check(PSA_HANDLE_IS_VALID(handle),
          "K2 the attestation partition connects to SERVICE_HSM");
    status = wt_ffm_call(&g_runtime, TEST_ATTEST_PARTITION, handle,
                         PSA_IPC_CALL, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_NOT_PERMITTED && g_submit_calls == 0U,
          "K2 the attestation partition is refused on the ordinary wire");
    (void)wt_ffm_close(&g_runtime, TEST_ATTEST_PARTITION, handle);
    handle = wt_ffm_connect(&g_runtime, TEST_ROGUE_PARTITION, TEST_HSM_SID,
                            1U);
    status = wt_ffm_call(&g_runtime, TEST_ROGUE_PARTITION, handle,
                         PSA_IPC_CALL, in_vec, 1U, out_vec, 1U);
    check(status == PSA_ERROR_NOT_PERMITTED && g_submit_calls == 0U,
          "K2 another partition is refused on the ordinary wire");
    (void)wt_ffm_close(&g_runtime, TEST_ROGUE_PARTITION, handle);
    handle = wt_ffm_connect(&g_runtime, TEST_NS_CLIENT, TEST_HSM_SID, 1U);
    out_vec[0].len = sizeof(out);
    status = wt_ffm_call(&g_runtime, TEST_NS_CLIENT, handle, PSA_IPC_CALL,
                         in_vec, 1U, out_vec, 1U);
    check(status == PSA_SUCCESS && g_submit_calls == 1U &&
          out_vec[0].len == 1U && out[0] == 0x5AU,
          "K2 a Non-secure client is served on the ordinary wire");
    (void)wt_ffm_close(&g_runtime, TEST_NS_CLIENT, handle);
    wt_hsm_relay_set_submit(NULL, NULL);
}

int main(void)
{
    if (store_up() != 0) {
        (void)fprintf(stderr, "store setup failed\n");
        return 1;
    }
    if (runtime_up() != 0) {
        (void)fprintf(stderr, "runtime setup failed\n");
        return 1;
    }
    test_pool_reserve();
    test_vault_random_face();
    test_door_confinement();
    test_nvm_door();
    test_attest_door();
    check(g_panics == 0U,
          "no door client was ever classified for a must-panic error");
    if (g_failures != 0) {
        (void)printf("keystore_ipc: %d failures\n", g_failures);
        return 1;
    }
    (void)printf("PASS: keystore_ipc\n");
    return 0;
}
