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

/* Host proof of the OS-neutral PSA storage client (SRC-PSA-STORAGE): the
 * public psa_its_* / psa_ps_* calls from src/client/psa_storage_client.c
 * marshal onto SERVICE_ITS / SERVICE_PS through the same OS-neutral FF-M
 * client the target links (src/client/psa_ffm_client.c). Host stubs supply the
 * Armv8-M CMSE veneers, routing them to the in-process FF-M runtime that runs
 * the real storage dispatch, the real gated vault, and the real wolfHSM NVM
 * stack on the RAM flash simulator. It proves the neutral client marshals the
 * wire header and object bytes, writes the reply length back, and enforces the
 * PSA Storage 1.0 argument rules before any IPC — with no operating-system
 * dependency. */

#include "wolftrust/ffm.h"
#include "wolftrust/ffm_veneer.h"
#include "wolftrust/services/storage_service.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/hsm.h"

#include "psa/client.h"
#include "psa/error.h"
#include "psa/storage_common.h"
#include "psa/internal_trusted_storage.h"
#include "psa/protected_storage.h"
#include "psa_manifest/sid.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_VAULT_PARTITION 5
#define TEST_VAULT_SID       4098U
#define TEST_ITS_PARTITION   6
#define TEST_PS_PARTITION    7
#define TEST_NS_CLIENT       (-1)

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];
static wt_ffm_runtime_t* g_rt;
static int g_failures;
static void* g_output;
static size_t g_output_size;
static unsigned int g_storage_dispatches;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    } else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static int all_zero(const uint8_t* buf, size_t len)
{
    size_t i;

    for (i = 0U; i < len; i++) {
        if (buf[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

/* ---- host memcheck standing in for the Armv8-M CMSE checker ---- */
static int test_check_read(void* context, psa_client_id_t caller,
                           const void* address, size_t size)
{
    (void)context;
    (void)caller;
    return size == 0U || address != NULL;
}

/* Caller memory ends well short of this span, as on an LP64 Normal world. */
#define TEST_CALLER_SPAN (1024U * 1024U)

static int test_check_write(void* context, psa_client_id_t caller,
                            void* address, size_t size)
{
    (void)context;
    (void)caller;
    if (address == g_output && size > g_output_size) {
        return 0;
    }
    return size == 0U || (address != NULL && size <= TEST_CALLER_SPAN);
}

static void test_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
}

/* Fallback port dispatch: never used — every partition registers its own. */
static int test_dispatch(void* context, wt_ffm_runtime_t* runtime,
                         int32_t partition_id)
{
    (void)context;
    (void)runtime;
    (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

static int test_storage_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                 int32_t partition_id)
{
    g_storage_dispatches++;
    return wt_storage_service_dispatch(context, runtime, partition_id);
}

static const wt_ffm_port_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    test_dispatch,
    test_panic
};

/* ---- host stubs for the Armv8-M NS->S veneers: route to the runtime ---- */
int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version)
{
    return (int32_t)wt_ffm_connect(g_rt, TEST_NS_CLIENT, sid, version);
}

void WolfTrust_FFM_Close(int32_t handle)
{
    (void)wt_ffm_close(g_rt, TEST_NS_CLIENT, handle);
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
        wt_ffm_call_refuse(g_rt, TEST_NS_CLIENT, handle);
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
    st = wt_ffm_call(g_rt, TEST_NS_CLIENT, handle, type, in, iv->in_count,
                     out, iv->out_count);
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

/* ---- manifest fixture: vault + ITS + PS as production declares them ---- */
static const wt_service_descriptor_t g_vault_services[] = {
    {
        "SERVICE_VAULT", TEST_VAULT_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 0U, 1U
    }
};

static const wt_service_descriptor_t g_its_services[] = {
    {
        "SERVICE_ITS", SERVICE_ITS_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const wt_service_descriptor_t g_ps_services[] = {
    {
        "SERVICE_PS", SERVICE_PS_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const uint32_t g_its_deps[] = { TEST_VAULT_SID };
static const uint32_t g_ps_deps[] = { TEST_VAULT_SID };

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
    },
    {
        "PARTITION_PS", TEST_PS_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_ps_services, 1U, g_ps_deps, 1U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "psa-storage-client-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

int main(void)
{
    static const uint8_t object[] = "its-client-secret";
    static const uint8_t ps_object[] = "ps-client-secret";
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
    wt_storage_service_ctx_t ps_ctx;
    struct psa_storage_info_t info;
    uint8_t buffer[64];
    uint8_t big[600];
    uint8_t large[2048];
    unsigned int dispatches;
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
    /* PS seals every object; bind the AES-GCM sealer over the same NVM. */
    if (wt_hsm_seal_init(&nvm_ctx) != 0) {
        (void)fprintf(stderr, "wt_hsm_seal_init failed\n");
        return 1;
    }
    wt_hsm_vault_set_sealer(&wt_hsm_sealer);

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
                                  test_storage_dispatch, &its_ctx) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "ITS register failed\n");
        return 1;
    }
    (void)memset(&ps_ctx, 0, sizeof(ps_ctx));
    ps_ctx.transport = wt_spm_transport_direct;
    ps_ctx.vault_sid = TEST_VAULT_SID;
    ps_ctx.vault_handle = 0;
    ps_ctx.client_flags_mask = WT_VAULT_FLAG_WRITE_ONCE |
                               WT_VAULT_FLAG_NO_CONFIDENTIALITY |
                               WT_VAULT_FLAG_NO_REPLAY;
    ps_ctx.vault_flags = WT_VAULT_FLAG_SEALED;
    ps_ctx.caps = 0U;
    if (wt_ffm_register_partition(&runtime, TEST_PS_PARTITION,
                                  test_storage_dispatch, &ps_ctx) !=
            WT_FFM_SUCCESS) {
        (void)fprintf(stderr, "PS register failed\n");
        return 1;
    }
    g_rt = &runtime;

    /* ---- ITS through the public client ---- */
    status = psa_its_set(0x1111ULL, sizeof(object), object, 0U);
    check(status == PSA_SUCCESS,
          "psa_its_set stores an object through the neutral client");
    (void)memset(buffer, 0, sizeof(buffer));
    status = psa_its_get(0x1111ULL, 0U, sizeof(buffer), buffer, &got);
    check(status == PSA_SUCCESS && got == sizeof(object) &&
          memcmp(buffer, object, sizeof(object)) == 0,
          "psa_its_get returns the stored object and writes the length back");
    (void)memset(&info, 0, sizeof(info));
    status = psa_its_get_info(0x1111ULL, &info);
    check(status == PSA_SUCCESS && info.size == sizeof(object) &&
          info.flags == 0U,
          "psa_its_get_info reports the object size and passed-through flags");
    (void)memset(buffer, 0, sizeof(buffer));
    status = psa_its_get(0x1111ULL, 4U, sizeof(buffer), buffer, &got);
    check(status == PSA_SUCCESS && got == sizeof(object) - 4U &&
          memcmp(buffer, object + 4U, got) == 0,
          "psa_its_get honors the read offset");

    /* A destination larger than one copied transfer still reads the object. */
    g_output = large;
    g_output_size = sizeof(large);
    (void)memset(large, 0, sizeof(large));
    status = psa_its_get(0x1111ULL, 0U,
                         WT_FFM_TRANSFER_BYTES - sizeof(wt_vault_req_t) + 4U,
                         large, &got);
    check(status == PSA_SUCCESS && got == sizeof(object) &&
          memcmp(large, object, sizeof(object)) == 0,
          "psa_its_get reads into a buffer above the vault reply bound");
    (void)memset(large, 0, sizeof(large));
    dispatches = g_storage_dispatches;
    status = psa_its_get(0x1111ULL, 0U, sizeof(large), large, &got);
    check(status == PSA_SUCCESS && got == sizeof(object) &&
          memcmp(large, object, sizeof(object)) == 0 &&
          g_storage_dispatches == dispatches + 3U,
          "WT-FFM-0035: oversized valid ITS buffer dispatches one read");
    (void)memset(large, 0, sizeof(large));
    dispatches = g_storage_dispatches;
    status = psa_its_get(0x1111ULL, 0U, sizeof(large) + 1U, large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT &&
          all_zero(large, sizeof(large)) &&
          g_storage_dispatches == dispatches + 2U,
          "WT-FFM-0012: ITS validates the full range before capping");
    dispatches = g_storage_dispatches;
    status = psa_its_get(0x1111ULL, sizeof(object) - 2U, UINT32_MAX,
                         large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT &&
          all_zero(large, sizeof(large)) &&
          (g_storage_dispatches == dispatches ||
           g_storage_dispatches == dispatches + 2U),
          "WT-FFM-0012: ITS refuses the dev_apis s008 oversized range");
#if SIZE_MAX > UINT32_MAX
    status = psa_its_get(0x1111ULL, 0U, (size_t)UINT32_MAX + 1U,
                         large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT &&
          all_zero(large, sizeof(large)),
          "WT-FFM-0012: ITS refuses a range above the veneer length limit");
#endif
    (void)memset(large, 0, sizeof(large));
    status = psa_its_get(0x1111ULL, 0U, SIZE_MAX, large, &got);
    check(status != PSA_SUCCESS && all_zero(large, sizeof(large)),
          "psa_its_get refuses a buffer range that wraps the address space");
    (void)memset(large, 0, sizeof(large));
    got = 1U;
    status = psa_its_get(0x1111ULL, 0U, (size_t)TEST_CALLER_SPAN + 1U, large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT && got == 0U &&
          all_zero(large, sizeof(large)),
          "psa_its_get refuses a buffer range past the caller's memory");

    /* WRITE_ONCE lifecycle through the client. */
    status = psa_its_set(0x2222ULL, sizeof(object), object,
                         PSA_STORAGE_FLAG_WRITE_ONCE);
    check(status == PSA_SUCCESS, "psa_its_set(WRITE_ONCE) stores the object");
    status = psa_its_set(0x2222ULL, sizeof(object), object, 0U);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WRITE_ONCE uid refuses a second psa_its_set");
    status = psa_its_remove(0x2222ULL);
    check(status == PSA_ERROR_NOT_PERMITTED,
          "WRITE_ONCE uid refuses psa_its_remove");

    status = psa_its_remove(0x1111ULL);
    check(status == PSA_SUCCESS, "psa_its_remove deletes the object");
    status = psa_its_get(0x1111ULL, 0U, sizeof(buffer), buffer, &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST, "removed uid no longer exists");

    /* PSA Storage 1.0 argument rules, enforced client-side before any IPC. */
    status = psa_its_set(0x3333ULL, 5U, NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "psa_its_set rejects a NULL data pointer with nonzero length");
    (void)memset(big, 0x5A, sizeof(big));
    status = psa_its_set(0x3333ULL, sizeof(big), big, 0U);
    check(status == PSA_ERROR_INSUFFICIENT_STORAGE,
          "psa_its_set reports insufficient storage above the transfer bound");
    status = psa_its_get(0x1111ULL, 0U, sizeof(buffer), buffer, NULL);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "psa_its_get rejects a NULL length pointer");
    status = psa_its_get_info(0x1111ULL, NULL);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "psa_its_get_info rejects a NULL info pointer");

    /* ---- PS through the public client (sealed face) ---- */
    status = psa_ps_set(0x4444ULL, sizeof(ps_object), ps_object, 0U);
    check(status == PSA_SUCCESS,
          "psa_ps_set stores a sealed object through the client");
    (void)memset(buffer, 0, sizeof(buffer));
    status = psa_ps_get(0x4444ULL, 0U, sizeof(buffer), buffer, &got);
    check(status == PSA_SUCCESS && got == sizeof(ps_object) &&
          memcmp(buffer, ps_object, sizeof(ps_object)) == 0,
          "psa_ps_get returns the sealed object in the clear to its owner");
    (void)memset(large, 0, sizeof(large));
    dispatches = g_storage_dispatches;
    status = psa_ps_get(0x4444ULL, 0U, sizeof(large), large, &got);
    check(status == PSA_SUCCESS && got == sizeof(ps_object) &&
          memcmp(large, ps_object, sizeof(ps_object)) == 0 &&
          g_storage_dispatches == dispatches + 3U,
          "WT-FFM-0035: oversized valid PS buffer dispatches one read");
    (void)memset(large, 0, sizeof(large));
    dispatches = g_storage_dispatches;
    status = psa_ps_get(0x4444ULL, 0U, sizeof(large) + 1U, large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT &&
          all_zero(large, sizeof(large)) &&
          g_storage_dispatches == dispatches + 2U,
          "WT-FFM-0012: PS validates the full range before capping");
    dispatches = g_storage_dispatches;
    status = psa_ps_get(0x4444ULL, sizeof(ps_object) - 2U, UINT32_MAX,
                        large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT &&
          all_zero(large, sizeof(large)) &&
          (g_storage_dispatches == dispatches ||
           g_storage_dispatches == dispatches + 2U),
          "WT-FFM-0012: PS refuses the dev_apis s008 oversized range");
#if SIZE_MAX > UINT32_MAX
    status = psa_ps_get(0x4444ULL, 0U, (size_t)UINT32_MAX + 1U,
                        large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT &&
          all_zero(large, sizeof(large)),
          "WT-FFM-0012: PS refuses a range above the veneer length limit");
#endif
    (void)memset(large, 0, sizeof(large));
    status = psa_ps_get(0x4444ULL, 0U, SIZE_MAX, large, &got);
    check(status != PSA_SUCCESS && all_zero(large, sizeof(large)),
          "psa_ps_get refuses a buffer range that wraps the address space");
    (void)memset(large, 0, sizeof(large));
    got = 1U;
    status = psa_ps_get(0x4444ULL, 0U, (size_t)TEST_CALLER_SPAN + 1U, large, &got);
    check(status == PSA_ERROR_INVALID_ARGUMENT && got == 0U &&
          all_zero(large, sizeof(large)),
          "psa_ps_get refuses a buffer range past the caller's memory");
    (void)memset(&info, 0, sizeof(info));
    status = psa_ps_get_info(0x4444ULL, &info);
    check(status == PSA_SUCCESS && info.size == sizeof(ps_object) &&
          info.flags == 0U,
          "psa_ps_get_info hides the frontend's internal sealing flag");
    status = psa_ps_remove(0x4444ULL);
    check(status == PSA_SUCCESS, "psa_ps_remove deletes the sealed object");

    /* Optional PS surface the service does not implement. */
    check(psa_ps_get_support() == 0U,
          "psa_ps_get_support advertises no optional features");
    status = psa_ps_create(0x5555ULL, 32U, 0U);
    check(status == PSA_ERROR_NOT_SUPPORTED,
          "psa_ps_create is refused NOT_SUPPORTED");
    status = psa_ps_set_extended(0x5555ULL, 0U, sizeof(ps_object), ps_object);
    check(status == PSA_ERROR_NOT_SUPPORTED,
          "psa_ps_set_extended is refused NOT_SUPPORTED");

    if (g_failures != 0) {
        (void)printf("FAIL: psa_storage_client (%d failures)\n", g_failures);
        return 1;
    }
    (void)printf("PASS: psa_storage_client (OS-neutral PSA storage client)\n");
    return 0;
}
