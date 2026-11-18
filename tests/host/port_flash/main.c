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

/* The flash contract (WT-PORT-0003, WT-FWU-0002) on the production backend:
 * port/common/hsm_flash.c, hsm_flash_ctx.c and the port's flash_drv.c link
 * against a model of the device beneath the driver, and every case runs the
 * real wolfHSM store, FWU staging, conformance NVM sync and privilege gate
 * paths. Each case runs in its own process, since the backend keeps staging
 * state and the model keeps its array. */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "flash_array.h"
#include "flash_port.h"
#include "hsm_flash.h"
#include "memory_map.h"
#include "wolftrust/services/fwu_service.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_unit.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#if defined(WT_PORT_MODEL_STM32H563)
#include "stm32h563_model.h"
#endif

#define UNIT        WT_FLASH_PROGRAM_UNIT
#define SECTOR      WT_FLASH_SECTOR_SIZE
#define STORE_BASE  WT_HSM_NVM_FLASH_BASE_S
#define FWU_BASE    WT_FWU_UPDATE_FLASH_BASE_S
#define FWU_SIZE    WT_FWU_UPDATE_FLASH_SIZE
#define CAPACITY    (FWU_SIZE - WT_FWU_TRAILER_SIZE)
#define HEADER      0x400u
/* Objects sized to the port's store so three rounds fill and compact it. */
#define OBJECTS     16u
#define OBJECT_MAX  (WT_HSM_NVM_FLASH_SIZE / 64u)
#define ROUNDS      3u

static int checks;
static int failures;
static int g_unprivileged;
static uint32_t g_gate_calls[6];

static whNvmFlashContext g_nf_ctx;
static whNvmFlashConfig g_nf_cfg;
static whNvmContext g_nvm;
static whNvmConfig g_nvm_cfg;
static whNvmCb g_nvm_cb = WH_NVM_FLASH_CB;
static uint8_t g_pattern[OBJECT_MAX];

extern const wt_fwu_backend_t wt_fwu_flash_backend;
extern volatile int32_t g_wt_flash_last_error;
extern volatile uint32_t g_wt_flash_first_err;
extern volatile uint32_t g_wt_flash_first_err_off;

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

/* The arch stubs: a thread is unprivileged when the case says so, and the
 * SVC dispatcher re-enters the same callback with privilege. */
int wt_arch_thread_unprivileged(void)
{
    return g_unprivileged;
}

int wt_spm_sp_call(struct wt_spm_call* call)
{
    void* ctx = wt_hsm_flash_context();
    int was = g_unprivileged;

    if (call->op != WT_SPM_OP_KEYSTORE_FLASH || call->call_type < 0 ||
            call->call_type > WT_SPM_KS_FLASH_CLEANUP) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    g_gate_calls[call->call_type]++;
    g_unprivileged = 0;
    switch (call->call_type) {
        case WT_SPM_KS_FLASH_READ:
            call->ret_int = g_wt_hsm_flash_cb.Read(ctx, call->vec_idx,
                                                   call->num_bytes,
                                                   call->buffer);
            break;
        case WT_SPM_KS_FLASH_PROGRAM:
            call->ret_int = g_wt_hsm_flash_cb.Program(ctx, call->vec_idx,
                                                      call->num_bytes,
                                                      call->buffer);
            break;
        case WT_SPM_KS_FLASH_ERASE:
            call->ret_int = g_wt_hsm_flash_cb.Erase(ctx, call->vec_idx,
                                                    call->num_bytes);
            break;
        case WT_SPM_KS_FLASH_VERIFY:
            call->ret_int = g_wt_hsm_flash_cb.Verify(ctx, call->vec_idx,
                                                     call->num_bytes,
                                                     call->buffer);
            break;
        case WT_SPM_KS_FLASH_BLANKCHECK:
            call->ret_int = g_wt_hsm_flash_cb.BlankCheck(ctx, call->vec_idx,
                                                         call->num_bytes);
            break;
        default:
            call->ret_int = g_wt_hsm_flash_cb.Cleanup(ctx);
            break;
    }
    g_unprivileged = was;
    return WT_FFM_SUCCESS;
}

static int store_init(void)
{
    return g_wt_hsm_flash_cb.Init(wt_hsm_flash_context(),
                                  wt_hsm_flash_config());
}

static void fill(uint8_t* out, uint32_t seed, uint32_t len)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        out[i] = (uint8_t)(seed * 7u + i * 13u + 1u);
    }
}

static int nvm_open(void)
{
    (void)memset(&g_nf_ctx, 0, sizeof(g_nf_ctx));
    (void)memset(&g_nvm, 0, sizeof(g_nvm));
    g_nf_cfg.cb = &g_wt_hsm_flash_cb;
    g_nf_cfg.context = wt_hsm_flash_context();
    g_nf_cfg.config = wt_hsm_flash_config();
    g_nvm_cfg.cb = &g_nvm_cb;
    g_nvm_cfg.context = &g_nf_ctx;
    g_nvm_cfg.config = &g_nf_cfg;
    return wh_Nvm_Init(&g_nvm, &g_nvm_cfg);
}

/* Fill, read back, destroy, refill until the store compacts, reopen as a
 * reboot would and read everything back; 0 when every object matched. */
static int nvm_lifecycle(uint32_t* compactions)
{
    whNvmMetadata meta;
    uint8_t readback[OBJECT_MAX];
    whNvmId victims[OBJECTS / 2u];
    uint32_t round;
    uint32_t i;
    uint32_t len;
    uint32_t erases_at_open;
    int ret;

    ret = nvm_open();
    erases_at_open = fa_erases();
    for (round = 0u; ret == WH_ERROR_OK && round < ROUNDS; round++) {
        for (i = 0u; ret == WH_ERROR_OK && i < OBJECTS; i++) {
            len = 1u + ((i * 37u + round * 11u) % OBJECT_MAX);
            (void)memset(&meta, 0, sizeof(meta));
            meta.id = (whNvmId)(0x100u + i);
            meta.access = WH_NVM_ACCESS_ANY;
            meta.flags = WH_NVM_FLAGS_NONE;
            meta.len = (whNvmSize)len;
            fill(g_pattern, meta.id + round, len);
            ret = wh_Nvm_AddObjectWithReclaim(&g_nvm, &meta, (whNvmSize)len,
                                              g_pattern);
        }
        for (i = 0u; ret == WH_ERROR_OK && i < OBJECTS; i++) {
            len = 1u + ((i * 37u + round * 11u) % OBJECT_MAX);
            fill(g_pattern, 0x100u + i + round, len);
            (void)memset(readback, 0, sizeof(readback));
            ret = wh_Nvm_Read(&g_nvm, (whNvmId)(0x100u + i), 0u,
                              (whNvmSize)len, readback);
            if (ret == WH_ERROR_OK && memcmp(readback, g_pattern, len) != 0) {
                ret = WH_ERROR_NOTVERIFIED;
            }
        }
        for (i = 0u; i < OBJECTS / 2u; i++) {
            victims[i] = (whNvmId)(0x100u + 2u * i);
        }
        if (ret == WH_ERROR_OK) {
            ret = wh_Nvm_DestroyObjects(&g_nvm, OBJECTS / 2u, victims);
        }
    }
    *compactions = fa_erases() - erases_at_open;
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_Cleanup(&g_nvm);
    }
    if (ret == WH_ERROR_OK) {
        ret = nvm_open();
    }
    for (i = 1u; ret == WH_ERROR_OK && i < OBJECTS; i += 2u) {
        len = 1u + ((i * 37u + (ROUNDS - 1u) * 11u) % OBJECT_MAX);
        fill(g_pattern, 0x100u + i + ROUNDS - 1u, len);
        (void)memset(readback, 0, sizeof(readback));
        ret = wh_Nvm_Read(&g_nvm, (whNvmId)(0x100u + i), 0u, (whNvmSize)len,
                          readback);
        if (ret == WH_ERROR_OK && memcmp(readback, g_pattern, len) != 0) {
            ret = WH_ERROR_NOTVERIFIED;
        }
    }
    return ret;
}

static void case_init_identity(void)
{
    wt_hsm_flash_context_t foreign;
    wt_hsm_flash_config_t forged;

    (void)memset(&forged, 0, sizeof(forged));
    (void)memcpy(&forged, wt_hsm_flash_config(), sizeof(forged));
    check(store_init() == WH_ERROR_OK, "the store context takes its own config");
    check(g_wt_hsm_flash_cb.Init(wt_hsm_flash_context(), &forged) ==
              WH_ERROR_BADARGS,
          "a copied config is refused: geometry is bound to the context");
    check(g_wt_hsm_flash_cb.Init(&foreign, wt_hsm_flash_config()) ==
              WH_ERROR_BADARGS,
          "an unknown context is refused");
    check(g_wt_hsm_flash_cb.PartitionSize(wt_hsm_flash_context()) == SECTOR,
          "the partition size is one sector");
    check(g_wt_hsm_flash_cb.PartitionSize(&foreign) == 0u,
          "an unknown context has no partition size");
}

static void case_store_lifecycle(void)
{
    uint32_t compactions = 0u;
    int ret;

    ret = nvm_lifecycle(&compactions);
    if (ret != WH_ERROR_OK) {
        printf("  lifecycle rc=%d last_error=%d first_err=%#x off=%#x\n", ret,
               (int)g_wt_flash_last_error, (unsigned)g_wt_flash_first_err,
               (unsigned)g_wt_flash_first_err_off);
    }
    check(ret == WH_ERROR_OK,
          "three fill/read/destroy rounds and a reopen through the backend");
    check(compactions >= 1u, "the store compacted into its other partition");
    check(fa_programs() > 100u, "the lifecycle programmed many units");
    check(g_wt_flash_last_error == 0, "no primitive failed");
#if defined(WT_PORT_MODEL_STM32H563)
    check(wt_h5_model_unmasked_array_accesses() == 0u,
          "every array access ran with interrupts masked");
    check(wt_h5_model_irq_depth() == 0,
          "the interrupt state was restored after every call");
    check(wt_h5_model_locked(), "the controller is locked between calls");
#endif
}

static void case_refusals(void)
{
    void* ctx = wt_hsm_flash_context();
    uint8_t buf[2u * UNIT];

    check(store_init() == WH_ERROR_OK, "init");
    check(g_wt_hsm_flash_cb.Read(ctx, WT_HSM_NVM_FLASH_SIZE - 8u, 16u, buf) ==
              WH_ERROR_BADARGS, "a read past the store is refused");
    check(g_wt_flash_first_err == (0x01000000u | 2000u) &&
              g_wt_flash_first_err_off == WT_HSM_NVM_FLASH_SIZE - 8u,
          "the first refusal is recorded with its stage and offset");
    check(g_wt_hsm_flash_cb.Read(ctx, 0u, 16u, NULL) == WH_ERROR_BADARGS,
          "a read into NULL is refused");
    check(g_wt_hsm_flash_cb.Program(ctx, 4u, UNIT, buf) == WH_ERROR_BADARGS,
          "a misaligned program is refused");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT - 1u, buf) ==
              WH_ERROR_BADARGS, "a partial unit is refused");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, UNIT) == WH_ERROR_BADARGS,
          "a sub-sector erase is refused");
    check(g_wt_hsm_flash_cb.Erase(ctx, UNIT, SECTOR) == WH_ERROR_BADARGS,
          "an unaligned sector erase is refused");
    check(g_wt_hsm_flash_cb.Verify(ctx, WT_HSM_NVM_FLASH_SIZE, 1u, buf) ==
              WH_ERROR_BADARGS, "a verify past the store is refused");
    check(g_wt_hsm_flash_cb.BlankCheck(ctx, WT_HSM_NVM_FLASH_SIZE, 1u) ==
              WH_ERROR_BADARGS, "a blank check past the store is refused");
    check(fa_programs() == 0u && fa_erases() == 0u,
          "no refusal reached the device");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 0u, NULL) == WH_ERROR_OK &&
              g_wt_hsm_flash_cb.Erase(ctx, 0u, 0u) == WH_ERROR_OK &&
              g_wt_hsm_flash_cb.Read(ctx, 0u, 0u, NULL) == WH_ERROR_OK,
          "zero-length operations succeed without touching the device");
}

static void case_write_lock(void)
{
    void* ctx = wt_hsm_flash_context();
    uint8_t buf[UNIT];

    (void)memset(buf, 0x5A, sizeof(buf));
    check(store_init() == WH_ERROR_OK, "init");
    check(g_wt_hsm_flash_cb.WriteLock(ctx, 0u, 0u) == WH_ERROR_OK, "lock");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, buf) == WH_ERROR_LOCKED &&
              g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_LOCKED,
          "a locked store refuses program and erase");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 0u, buf) == WH_ERROR_OK,
          "a zero-length program is fine while locked");
    check(fa_programs() == 0u && fa_erases() == 0u,
          "nothing reached the device while locked");
    check(g_wt_hsm_flash_cb.WriteUnlock(ctx, 0u, 0u) == WH_ERROR_OK,
          "unlock");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK &&
              g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, buf) == WH_ERROR_OK,
          "an unlocked store programs after an erase");
    check(g_wt_hsm_flash_cb.Verify(ctx, 0u, UNIT, buf) == WH_ERROR_OK,
          "the unit verifies through the checked read");
    check(g_wt_hsm_flash_cb.WriteLock(NULL, 0u, 0u) == WH_ERROR_BADARGS &&
              g_wt_hsm_flash_cb.WriteUnlock(NULL, 0u, 0u) == WH_ERROR_BADARGS,
          "a NULL context cannot be locked or unlocked");
}

static void case_gate_hop(void)
{
    void* ctx = wt_hsm_flash_context();
    wt_hsm_flash_context_t foreign;
    uint8_t buf[UNIT];
    uint8_t back[UNIT];

    (void)memset(buf, 0x3C, sizeof(buf));
    (void)memset(back, 0, sizeof(back));
    check(store_init() == WH_ERROR_OK, "init");
    g_unprivileged = 1;
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK &&
              g_gate_calls[WT_SPM_KS_FLASH_ERASE] == 1u,
          "an unprivileged erase hops through the gate");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, buf) == WH_ERROR_OK &&
              g_gate_calls[WT_SPM_KS_FLASH_PROGRAM] == 1u,
          "an unprivileged program hops through the gate");
    check(g_wt_hsm_flash_cb.Read(ctx, 0u, UNIT, back) == WH_ERROR_OK &&
              memcmp(back, buf, sizeof(buf)) == 0 &&
              g_gate_calls[WT_SPM_KS_FLASH_READ] == 1u,
          "an unprivileged read returns the programmed unit");
    check(g_wt_hsm_flash_cb.Verify(ctx, 0u, UNIT, buf) == WH_ERROR_OK &&
              g_wt_hsm_flash_cb.BlankCheck(ctx, UNIT, UNIT) == WH_ERROR_OK &&
              g_wt_hsm_flash_cb.Cleanup(ctx) == WH_ERROR_OK,
          "verify, blank check and cleanup hop through the gate");
    check(g_wt_hsm_flash_cb.Read(ctx, WT_HSM_NVM_FLASH_SIZE, 16u, back) ==
              WH_ERROR_BADARGS,
          "a forged offset is refused on the privileged side of the gate");
    check(g_wt_hsm_flash_cb.Read(&foreign, 0u, UNIT, back) ==
              WH_ERROR_BADARGS,
          "only the store context may hop: a foreign context is refused");
    g_unprivileged = 0;
    check(g_gate_calls[WT_SPM_KS_FLASH_READ] == 2u,
          "the foreign context never reached the dispatcher");
}

static void case_error_mapping(void)
{
    void* ctx = wt_hsm_flash_context();
    uint8_t buf[UNIT];
    uint8_t other[UNIT];

    (void)memset(buf, 0x11, sizeof(buf));
    (void)memset(other, 0x22, sizeof(other));
    check(store_init() == WH_ERROR_OK, "init");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK &&
              g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, buf) == WH_ERROR_OK,
          "erase and program");
    check(g_wt_hsm_flash_cb.BlankCheck(ctx, 0u, UNIT) == WH_ERROR_NOTBLANK,
          "a programmed unit is not blank");
    check(g_wt_hsm_flash_cb.BlankCheck(ctx, UNIT, UNIT) == WH_ERROR_OK,
          "an erased unit is blank");
    check(g_wt_flash_last_error == 0,
          "a non-blank result is not a device failure");
    check(g_wt_hsm_flash_cb.Verify(ctx, 0u, UNIT, other) ==
              WH_ERROR_NOTVERIFIED, "a mismatch is NOTVERIFIED");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, other) != WH_ERROR_OK,
          "a unit programmed twice between erases is refused");
    fa_fail_programs_after(0u);
    check(g_wt_hsm_flash_cb.Program(ctx, UNIT, UNIT, buf) ==
              WH_ERROR_ABORTED && g_wt_flash_last_error == WH_ERROR_ABORTED,
          "a device program fault is ABORTED and recorded");
    fa_fail_programs_after(0xFFFFFFFFu);
    fa_fail_erases_after(0u);
    check(g_wt_hsm_flash_cb.Erase(ctx, SECTOR, SECTOR) == WH_ERROR_ABORTED,
          "a device erase fault is ABORTED");
#if defined(WT_PORT_MODEL_STM32H563)
    check(wt_h5_model_locked() && wt_h5_model_irq_depth() == 0,
          "a failed erase still relocks and restores interrupts");
#endif
    fa_fail_erases_after(0xFFFFFFFFu);
}

static uint32_t g_erases_before[FWU_SIZE / SECTOR];

static void fwu_snapshot_erases(void)
{
    uint32_t s;

    for (s = 0u; s < FWU_SIZE / SECTOR; s++) {
        g_erases_before[s] = fa_sector_erases(FWU_BASE + s * SECTOR);
    }
}

/* Sectors erased exactly once since the snapshot, over the first bytes. */
static uint32_t fwu_sectors_erased_once(uint32_t bytes)
{
    uint32_t count = 0u;
    uint32_t s;

    for (s = 0u; s * SECTOR < bytes; s++) {
        if (fa_sector_erases(FWU_BASE + s * SECTOR) ==
                g_erases_before[s] + 1u) {
            count++;
        }
    }
    return count;
}

static void fwu_header(uint8_t* hdr, uint32_t fw_size, uint32_t version)
{
    (void)memset(hdr, 0xFF, HEADER);
    hdr[0] = 0x57u; hdr[1] = 0x4Fu; hdr[2] = 0x4Cu; hdr[3] = 0x46u;
    (void)memcpy(hdr + 4u, &fw_size, sizeof(fw_size));
    hdr[8] = 0x01u; hdr[9] = 0x00u; hdr[10] = 0x04u; hdr[11] = 0x00u;
    (void)memcpy(hdr + 12u, &version, sizeof(version));
}

static void case_fwu_staging(void)
{
    const wt_fwu_backend_t* be = &wt_fwu_flash_backend;
    static uint8_t chunk[SECTOR];
    uint8_t hdr[HEADER];
    uint32_t staged = HEADER + 100u;
    uint32_t written;
    uint32_t version = 0u;
    const uint8_t* trailer;
    uint32_t i;

    check(be->capacity == CAPACITY && be->align == UNIT,
          "capacity excludes the trailer; alignment is the program unit");
    check(be->begin(NULL) == 0, "begin");
    fwu_header(hdr, 100u, 7u);
    check(be->write(NULL, 0u, hdr, HEADER) == 0, "the header stages first");
    check(be->write(NULL, HEADER + UNIT, chunk, UNIT) != 0,
          "a write past the written extent is refused (no sparse candidate)");
    check(be->write(NULL, 0u, hdr, HEADER) != 0,
          "a write below the written extent is refused");
    (void)memset(chunk, 0x42, sizeof(chunk));
    check(be->write(NULL, HEADER, chunk, (100u + UNIT - 1u) / UNIT * UNIT) == 0,
          "the payload stages in program units");
    check(be->verify(NULL, staged, &version) == 0 && version == 7u,
          "FINISH with a logical size below the programmed extent verifies");
    check(be->verify(NULL, staged + UNIT, &version) != 0,
          "a logical size past the programmed extent is refused");
    check(be->verify(NULL, HEADER - 1u, &version) != 0,
          "a candidate shorter than the header is refused");
    check(be->arm(NULL, staged, version) == 0, "arm");
    trailer = fa_map(FWU_BASE + FWU_SIZE - UNIT, UNIT);
    check(trailer != NULL && trailer[UNIT - 5u] == 0x70u &&
              trailer[UNIT - 4u] == 0x42u && trailer[UNIT - 1u] == 0x54u,
          "the wolfBoot trigger sits in the topmost unit of the partition");
    check(fa_blank(FWU_BASE + FWU_SIZE - WT_FWU_TRAILER_SIZE,
                   WT_FWU_TRAILER_SIZE - UNIT) == FA_OK,
          "the rest of the trailer stays erased");
    check(be->disarm(NULL) == 0 &&
              fa_blank(FWU_BASE + FWU_SIZE - WT_FWU_TRAILER_SIZE,
                       WT_FWU_TRAILER_SIZE) == FA_OK,
          "disarm erases the trailer");

    /* A whole-capacity candidate: every sector erased exactly once, however
     * many sectors the partition has. */
    fwu_snapshot_erases();
    check(be->begin(NULL) == 0, "begin again");
    written = 0u;
    while (written < CAPACITY - UNIT) {
        uint32_t size = CAPACITY - UNIT - written;

        if (size > sizeof(chunk)) {
            size = (uint32_t)sizeof(chunk);
        }
        for (i = 0u; i < size; i++) {
            chunk[i] = (uint8_t)(written + i);
        }
        if (be->write(NULL, written, chunk, size) != 0) {
            break;
        }
        written += size;
    }
    check(written == CAPACITY - UNIT &&
              be->write(NULL, written, chunk, 2u * UNIT) != 0 &&
              fa_blank(FWU_BASE + CAPACITY, WT_FWU_TRAILER_SIZE) == FA_OK,
          "an in-sequence write straddling the trailer is refused, trailer blank");
    for (i = 0u; i < UNIT; i++) {
        chunk[i] = (uint8_t)(written + i);
    }
    if (be->write(NULL, written, chunk, UNIT) == 0) {
        written += UNIT;
    }
    check(written == CAPACITY, "the whole capacity stages sequentially");
    check(fwu_sectors_erased_once(CAPACITY) == CAPACITY / SECTOR,
          "each staged sector was erased exactly once, past 32 sectors too");
    check(fa_sector_erases(FWU_BASE + FWU_SIZE - UNIT) ==
              g_erases_before[FWU_SIZE / SECTOR - 1u],
          "staging never touched the trailer");
    fwu_header(hdr, CAPACITY - HEADER, 9u);
    check(be->write(NULL, CAPACITY, hdr, UNIT) != 0,
          "the candidate cannot grow into the trailer");
}

static void case_fwu_failures(void)
{
    const wt_fwu_backend_t* be = &wt_fwu_flash_backend;
    uint8_t hdr[HEADER];
    uint32_t version;

    check(be->begin(NULL) == 0, "begin");
    fwu_header(hdr, 16u, 3u);
    fa_fail_erases_after(0u);
    check(be->write(NULL, 0u, hdr, HEADER) != 0,
          "a failed sector erase fails the write");
    fa_fail_erases_after(0xFFFFFFFFu);
    check(be->begin(NULL) == 0 && be->write(NULL, 0u, hdr, HEADER) == 0,
          "a fresh candidate erases the sector again and stages");
    fa_fail_programs_after(0u);
    check(be->write(NULL, HEADER, hdr, UNIT) != 0,
          "a failed program fails the write");
    fa_fail_programs_after(0xFFFFFFFFu);
    check(be->verify(NULL, HEADER + UNIT, &version) != 0,
          "a candidate whose write failed does not verify past the extent");
    fwu_header(hdr, 0x10000u, 3u);
    check(be->begin(NULL) == 0 && be->write(NULL, 0u, hdr, HEADER) == 0 &&
              be->verify(NULL, HEADER, &version) != 0,
          "a header declaring more payload than staged is refused");
    (void)memset(hdr, 0xFF, HEADER);
    check(be->begin(NULL) == 0 && be->write(NULL, 0u, hdr, HEADER) == 0 &&
              be->verify(NULL, HEADER, &version) != 0,
          "a header without the magic is refused");
}

static void case_conf_nvm_sync(void)
{
    uint8_t out[2u * UNIT];
    uint8_t in[2u * UNIT];

    (void)memset(out, 0x77, sizeof(out));
    (void)memset(in, 0, sizeof(in));
    check(wt_conf_nvm_flash_sync(out, UNIT - 1u, 1) != 0,
          "a length that is not a whole unit is refused");
    check(wt_conf_nvm_flash_sync(NULL, UNIT, 1) != 0, "NULL is refused");
    check(wt_conf_nvm_flash_sync(out, sizeof(out), 1) == 0,
          "a store erases the sector and programs the buffer");
    check(wt_conf_nvm_flash_sync(in, sizeof(in), 0) == 0 &&
              memcmp(in, out, sizeof(out)) == 0,
          "a load reads the stored bytes back");
    (void)memset(out, 0x11, sizeof(out));
    check(wt_conf_nvm_flash_sync(out, sizeof(out), 1) == 0 &&
              wt_conf_nvm_flash_sync(in, sizeof(in), 0) == 0 &&
              memcmp(in, out, sizeof(out)) == 0,
          "a second store replaces the sector's content");
    fa_fail_erases_after(0u);
    check(wt_conf_nvm_flash_sync(out, sizeof(out), 1) != 0,
          "a failed erase fails the store");
    fa_fail_erases_after(0xFFFFFFFFu);
}

static void case_remeasure_tamper(void)
{
    uintptr_t guest0 = WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE);
    const uint8_t* p;
    uint8_t zero[UNIT];
    uint8_t* sector = fa_map(guest0, SECTOR);

    (void)memset(zero, 0, sizeof(zero));
    check(wt_hsm_flash_remeasure_tamper(guest0 + SECTOR) != 0,
          "only guest 0's first sector may be tampered with");
    /* A partial erase must not pass on a sector that was already blank. */
    if (sector != NULL) {
        (void)memset(sector, 0x5A, SECTOR);
    }
    check(wt_hsm_flash_remeasure_tamper(guest0) == 0, "the probe tamper runs");
    p = fa_map(guest0, UNIT);
    check(p != NULL && memcmp(p, zero, sizeof(zero)) == 0 &&
              fa_blank(guest0 + UNIT, SECTOR - UNIT) == FA_OK,
          "the sector is erased and its first unit zeroed");
}

#if defined(WT_PORT_MODEL_STM32H563)
static int all_zero(const uint8_t* buf, uint32_t len)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        if (buf[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void case_ecc_read(void)
{
    void* ctx = wt_hsm_flash_context();
    uint8_t buf[UNIT];

    (void)memset(buf, 0x11, sizeof(buf));
    check(store_init() == WH_ERROR_OK, "init");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK &&
              g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, buf) == WH_ERROR_OK,
          "erase and program");
    wt_h5_model_ecc_bad(STORE_BASE, UNIT);
    check(g_wt_hsm_flash_cb.Read(ctx, 0u, UNIT, buf) == WH_ERROR_ABORTED &&
              all_zero(buf, sizeof(buf)),
          "an ECC double error inside the read is contained: ABORTED, zeroed");
    check(g_wt_flash_last_error == WH_ERROR_ABORTED,
          "the ECC read fault is recorded");
    (void)memset(buf, 0x11, sizeof(buf));
    check(g_wt_hsm_flash_cb.Verify(ctx, 0u, UNIT, buf) == WH_ERROR_ABORTED,
          "a verify over the bad unit is ABORTED, not a mismatch");
    check(g_wt_hsm_flash_cb.BlankCheck(ctx, 0u, UNIT) == WH_ERROR_ABORTED,
          "a blank check over the bad unit is ABORTED, not blank");
    check(wt_h5_model_irq_depth() == 0,
          "interrupts are restored after a contained ECC fault");
    wt_h5_model_ecc_bad(0u, 0u);
    check(g_wt_hsm_flash_cb.Read(ctx, UNIT, UNIT, buf) == WH_ERROR_OK,
          "a clean unit still reads");
}

static void case_icache_busy(void)
{
    void* ctx = wt_hsm_flash_context();
    uint8_t buf[UNIT];

    (void)memset(buf, 0x22, sizeof(buf));
    check(store_init() == WH_ERROR_OK, "init");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK, "erase");
    wt_h5_model_icache_stuck(1);
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, buf) == WH_ERROR_ABORTED,
          "a program whose ICACHE invalidate never completes is ABORTED");
    check(g_wt_hsm_flash_cb.Erase(ctx, SECTOR, SECTOR) == WH_ERROR_ABORTED,
          "an erase whose ICACHE invalidate never completes is ABORTED");
    check(wt_h5_model_locked() && wt_h5_model_irq_depth() == 0,
          "a busy cache still relocks and restores interrupts");
    wt_h5_model_icache_stuck(0);
    check(g_wt_hsm_flash_cb.Erase(ctx, SECTOR, SECTOR) == WH_ERROR_OK,
          "with the cache idle again the erase completes");
}

static void case_controller_stuck(void)
{
    void* ctx = wt_hsm_flash_context();
    uint8_t buf[UNIT];
    int mode;

    (void)memset(buf, 0x33, sizeof(buf));
    check(store_init() == WH_ERROR_OK, "init");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK, "erase");
    for (mode = 1; mode <= 2; mode++) {
        wt_h5_model_busy(mode);
        check(g_wt_hsm_flash_cb.Program(ctx, 0u, UNIT, buf) ==
                  WH_ERROR_ABORTED,
              "a program on a controller that stays busy is ABORTED");
        wt_h5_model_busy(mode);
        check(g_wt_hsm_flash_cb.Erase(ctx, SECTOR, SECTOR) == WH_ERROR_ABORTED,
              "an erase on a controller that stays busy is ABORTED");
        wt_port_flash_quiesce();
        check(wt_h5_model_locked() && wt_h5_model_irq_depth() == 0,
              "a busy controller still relocks, restores interrupts and "
              "lets quiesce return");
        wt_h5_model_busy(0);
    }
    wt_h5_model_keys_ignored(1);
    check(g_wt_hsm_flash_cb.Erase(ctx, SECTOR, SECTOR) == WH_ERROR_ABORTED &&
              wt_h5_model_locked(),
          "an erase whose unlock never takes is ABORTED and stays locked");
    wt_h5_model_keys_ignored(0);
    check(g_wt_hsm_flash_cb.Erase(ctx, SECTOR, SECTOR) == WH_ERROR_OK,
          "with the controller idle again the erase completes");
}
#endif

typedef struct test_case {
    void (*fn)(void);
    const char* name;
} test_case_t;

static const test_case_t g_cases[] = {
    { case_init_identity, "identity-bound init" },
    { case_store_lifecycle, "wolfHSM store lifecycle" },
    { case_refusals, "range and alignment refusals" },
    { case_write_lock, "write lock" },
    { case_gate_hop, "privilege gate" },
    { case_error_mapping, "error mapping" },
    { case_fwu_staging, "FWU staging" },
    { case_fwu_failures, "FWU failures" },
    { case_conf_nvm_sync, "conformance NVM sync" },
    { case_remeasure_tamper, "remeasure probe tamper" },
#if defined(WT_PORT_MODEL_STM32H563)
    { case_ecc_read, "ECC-contained read" },
    { case_icache_busy, "ICACHE invalidate that never completes" },
    { case_controller_stuck, "flash controller busy or unlock refused" },
#endif
};

int main(void)
{
    size_t i;
    int failed = 0;

    printf("RUN: unit/port_flash (%s)\n", WT_PORT_MODEL_NAME);
    for (i = 0u; i < sizeof(g_cases) / sizeof(g_cases[0]); i++) {
        pid_t pid;
        int status = 0;

        (void)fflush(stdout);
        pid = fork();
        if (pid == 0) {
            printf(" case: %s\n", g_cases[i].name);
            g_cases[i].fn();
            (void)fflush(stdout);
            _exit(failures == 0 ? 0 : 1);
        }
        if (pid < 0 || waitpid(pid, &status, 0) < 0 ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf(" case FAILED: %s\n", g_cases[i].name);
            failed++;
        }
    }
    if (failed == 0) {
        printf("PASS: unit/port_flash (%s, %u cases)\n", WT_PORT_MODEL_NAME,
               (unsigned)(sizeof(g_cases) / sizeof(g_cases[0])));
        return 0;
    }
    printf("FAIL: unit/port_flash (%s, %d cases failed)\n",
           WT_PORT_MODEL_NAME, failed);
    return 1;
}
