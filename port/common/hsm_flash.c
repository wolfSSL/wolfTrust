/* hsm_flash.c
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

/* The wolfHSM NVM backend and the FWU staging backend every port shares,
 * over the port's flash_port.h primitives. Geometry comes from the port's
 * memory_map.h; the context a confined partition can write holds no geometry
 * at all, so the privileged path resolves it from the immutable config the
 * context's identity names. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hsm_flash.h"
#include "flash_port.h"
#include "memory_map.h"
#include "wolftrust/arch.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/static_assert.h"
#include "wolftrust/zeroize.h"
#include "wolftrust/services/fwu_service.h"
#include "wolfhsm/wh_error.h"

#if defined(WOLFHSM_CFG_FLASH_UNIT_SIZE)
/* The wolfHSM store writes whole units; the device's program unit divides it. */
WT_STATIC_ASSERT(WT_FLASH_PROGRAM_UNIT <= WOLFHSM_CFG_FLASH_UNIT_SIZE &&
                 (WOLFHSM_CFG_FLASH_UNIT_SIZE % WT_FLASH_PROGRAM_UNIT) == 0u,
                 "WT_FLASH_PROGRAM_UNIT must divide the wolfHSM flash unit");
#endif
WT_STATIC_ASSERT((WT_FLASH_SECTOR_SIZE % WT_FLASH_PROGRAM_UNIT) == 0u &&
                 WT_FWU_TRAILER_SIZE >= WT_FLASH_SECTOR_SIZE &&
                 (WT_FWU_TRAILER_SIZE % WT_FLASH_SECTOR_SIZE) == 0u &&
                 WT_FWU_UPDATE_FLASH_SIZE > WT_FWU_TRAILER_SIZE,
                 "flash geometry: sectors hold whole units, the trailer whole sectors");

static const wt_hsm_flash_config_t g_hsm_flash_cfg = {
    .base = WT_HSM_NVM_FLASH_BASE_S,
    .size = WT_HSM_NVM_FLASH_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = WT_FLASH_PROGRAM_UNIT,
};

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* The conformance DRIVER partition's NVMEM boot flag lives in its own flash
 * sector so it survives the suite's panic-test resets. */
static const wt_hsm_flash_config_t g_conf_nvm_cfg = {
    .base = WT_CONF_NVM_FLASH_BASE_S,
    .size = WT_CONF_NVM_FLASH_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = WT_FLASH_PROGRAM_UNIT,
};
static wt_hsm_flash_context_t g_conf_nvm_ctx;
#endif
#if defined(WT_FWU)
static const wt_hsm_flash_config_t g_fwu_flash_cfg = {
    .base = WT_FWU_UPDATE_FLASH_BASE_S,
    .size = WT_FWU_UPDATE_FLASH_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = WT_FLASH_PROGRAM_UNIT,
};
static wt_hsm_flash_context_t g_fwu_flash_ctx;
#endif
#if defined(WT_REMEASURE_PROBE)
/* Guest 0's first sector, the only window the probe may tamper with. */
static const wt_hsm_flash_config_t g_remeasure_probe_cfg = {
    .base = WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE),
    .size = WT_FLASH_SECTOR_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = WT_FLASH_PROGRAM_UNIT,
};
#endif

/* Direct-path forensics, read over the debug port: the last primitive
 * failure and the first refusal. */
volatile int32_t g_wt_flash_last_error __attribute__((used));
volatile uint32_t g_wt_flash_first_err __attribute__((used));
volatile uint32_t g_wt_flash_first_err_off __attribute__((used));

static const wt_hsm_flash_config_t *wt_hsm_flash_cfg_of(const void *context)
{
    if (context == (const void *)&g_hsm_flash_ctx) {
        return &g_hsm_flash_cfg;
    }
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    if (context == (const void *)&g_conf_nvm_ctx) {
        return &g_conf_nvm_cfg;
    }
#endif
#if defined(WT_FWU)
    if (context == (const void *)&g_fwu_flash_ctx) {
        return &g_fwu_flash_cfg;
    }
#endif
    return NULL;
}

static int wt_hsm_flash_refuse(int rc, uint32_t stage, uint32_t offset)
{
    if (g_wt_flash_first_err == 0u) {
        g_wt_flash_first_err = (stage << 24) | ((uint32_t)(-rc) & 0x00FFFFFFu);
        g_wt_flash_first_err_off = offset;
    }
    return rc;
}

static int wt_hsm_flash_result(int rc, uint32_t stage, uint32_t offset)
{
    if (rc != WH_ERROR_OK) {
        g_wt_flash_last_error = (int32_t)rc;
        (void)wt_hsm_flash_refuse(rc, stage, offset);
    }
    return rc;
}

static int wt_flash_range_ok(const wt_hsm_flash_config_t *cfg,
                             uint32_t offset, uint32_t size)
{
    if (cfg == NULL || cfg->sector_size == 0u || cfg->program_unit == 0u) {
        return 0;
    }
    if (offset > cfg->size) {
        return 0;
    }
    if (size > cfg->size - offset) {
        return 0;
    }
    return 1;
}

/* A confined keystore partition hops to the privileged SVC dispatcher, which
 * re-enters the same callback with privilege. */
static int wt_hsm_flash_gate(void *context, int sub_op, uint32_t offset,
                             uint32_t size, void *data)
{
    wt_spm_call_t call;
    int rc;

    if (context != (void *)&g_hsm_flash_ctx) {
        return WH_ERROR_BADARGS;
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_KEYSTORE_FLASH;
    call.call_type = sub_op;
    call.vec_idx = offset;
    call.num_bytes = size;
    call.buffer = data;
    rc = wt_spm_sp_call(&call);
    if (rc != WT_FFM_SUCCESS) {
        g_wt_flash_gate_aborts++;
        if (g_wt_flash_gate_abort_info == 0u) {
            g_wt_flash_gate_abort_info = ((uint32_t)sub_op << 24) |
                                         ((uint32_t)rc & 0x00FFFFFFu);
        }
        return WH_ERROR_ABORTED;
    }
    return call.ret_int;
}

static int wt_hsm_flash_init(void *context, const void *config)
{
    wt_hsm_flash_context_t *ctx = (wt_hsm_flash_context_t *)context;
    const wt_hsm_flash_config_t *cfg =
        (const wt_hsm_flash_config_t *)config;

    if (ctx == NULL || cfg == NULL || cfg != wt_hsm_flash_cfg_of(ctx) ||
        cfg->base == 0u || cfg->size == 0u ||
        cfg->sector_size == 0u || cfg->program_unit == 0u ||
        (cfg->size % cfg->sector_size) != 0u ||
        (cfg->sector_size % cfg->program_unit) != 0u) {
        return WH_ERROR_BADARGS;
    }
    ctx->write_locked = false;
    return WH_ERROR_OK;
}

static int wt_hsm_flash_cleanup(void *context)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_CLEANUP, 0u, 0u,
                                 NULL);
    }
    wt_port_flash_quiesce();
    return WH_ERROR_OK;
}

static uint32_t wt_hsm_flash_partition_size(void *context)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);

    if (cfg == NULL) {
        return 0u;
    }
    return cfg->sector_size;
}

static int wt_hsm_flash_write_lock(void *context, uint32_t offset,
                                   uint32_t size)
{
    wt_hsm_flash_context_t *ctx = (wt_hsm_flash_context_t *)context;
    (void)offset;
    (void)size;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    ctx->write_locked = true;
    return WH_ERROR_OK;
}

static int wt_hsm_flash_write_unlock(void *context, uint32_t offset,
                                     uint32_t size)
{
    wt_hsm_flash_context_t *ctx = (wt_hsm_flash_context_t *)context;
    (void)offset;
    (void)size;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    ctx->write_locked = false;
    return WH_ERROR_OK;
}

static int wt_hsm_flash_read(void *context, uint32_t offset, uint32_t size,
                             uint8_t *data)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_READ, offset, size,
                                 data);
    }
    if (!wt_flash_range_ok(cfg, offset, size)) {
        return wt_hsm_flash_refuse(WH_ERROR_BADARGS, 0x01u, offset);
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    return wt_hsm_flash_result(wt_port_flash_read(cfg->base + offset, data,
                                                  size), 0x06u, offset);
}

static int wt_hsm_flash_program(void *context, uint32_t offset, uint32_t size,
                                const uint8_t *data)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);
    const wt_hsm_flash_context_t *ctx =
        (const wt_hsm_flash_context_t *)context;

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_PROGRAM, offset,
                                 size, (void *)(uintptr_t)data);
    }
    if (!wt_flash_range_ok(cfg, offset, size)) {
        return wt_hsm_flash_refuse(WH_ERROR_BADARGS, 0x01u, offset);
    }
    if ((offset % cfg->program_unit) != 0u ||
            (size % cfg->program_unit) != 0u) {
        return wt_hsm_flash_refuse(WH_ERROR_BADARGS, 0x02u, offset);
    }
    if (size != 0u && ctx->write_locked) {
        return wt_hsm_flash_refuse(WH_ERROR_LOCKED, 0x03u, offset);
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    return wt_hsm_flash_result(wt_port_flash_program(cfg->base + offset, data,
                                                     size), 0x04u, offset);
}

static int wt_hsm_flash_erase(void *context, uint32_t offset, uint32_t size)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);
    const wt_hsm_flash_context_t *ctx =
        (const wt_hsm_flash_context_t *)context;

    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_ERASE, offset, size,
                                 NULL);
    }
    if (!wt_flash_range_ok(cfg, offset, size)) {
        return wt_hsm_flash_refuse(WH_ERROR_BADARGS, 0x01u, offset);
    }
    if ((offset % cfg->sector_size) != 0u ||
            (size % cfg->sector_size) != 0u) {
        return wt_hsm_flash_refuse(WH_ERROR_BADARGS, 0x02u, offset);
    }
    if (size != 0u && ctx->write_locked) {
        return wt_hsm_flash_refuse(WH_ERROR_LOCKED, 0x03u, offset);
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    return wt_hsm_flash_result(wt_port_flash_erase(cfg->base + offset, size),
                               0x05u, offset);
}

/* Compare through the checked read, one program unit at a time, so a device
 * fault in the store is a refusal rather than a false mismatch or match. */
static int wt_hsm_flash_verify(void *context, uint32_t offset, uint32_t size,
                               const uint8_t *data)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);
    uint8_t flash_data[WT_FLASH_PROGRAM_UNIT];
    uint32_t checked = 0u;
    int ret = WH_ERROR_OK;

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_VERIFY, offset,
                                 size, (void *)(uintptr_t)data);
    }
    if (!wt_flash_range_ok(cfg, offset, size)) {
        return wt_hsm_flash_refuse(WH_ERROR_BADARGS, 0x01u, offset);
    }
    while (checked < size && ret == WH_ERROR_OK) {
        uint32_t chunk = size - checked;

        if (chunk > (uint32_t)sizeof(flash_data)) {
            chunk = (uint32_t)sizeof(flash_data);
        }
        ret = wt_port_flash_read(cfg->base + offset + checked, flash_data,
                                 chunk);
        if (ret == WH_ERROR_OK &&
                memcmp(flash_data, data + checked, chunk) != 0) {
            ret = WH_ERROR_NOTVERIFIED;
        }
        if (ret == WH_ERROR_OK) {
            checked += chunk;
        }
    }
    wt_forceZero(flash_data, sizeof(flash_data));
    if (ret != WH_ERROR_NOTVERIFIED) {
        ret = wt_hsm_flash_result(ret, 0x06u, offset);
    }
    return ret;
}

static int wt_hsm_flash_blank_check(void *context, uint32_t offset,
                                    uint32_t size)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);
    int ret;

    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_BLANKCHECK, offset,
                                 size, NULL);
    }
    if (!wt_flash_range_ok(cfg, offset, size)) {
        return wt_hsm_flash_refuse(WH_ERROR_BADARGS, 0x01u, offset);
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    ret = wt_port_flash_blank_check(cfg->base + offset, size);
    if (ret != WH_ERROR_NOTBLANK) {
        ret = wt_hsm_flash_result(ret, 0x07u, offset);
    }
    return ret;
}

const whFlashCb g_wt_hsm_flash_cb = {
    .Init = wt_hsm_flash_init,
    .Cleanup = wt_hsm_flash_cleanup,
    .PartitionSize = wt_hsm_flash_partition_size,
    .WriteLock = wt_hsm_flash_write_lock,
    .WriteUnlock = wt_hsm_flash_write_unlock,
    .Read = wt_hsm_flash_read,
    .Program = wt_hsm_flash_program,
    .Erase = wt_hsm_flash_erase,
    .Verify = wt_hsm_flash_verify,
    .BlankCheck = wt_hsm_flash_blank_check,
};

void *wt_hsm_flash_context(void)
{
    return &g_hsm_flash_ctx;
}

const void *wt_hsm_flash_config(void)
{
    return &g_hsm_flash_cfg;
}

int wt_hsm_flash_format(void)
{
    return wt_hsm_flash_erase(&g_hsm_flash_ctx, 0u, g_hsm_flash_cfg.size);
}

#if defined(WT_FWU)
/* SERVICE_FWU staging into the wolfBoot update partition, contiguous from
 * offset 0 with each sector erased lazily; arm() programs wolfBoot's update
 * trigger in the trailer, and the swapped image still faces launch verify. */

/* Erased high-water mark: every sector below it is blank or holds staged
 * data and is never erased again, whatever the partition's sector count. */
static uint32_t g_fwu_erased_end;
static uint32_t g_fwu_written_end;

static int wt_fwu_ensure_erased(uint32_t offset, uint32_t size)
{
    uint32_t sector_size = g_fwu_flash_cfg.sector_size;
    uint32_t end = offset + size;
    uint32_t s;

    end = ((end + sector_size - 1u) / sector_size) * sector_size;
    for (s = g_fwu_erased_end; s < end; s += sector_size) {
        if (wt_hsm_flash_erase(&g_fwu_flash_ctx, s, sector_size) !=
                WH_ERROR_OK) {
            return -1;
        }
        g_fwu_erased_end = s + sector_size;
    }
    return 0;
}

/* The staged bytes read back through the checked read, never the mapped
 * array, so an ECC event is a failed write rather than a corrupt candidate. */
static int wt_fwu_readback_matches(uint32_t offset, const uint8_t *data,
                                   uint32_t size)
{
    uint8_t flash_data[WT_FLASH_PROGRAM_UNIT];
    uint32_t checked = 0u;
    int same = 1;

    while (same != 0 && checked < size) {
        uint32_t chunk = size - checked;

        if (chunk > (uint32_t)sizeof(flash_data)) {
            chunk = (uint32_t)sizeof(flash_data);
        }
        if (wt_hsm_flash_read(&g_fwu_flash_ctx, offset + checked, chunk,
                              flash_data) != WH_ERROR_OK ||
                memcmp(flash_data, data + checked, chunk) != 0) {
            same = 0;
        }
        checked += chunk;
    }
    wt_forceZero(flash_data, sizeof(flash_data));
    return same;
}

static int wt_fwu_backend_begin(void *ctx)
{
    (void)ctx;
    if (wt_hsm_flash_init(&g_fwu_flash_ctx, &g_fwu_flash_cfg) != WH_ERROR_OK) {
        return -1;
    }
    g_fwu_erased_end = 0u;
    g_fwu_written_end = 0u;
    return 0;
}

static int wt_fwu_backend_write(void *ctx, uint32_t offset,
                                const uint8_t *data, uint32_t size)
{
    uint32_t reserved = g_fwu_flash_cfg.size - WT_FWU_TRAILER_SIZE;

    (void)ctx;
    /* The trailer sectors hold wolfBoot's swap trigger and are owned by
     * arm/disarm alone; staging data must never pre-program them. */
    if (offset >= reserved || size > reserved - offset ||
            offset != g_fwu_written_end) {
        return -1;
    }
    if (wt_fwu_ensure_erased(offset, size) != 0) {
        return -1;
    }
    if (wt_hsm_flash_program(&g_fwu_flash_ctx, offset, size, data) !=
            WH_ERROR_OK) {
        return -1;
    }
    if (!wt_fwu_readback_matches(offset, data, size)) {
        return -1;
    }
    g_fwu_written_end = offset + size;
    return 0;
}

static int wt_fwu_backend_disarm(void *ctx);

static int wt_fwu_backend_arm(void *ctx, uint32_t image_size,
                              uint32_t version)
{
    uint32_t block_off = g_fwu_flash_cfg.size - g_fwu_flash_cfg.program_unit;
    uint8_t block[WT_FLASH_PROGRAM_UNIT];

    (void)ctx;
    (void)image_size;
    (void)version;
    /* The wolfBoot trigger lives in the topmost program unit of the partition
     * (state + magic); the block below it stays erased. The trailer sectors
     * never hold staged data, so they are erased outright. */
    if (wt_fwu_wolfboot_arm_trailer(block, (uint32_t)sizeof(block)) != 0) {
        return -1;
    }
    if (wt_fwu_backend_disarm(NULL) != 0) {
        return -1;
    }
    if (wt_hsm_flash_program(&g_fwu_flash_ctx, block_off,
                             (uint32_t)sizeof(block), block) != WH_ERROR_OK ||
            !wt_fwu_readback_matches(block_off, block,
                                     (uint32_t)sizeof(block))) {
        /* A partially programmed trigger must not survive a failed arm. */
        (void)wt_fwu_backend_disarm(NULL);
        return -1;
    }
    return 0;
}

static int wt_fwu_backend_disarm(void *ctx)
{
    uint32_t trailer = g_fwu_flash_cfg.size - WT_FWU_TRAILER_SIZE;

    (void)ctx;
    if (wt_hsm_flash_erase(&g_fwu_flash_ctx, trailer,
                           WT_FWU_TRAILER_SIZE) != WH_ERROR_OK) {
        return -1;
    }
    return 0;
}

/* wolfBoot image header size (staged images carry it). */
#define WT_FWU_IMAGE_HEADER_SIZE 0x400u
#define WT_FWU_IMAGE_MAGIC 0x464C4F57u
#define WT_FWU_HDR_TAG_VERSION 0x0001u

static int wt_fwu_backend_verify(void *ctx, uint32_t staged_size,
                                 uint32_t *header_version)
{
    uint8_t hdr[WT_FWU_IMAGE_HEADER_SIZE];
    uint32_t magic;
    uint32_t fw_size;
    uint32_t version = 0u;
    uint32_t offset = 8u;
    uint32_t tag;
    uint32_t len;
    int found = 0;

    (void)ctx;
    /* FINISH passes the logical size; the programmed extent is it rounded up
     * to a program unit. */
    if (header_version == NULL ||
            staged_size < WT_FWU_IMAGE_HEADER_SIZE ||
            !wt_fwu_staged_extent_ok(staged_size, g_fwu_written_end,
                                     WT_FLASH_PROGRAM_UNIT)) {
        return -1;
    }
    if (wt_hsm_flash_read(&g_fwu_flash_ctx, 0u, (uint32_t)sizeof(hdr), hdr) !=
            WH_ERROR_OK) {
        return -1;
    }
    memcpy(&magic, hdr, sizeof(magic));
    memcpy(&fw_size, hdr + 4u, sizeof(fw_size));
    if (magic != WT_FWU_IMAGE_MAGIC) {
        return -1;
    }
    /* The staged extent must cover the header plus the declared payload. */
    if (fw_size > staged_size - WT_FWU_IMAGE_HEADER_SIZE) {
        return -1;
    }
    while (offset + 4u <= WT_FWU_IMAGE_HEADER_SIZE) {
        if (hdr[offset] == 0xFFu) {
            offset++;
            continue;
        }
        tag = (uint32_t)hdr[offset] | ((uint32_t)hdr[offset + 1u] << 8);
        len = (uint32_t)hdr[offset + 2u] | ((uint32_t)hdr[offset + 3u] << 8);
        if (tag == 0u) {
            break;
        }
        if (offset + 4u + len > WT_FWU_IMAGE_HEADER_SIZE) {
            return -1;
        }
        if (tag == WT_FWU_HDR_TAG_VERSION && len == sizeof(version)) {
            memcpy(&version, hdr + offset + 4u, sizeof(version));
            found = 1;
        }
        offset += 4u + len;
    }
    if (found == 0) {
        return -1;
    }
    *header_version = version;
    return 0;
}

const wt_fwu_backend_t wt_fwu_flash_backend = {
    .begin = wt_fwu_backend_begin,
    .write = wt_fwu_backend_write,
    .arm = wt_fwu_backend_arm,
    .disarm = wt_fwu_backend_disarm,
    /* The trailer sectors are arm/disarm-owned, never staging capacity. */
    .capacity = WT_FWU_UPDATE_FLASH_SIZE - WT_FWU_TRAILER_SIZE,
    .align = WT_FLASH_PROGRAM_UNIT,
    .verify = wt_fwu_backend_verify,
};
#endif

#if defined(WT_REMEASURE_PROBE)
int wt_hsm_flash_remeasure_tamper(uintptr_t secure_base)
{
    if (secure_base != g_remeasure_probe_cfg.base) {
        return -1;
    }
    return (wt_port_flash_probe_tamper(secure_base - WT_FLASH_S_ALIAS_BASE +
                                       WT_FLASH_NS_BASE) == WH_ERROR_OK)
               ? 0 : -1;
}
#endif

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
static bool g_conf_nvm_ready;

int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store)
{
    int ret;

    if (buf == NULL || len == 0u || len > g_conf_nvm_cfg.size ||
            (len % g_conf_nvm_cfg.program_unit) != 0u) {
        return -1;
    }
    if (!g_conf_nvm_ready) {
        if (wt_hsm_flash_init(&g_conf_nvm_ctx, &g_conf_nvm_cfg) != WH_ERROR_OK) {
            return -1;
        }
        g_conf_nvm_ready = true;
    }
    if (store == 0) {
        ret = wt_hsm_flash_read(&g_conf_nvm_ctx, 0u, len, buf);
    }
    else {
        ret = wt_hsm_flash_erase(&g_conf_nvm_ctx, 0u,
                                 g_conf_nvm_cfg.sector_size);
        if (ret == WH_ERROR_OK) {
            ret = wt_hsm_flash_program(&g_conf_nvm_ctx, 0u, len, buf);
        }
    }
    return (ret == WH_ERROR_OK) ? 0 : -1;
}
#endif

#if defined(WT_DEPUTY_NEG_PROBE) && (WT_DEPUTY_NEG_PROBE == 1)
/* A primitive fed a forged offset must reject it with exactly
 * WH_ERROR_BADARGS through a delivered gate call. */
static int wt_deputy_expect_badargs(int32_t sub_op, uint32_t offset,
                                    uint32_t size, void *buf)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_KEYSTORE_FLASH;
    call.call_type = sub_op;
    call.vec_idx = offset;
    call.num_bytes = size;
    call.buffer = buf;
    if (wt_arch_sp_trap(&call) != WT_FFM_SUCCESS) {
        return 0;
    }
    return (call.ret_int == WH_ERROR_BADARGS) ? 1 : 0;
}

static int wt_deputy_read_ok(int32_t sub_op, uint8_t *buf, uint32_t size)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_KEYSTORE_FLASH;
    call.call_type = sub_op;
    call.vec_idx = 0u;
    call.num_bytes = size;
    call.buffer = buf;
    return (wt_arch_sp_trap(&call) == WT_FFM_SUCCESS &&
            call.ret_int == WH_ERROR_OK) ? 1 : 0;
}

/* The vault's writable context holds no geometry, so a deputy can only forge
 * offsets and lengths: each must be refused against the const config the
 * resolver names, and the store must still read back unchanged. */
__attribute__((used, noinline))
int wt_platform_deputy_flash_probe(void)
{
    const wt_hsm_flash_config_t *cfg;
    uint8_t ref[WT_FLASH_PROGRAM_UNIT];
    uint8_t leak[WT_FLASH_PROGRAM_UNIT];
    uint32_t oor;
    int ok = 1;

    /* Wraps modulo 2^32 so base + offset addresses SPM-private RAM. */
    oor = (uint32_t)((uintptr_t)WT_RAM_S_BASE - g_hsm_flash_cfg.base);

    (void)memset(ref, 0, sizeof(ref));
    if (wt_deputy_read_ok(WT_SPM_KS_FLASH_READ, ref, sizeof(ref)) == 0) {
        return 0;
    }
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_READ, oor, 16u, leak);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_PROGRAM, oor, 16u, leak);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_ERASE, oor,
                                   g_hsm_flash_cfg.sector_size, NULL);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_VERIFY, oor, 16u, leak);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_BLANKCHECK, oor, 16u,
                                   NULL);
    /* A length running past the store from an in-range offset. */
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_READ,
                                   g_hsm_flash_cfg.size - 8u, 16u, leak);
    /* Misaligned program and sub-sector erase, checked on the const units. */
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_PROGRAM, 4u, 16u, leak);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_ERASE, 0u, 16u, NULL);

    /* Resolver seam: whatever the writable context holds, every primitive
     * takes its geometry from the immutable config. */
    g_hsm_flash_ctx.write_locked = true;
    cfg = wt_hsm_flash_cfg_of(&g_hsm_flash_ctx);
    g_hsm_flash_ctx.write_locked = false;
    if (cfg != &g_hsm_flash_cfg) {
        ok = 0;
    }

    (void)memset(leak, 0, sizeof(leak));
    if (wt_deputy_read_ok(WT_SPM_KS_FLASH_READ, leak, sizeof(leak)) == 0 ||
            memcmp(leak, ref, sizeof(ref)) != 0) {
        ok = 0;
    }
    if (wt_deputy_read_ok(WT_SPM_KS_FLASH_VERIFY, ref, sizeof(ref)) == 0) {
        ok = 0;
    }
    return ok;
}
#endif
