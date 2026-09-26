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

/* wolfHSM NVM backend on the XSPI0 octal NOR. Reads go through the Secure
 * alias of the XIP window; program and erase issue XSPI IP commands through
 * the RAM-resident NOR driver (xspi_nor.c). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hsm_flash.h"
#include "memory_map.h"
#include "xspi_nor.h"
#include "mimxrt798_regs.h"
#include "wolftrust/arch.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/services/fwu_service.h"
#include "wolfhsm/wh_error.h"

typedef struct wt_hsm_flash_config {
    uintptr_t base;
    uint32_t size;
    uint32_t sector_size;
    uint32_t program_unit;
} wt_hsm_flash_config_t;

typedef struct wt_hsm_flash_context {
    bool write_locked;
} wt_hsm_flash_context_t;

static const wt_hsm_flash_config_t g_hsm_flash_cfg = {
    .base = WT_HSM_NVM_FLASH_BASE_S,
    .size = WT_HSM_NVM_FLASH_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = 16u,
};

static wt_hsm_flash_context_t g_hsm_flash_ctx;
volatile uint32_t g_wt_flash_gate_aborts __attribute__((used));
/* Last NOR driver failure, read over the debug port by the hardware harness. */
volatile int32_t g_wt_nor_last_error __attribute__((used));

/* The context sits in the keystore band the confined partitions can write, so
 * the privileged path takes its geometry from the const config it belongs to. */
static const wt_hsm_flash_config_t *wt_hsm_flash_cfg_of(const void *context)
{
    if (context == (const void *)&g_hsm_flash_ctx) {
        return &g_hsm_flash_cfg;
    }
    return NULL;
}

/* The store is read through the Secure alias; the NOR controller addresses
 * it in the Non-secure aperture numbering. */
static uint32_t wt_hsm_flash_device_address(const wt_hsm_flash_config_t *cfg,
                                            uint32_t offset)
{
    return (uint32_t)(cfg->base - WT_FLASH_S_ALIAS_BASE + WT_FLASH_NS_BASE) +
           offset;
}

static int wt_hsm_flash_nor_result(int rc)
{
    if (rc != WT_XSPI_NOR_OK) {
        g_wt_nor_last_error = (int32_t)rc;
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}
volatile uint32_t g_wt_flash_gate_abort_info __attribute__((used));

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
        return WH_ERROR_BADARGS;
    }
    if (size != 0u) {
        (void)memcpy(data, (const uint8_t *)(cfg->base + offset), size);
    }
    return WH_ERROR_OK;
}

static int wt_hsm_flash_program(void *context, uint32_t offset, uint32_t size,
                                const uint8_t *data)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);
    wt_hsm_flash_context_t *ctx = (wt_hsm_flash_context_t *)context;

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_PROGRAM, offset,
                                 size, (void *)(uintptr_t)data);
    }
    if (!wt_flash_range_ok(cfg, offset, size) ||
            (offset % cfg->program_unit) != 0u ||
            (size % cfg->program_unit) != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (size != 0u && ctx->write_locked) {
        return WH_ERROR_LOCKED;
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    return wt_hsm_flash_nor_result(
        wt_xspi_nor_program(wt_hsm_flash_device_address(cfg, offset), data,
                            size));
}

static int wt_hsm_flash_erase(void *context, uint32_t offset, uint32_t size)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);
    wt_hsm_flash_context_t *ctx = (wt_hsm_flash_context_t *)context;

    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_ERASE, offset, size,
                                 NULL);
    }
    if (!wt_flash_range_ok(cfg, offset, size) ||
            (offset % cfg->sector_size) != 0u ||
            (size % cfg->sector_size) != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (size != 0u && ctx->write_locked) {
        return WH_ERROR_LOCKED;
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }
    return wt_hsm_flash_nor_result(
        wt_xspi_nor_erase(wt_hsm_flash_device_address(cfg, offset), size));
}

static int wt_hsm_flash_verify(void *context, uint32_t offset, uint32_t size,
                               const uint8_t *data)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_VERIFY, offset,
                                 size, (void *)(uintptr_t)data);
    }
    if (!wt_flash_range_ok(cfg, offset, size)) {
        return WH_ERROR_BADARGS;
    }
    if (size != 0u &&
            memcmp((const uint8_t *)(cfg->base + offset), data, size) != 0) {
        return WH_ERROR_NOTVERIFIED;
    }
    return WH_ERROR_OK;
}

static int wt_hsm_flash_blank_check(void *context, uint32_t offset,
                                    uint32_t size)
{
    const wt_hsm_flash_config_t *cfg = wt_hsm_flash_cfg_of(context);
    const uint8_t *p;
    uint32_t i;

    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_BLANKCHECK, offset,
                                 size, NULL);
    }
    if (!wt_flash_range_ok(cfg, offset, size)) {
        return WH_ERROR_BADARGS;
    }
    p = (const uint8_t *)(cfg->base + offset);
    for (i = 0u; i < size; i++) {
        if (p[i] != 0xFFu) {
            return WH_ERROR_NOTBLANK;
        }
    }
    return WH_ERROR_OK;
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

/* SERVICE_FWU staging into the wolfBoot update partition: the NOR driver can
 * write it, but arming the wolfBoot trailer is not ported yet, so every
 * write-side entry reports NOTIMPL rather than stage an image nothing boots. */
static int wt_fwu_backend_begin(void *ctx)
{
    (void)ctx;
    return WH_ERROR_NOTIMPL;
}

static int wt_fwu_backend_write(void *ctx, uint32_t offset,
                                const uint8_t *data, uint32_t size)
{
    (void)ctx;
    (void)offset;
    (void)data;
    (void)size;
    return WH_ERROR_NOTIMPL;
}

static int wt_fwu_backend_arm(void *ctx, uint32_t image_size,
                              uint32_t version)
{
    (void)ctx;
    (void)image_size;
    (void)version;
    return WH_ERROR_NOTIMPL;
}

static int wt_fwu_backend_disarm(void *ctx)
{
    (void)ctx;
    return WH_ERROR_NOTIMPL;
}

static int wt_fwu_backend_verify(void *ctx, uint32_t staged_size,
                                 uint32_t *header_version)
{
    (void)ctx;
    (void)staged_size;
    (void)header_version;
    return WH_ERROR_NOTIMPL;
}

const wt_fwu_backend_t wt_fwu_flash_backend = {
    .begin = wt_fwu_backend_begin,
    .write = wt_fwu_backend_write,
    .arm = wt_fwu_backend_arm,
    .disarm = wt_fwu_backend_disarm,
    .capacity = WT_FWU_UPDATE_FLASH_SIZE - WT_FLASH_SECTOR_SIZE,
    .align = 16u,
    .verify = wt_fwu_backend_verify,
};

#if defined(WT_REMEASURE_PROBE)
int wt_hsm_flash_remeasure_tamper(uintptr_t secure_base)
{
    (void)secure_base;
    return -1;
}
#endif

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store)
{
    if (buf == NULL || len == 0u || len > WT_CONF_NVM_FLASH_SIZE) {
        return -1;
    }
    if (store == 0) {
        (void)memcpy(buf, (const uint8_t *)WT_CONF_NVM_FLASH_BASE_S, len);
        return 0;
    }
    return -1;
}
#endif
