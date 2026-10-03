/* hsm_nvm.c
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

/* wolfHSM NVM provider (WT-PORT-0003) and firmware-update staging for the
 * QEMU machines: RAM-backed until a flash controller model exists. The
 * vault therefore does not survive a reset on these targets. */

#include "wolftrust/port_nvm.h"
#include "wolftrust/services/fwu_service.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WT_NVM_SIZE        0x00010000u
#define WT_NVM_SECTOR_SIZE 0x00001000u
#define WT_NVM_PAGE_SIZE   16u
#define WT_FWU_STAGE_SIZE  0x00010000u

static uint8_t g_nvm_memory[WT_NVM_SIZE] __attribute__((aligned(16)));
static whFlashRamsimCtx g_nvm_ctx;
static const whFlashRamsimCfg g_nvm_cfg = {
    .memory = g_nvm_memory,
    .size = WT_NVM_SIZE,
    .sectorSize = WT_NVM_SECTOR_SIZE,
    .pageSize = WT_NVM_PAGE_SIZE,
    .erasedByte = 0xFFu,
    .initData = NULL,
};

const whFlashCb g_wt_hsm_flash_cb = WH_FLASH_RAMSIM_CB;

void *wt_hsm_flash_context(void)
{
    return &g_nvm_ctx;
}

const void *wt_hsm_flash_config(void)
{
    return &g_nvm_cfg;
}

int wt_hsm_flash_format(void)
{
    (void)memset(g_nvm_memory, 0xFF, sizeof(g_nvm_memory));
    return 0;
}

static uint8_t g_fwu_stage[WT_FWU_STAGE_SIZE] __attribute__((aligned(16)));
static uint32_t g_fwu_staged;

static int wt_fwu_backend_begin(void* ctx)
{
    (void)ctx;
    (void)memset(g_fwu_stage, 0xFF, sizeof(g_fwu_stage));
    g_fwu_staged = 0u;
    return 0;
}

static int wt_fwu_backend_write(void* ctx, uint32_t offset,
                                const uint8_t* data, uint32_t size)
{
    (void)ctx;
    if (data == NULL || size == 0u || offset > WT_FWU_STAGE_SIZE ||
            size > WT_FWU_STAGE_SIZE - offset) {
        return -1;
    }
    (void)memcpy(&g_fwu_stage[offset], data, size);
    if (offset + size > g_fwu_staged) {
        g_fwu_staged = offset + size;
    }
    return 0;
}

static int wt_fwu_backend_arm(void* ctx, uint32_t image_size,
                              uint32_t version)
{
    (void)ctx;
    (void)image_size;
    (void)version;
    return -1;
}

static int wt_fwu_backend_disarm(void* ctx)
{
    (void)ctx;
    return 0;
}

/* No boot loader consumes the staged image on these machines yet. */
static int wt_fwu_backend_verify(void* ctx, uint32_t staged_size,
                                 uint32_t* header_version)
{
    (void)ctx;
    (void)staged_size;
    (void)header_version;
    return -1;
}

const wt_fwu_backend_t wt_fwu_flash_backend = {
    .begin = wt_fwu_backend_begin,
    .write = wt_fwu_backend_write,
    .arm = wt_fwu_backend_arm,
    .disarm = wt_fwu_backend_disarm,
    .capacity = WT_FWU_STAGE_SIZE,
    .align = 16u,
    .verify = wt_fwu_backend_verify,
};
