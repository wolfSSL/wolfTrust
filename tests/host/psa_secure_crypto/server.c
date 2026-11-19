/* server.c
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

/* The crypto partition stand-in: wt_native_submit with the Secure PSA
 * service over a RAM-simulated flash mapped from a file, so persistent keys
 * outlive a service restart. Frames on stdin/stdout:
 * [i32 client][u32 resp_cap][u32 len][req] in, [i32 rc][u32 len][resp] out. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/crypto_native.h"
#include "wolftrust/services/psa_crypto_service.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef WT_PSA_FLASH_FILE
#error "build with -DWT_PSA_FLASH_FILE naming the simulated flash file"
#endif

#define SRV_OWNER     6
#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static whFlashRamsimCfg g_ramsim_cfg;
static whFlashRamsimCtx g_ramsim_ctx;
static const whFlashCb g_ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
static whNvmFlashConfig g_nvm_flash_cfg;
static whNvmFlashContext g_nvm_flash_ctx;
static const whNvmCb g_nvm_cb[1] = {WH_NVM_FLASH_CB};
static whNvmConfig g_nvm_cfg;
static whNvmContext g_nvm_ctx;
static uint8_t g_flash_init[RAMSIM_SIZE];
#ifdef WT_PSA_POOL_STATS
static size_t g_fn_peak[WT_PSA_FN_COUNT];
static size_t g_rest_peak;

/* Per-function in-call peak and the resident peak between calls. */
static void pool_note(const uint8_t* req, size_t len)
{
    wt_crypto_wire_req_t hdr;
    size_t in_use;
    size_t peak;
    size_t hwm;

    wt_psa_pool_stats(&in_use, &peak, &hwm);
    if (in_use > g_rest_peak) {
        g_rest_peak = in_use;
    }
    if (len >= sizeof(hdr)) {
        (void)memcpy(&hdr, req, sizeof(hdr));
        if (hdr.op == WT_CRYPTO_OP_PSA && hdr.usage < WT_PSA_FN_COUNT &&
                peak > g_fn_peak[hdr.usage]) {
            g_fn_peak[hdr.usage] = peak;
        }
    }
}

static void pool_report(void)
{
    size_t in_use;
    size_t peak;
    size_t hwm;
    size_t fn;

    wt_psa_pool_stats(&in_use, &peak, &hwm);
    (void)fprintf(stderr, "POOL rest_peak=%zu hwm=%zu\n", g_rest_peak, hwm);
    for (fn = 0U; fn < WT_PSA_FN_COUNT; fn++) {
        if (g_fn_peak[fn] != 0U) {
            (void)fprintf(stderr, "POOL fn=%zu peak=%zu\n", fn, g_fn_peak[fn]);
        }
    }
}
#endif

int wolftrust_rng_generate_block(unsigned char* output, unsigned int sz)
{
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t got = -1;

    if (fd >= 0) {
        got = read(fd, output, sz);
        (void)close(fd);
    }
    return (got == (ssize_t)sz) ? 0 : -1;
}

static uint8_t* flash_map(const char* path)
{
    uint8_t* mem;
    off_t len;
    int fd = open(path, O_RDWR | O_CREAT, 0600);

    if (fd < 0) {
        return NULL;
    }
    len = lseek(fd, 0, SEEK_END);
    if (len != RAMSIM_SIZE && ftruncate(fd, RAMSIM_SIZE) != 0) {
        (void)close(fd);
        return NULL;
    }
    mem = (uint8_t*)mmap(NULL, RAMSIM_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    (void)close(fd);
    if (mem == MAP_FAILED) {
        return NULL;
    }
    if (len != RAMSIM_SIZE) {
        (void)memset(mem, 0xFF, RAMSIM_SIZE);
    }
    /* Ramsim erases on init unless handed the image to start from. */
    (void)memcpy(g_flash_init, mem, RAMSIM_SIZE);
    return mem;
}

static int store_up(uint8_t* mem)
{
    (void)memset(&g_ramsim_cfg, 0, sizeof(g_ramsim_cfg));
    g_ramsim_cfg.memory = mem;
    g_ramsim_cfg.size = RAMSIM_SIZE;
    g_ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    g_ramsim_cfg.pageSize = RAMSIM_PAGE;
    g_ramsim_cfg.erasedByte = 0xFF;
    g_ramsim_cfg.initData = g_flash_init;
    g_nvm_flash_cfg.cb = g_ramsim_cb;
    g_nvm_flash_cfg.context = &g_ramsim_ctx;
    g_nvm_flash_cfg.config = &g_ramsim_cfg;
    g_nvm_cfg.cb = (whNvmCb*)g_nvm_cb;
    g_nvm_cfg.context = &g_nvm_flash_ctx;
    g_nvm_cfg.config = &g_nvm_flash_cfg;
    if (wh_Nvm_Init(&g_nvm_ctx, &g_nvm_cfg) != WH_ERROR_OK ||
            wt_hsm_vault_init(&g_nvm_ctx) != 0 ||
            wt_hsm_keyvault_init(&g_nvm_ctx) != 0 ||
            wt_psa_service_init() != 0) {
        return -1;
    }
    return 0;
}

static int read_all(void* buf, size_t len)
{
    uint8_t* p = (uint8_t*)buf;
    ssize_t got;

    while (len != 0U) {
        got = read(STDIN_FILENO, p, len);
        if (got <= 0) {
            return -1;
        }
        p += got;
        len -= (size_t)got;
    }
    return 0;
}

static int write_all(const void* buf, size_t len)
{
    const uint8_t* p = (const uint8_t*)buf;
    ssize_t put;

    while (len != 0U) {
        put = write(STDOUT_FILENO, p, len);
        if (put <= 0) {
            return -1;
        }
        p += put;
        len -= (size_t)put;
    }
    return 0;
}

int main(void)
{
    uint8_t req[WT_HSM_RELAY_MSG_MAX];
    uint8_t resp[WT_HSM_RELAY_MSG_MAX];
    uint32_t frame[3];
    uint32_t out[2];
    size_t resp_len;
    uint8_t* mem;
    int rc;

    mem = flash_map(WT_PSA_FLASH_FILE);
    if (mem == NULL || store_up(mem) != 0) {
        (void)fprintf(stderr, "server: store setup failed\n");
        return 1;
    }
    while (read_all(frame, sizeof(frame)) == 0) {
        if (frame[2] > sizeof(req) || read_all(req, frame[2]) != 0) {
            return 1;
        }
        if (frame[1] > sizeof(resp)) {
            frame[1] = sizeof(resp);
        }
        resp_len = 0U;
#ifdef WT_PSA_POOL_STATS
        wt_psa_pool_stats_mark();
#endif
        rc = wt_native_submit((void*)(intptr_t)SRV_OWNER, (int32_t)frame[0],
                              req, frame[2], resp, frame[1], &resp_len);
#ifdef WT_PSA_POOL_STATS
        pool_note(req, frame[2]);
#endif
        out[0] = (uint32_t)rc;
        out[1] = (uint32_t)resp_len;
        if (write_all(out, sizeof(out)) != 0 ||
                write_all(resp, resp_len) != 0) {
            return 1;
        }
    }
#ifdef WT_PSA_POOL_STATS
    pool_report();
#endif
    return 0;
}
