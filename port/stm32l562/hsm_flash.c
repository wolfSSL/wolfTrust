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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "hsm_flash.h"

#include "memory_map.h"
#include "stm32l562_regs.h"
#include "wolfhsm/wh_error.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/services/fwu_service.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/arch.h"
#include "wolftrust/zeroize.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define WT_FLASH_SR_ALL_ERR    (WT_FLASH_SR_OPERR | WT_FLASH_SR_PROGERR | \
                                WT_FLASH_SR_WRPERR | WT_FLASH_SR_PGAERR | \
                                WT_FLASH_SR_SIZERR | WT_FLASH_SR_PGSERR)
/* DBANK=1 reports through ECCC and ECCD; ECCC2/ECCD2 are the single-bank
 * flags, and ADDR_ECC/BK_ECC hold until ECCC and ECCD clear (RM0438). */
#define WT_FLASH_ECCR_ECCC     (1u << 30)
#define WT_FLASH_ECCR_ECCIE    (1u << 24)
#define WT_FLASH_BANK2_BASE_NS (WT_FLASH_NS_BASE + WT_FLASH_BANK_SIZE)

static const wt_hsm_flash_config_t g_hsm_flash_cfg = {
    .base = WT_HSM_NVM_FLASH_BASE_S,
    .size = WT_HSM_NVM_FLASH_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = 8u,
};

/* The keystore partitions run unprivileged and their flash context struct
 * lives in partition-writable RAM, so its base/size cannot be trusted by the
 * privileged flash primitives: a partition that rewrote them would redirect a
 * privileged read/program/erase to any address. Geometry is resolved instead
 * from the immutable .rodata config keyed by the context identity, and an
 * unknown context is refused. */
static const wt_hsm_flash_config_t g_fwu_flash_cfg;
static wt_hsm_flash_context_t g_fwu_flash_ctx;
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
static const wt_hsm_flash_config_t g_conf_nvm_cfg;
static wt_hsm_flash_context_t g_conf_nvm_ctx;
#endif

static const wt_hsm_flash_config_t *wt_flash_geometry(const void *context)
{
    if (context == (const void *)&g_hsm_flash_ctx) {
        return &g_hsm_flash_cfg;
    }
    if (context == (const void *)&g_fwu_flash_ctx) {
        return &g_fwu_flash_cfg;
    }
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    if (context == (const void *)&g_conf_nvm_ctx) {
        return &g_conf_nvm_cfg;
    }
#endif
    return NULL;
}

/* Direct-path forensics (SWD-readable): count every program/erase attempt on
 * the NVM context and latch the first failure's sub-op, offset, and the raw
 * FLASH_SR error bits before they are cleared. */
volatile uint32_t g_wt_flash_prog_calls __attribute__((used));
volatile uint32_t g_wt_flash_erase_calls __attribute__((used));
volatile uint32_t g_wt_flash_first_err __attribute__((used));
volatile uint32_t g_wt_flash_first_err_off __attribute__((used));
volatile uint32_t g_wt_flash_first_err_sr __attribute__((used));
static volatile uint32_t g_flash_ecc_active;
static volatile uint32_t g_flash_ecc_detected;
static volatile uint32_t g_flash_ecc_bank;
static volatile uint32_t g_flash_ecc_start;
static volatile uint32_t g_flash_ecc_end;

static void wt_flash_barrier(void)
{
    __asm__ volatile ("dsb 0xF" ::: "memory");
    __asm__ volatile ("isb 0xF" ::: "memory");
}

static uint32_t wt_irq_save(void)
{
    uint32_t primask;

    __asm__ volatile ("mrs %0, primask" : "=r" (primask));
    __asm__ volatile ("cpsid i" ::: "memory");
    return primask;
}

static void wt_irq_restore(uint32_t primask)
{
    __asm__ volatile ("msr primask, %0" :: "r" (primask) : "memory");
}

/* ECCC and ECCD are write-1-to-clear; keep the interrupt enable. */
static void wt_flash_ecc_clear(void)
{
    WT_FLASH_ECCR = (WT_FLASH_ECCR & WT_FLASH_ECCR_ECCIE) |
                    WT_FLASH_ECCR_ECCC | WT_FLASH_ECCR_ECCD;
}

void NMI_Handler(void)
{
    uint32_t ecc = WT_FLASH_ECCR;
    uint32_t bank = (ecc & WT_FLASH_ECCR_BK) != 0u ? 1u : 0u;
    uint32_t address = ecc & WT_FLASH_ECCR_ADDR_MASK;

    if ((ecc & WT_FLASH_ECCR_ECCD) != 0u && g_flash_ecc_active != 0u &&
        bank == g_flash_ecc_bank && address >= g_flash_ecc_start &&
        address < g_flash_ecc_end) {
        g_flash_ecc_detected = 1u;
        wt_flash_ecc_clear();
        wt_flash_barrier();
        return;
    }

    for (;;) {
        __asm__ volatile ("wfi");
    }
}

static int wt_flash_read_checked(const uint8_t *source, uint8_t *data,
                                 uint32_t size)
{
    uintptr_t ns_address;
    uint32_t primask;
    uint32_t bank_off;
    uint32_t i;
    int ret = WH_ERROR_OK;

    primask = wt_irq_save();
    ns_address = (uintptr_t)source & ~0x04000000u;
    /* ADDR_ECC is a byte address within the bank, 0x0-0x7FFF8 (RM0438
     * FLASH_ECCR), the failing double-word's offset, not its index. */
    g_flash_ecc_bank = ns_address >= WT_FLASH_BANK2_BASE_NS ? 1u : 0u;
    if ((WT_FLASH_OPTR & WT_FLASH_OPTR_SWAP_BANK) != 0u) {
        g_flash_ecc_bank ^= 1u;
    }
    bank_off = (uint32_t)((ns_address - WT_FLASH_NS_BASE) %
                          WT_FLASH_BANK_SIZE);
    /* Exactly the double-words the read touches */
    g_flash_ecc_start = bank_off & ~7u;
    g_flash_ecc_end = (bank_off + size + 7u) & ~7u;
    g_flash_ecc_detected = 0u;
    wt_flash_ecc_clear();
    g_flash_ecc_active = 1u;
    wt_flash_barrier();

    for (i = 0u; i < size; i++) {
        data[i] = ((const volatile uint8_t *)source)[i];
    }
    wt_flash_barrier();
    g_flash_ecc_active = 0u;

    if (g_flash_ecc_detected != 0u ||
        (WT_FLASH_ECCR & WT_FLASH_ECCR_ECCD) != 0u) {
        ret = WH_ERROR_ABORTED;
        (void)memset(data, 0, size);
    }
    wt_flash_ecc_clear();
    wt_flash_barrier();
    wt_irq_restore(primask);

    return ret;
}

static uintptr_t wt_flash_ns_addr(uintptr_t addr)
{
    return addr & ~0x04000000u;
}

static int wt_flash_range_ok(const wt_hsm_flash_config_t *geom,
                             uint32_t offset, uint32_t size)
{
    if (geom == NULL || geom->sector_size == 0u || geom->program_unit == 0u) {
        return 0;
    }
    if (offset > geom->size) {
        return 0;
    }
    if (size > geom->size - offset) {
        return 0;
    }
    return 1;
}

static void wt_flash_wait_complete(void)
{
    while ((WT_FLASH_SECSR & WT_FLASH_SR_BSY) != 0u) {
    }
}

/* SECSR flags are write-1-to-clear. */
static void wt_flash_clear_errors(void)
{
    WT_FLASH_SECSR = WT_FLASH_SR_ALL_ERR | WT_FLASH_SR_EOP;
}

static int wt_flash_check_errors(void)
{
    if ((WT_FLASH_SECSR & WT_FLASH_SR_ALL_ERR) != 0u) {
        wt_flash_clear_errors();
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

static void wt_flash_unlock(void)
{
    wt_flash_wait_complete();
    if ((WT_FLASH_SECCR & WT_FLASH_CR_LOCK) != 0u) {
        WT_FLASH_SECKEYR = WT_FLASH_KEY1;
        wt_flash_barrier();
        WT_FLASH_SECKEYR = WT_FLASH_KEY2;
        wt_flash_barrier();
        while ((WT_FLASH_SECCR & WT_FLASH_CR_LOCK) != 0u) {
        }
    }
}

static void wt_flash_lock(void)
{
    wt_flash_wait_complete();
    if ((WT_FLASH_SECCR & WT_FLASH_CR_LOCK) == 0u) {
        WT_FLASH_SECCR |= WT_FLASH_CR_LOCK;
    }
}

static void wt_flash_icache_invalidate(void)
{
    if ((WT_ICACHE_CR & WT_ICACHE_CR_EN) != 0u) {
        WT_ICACHE_CR |= WT_ICACHE_CR_CACHEINV;
        while ((WT_ICACHE_SR & WT_ICACHE_SR_BUSYF) != 0u) {
        }
        wt_flash_barrier();
    }
}

/* Confined-keystore trap: the controller-touching callbacks below also run
 * inside the unprivileged keystore partitions, whose MPU domain has no
 * flash-controller access; hop to the privileged SVC dispatcher, which
 * re-enters the same callback with privilege. Only the shared NVM context may
 * take this path; the FWU staging context has its own pinned gate. */
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

    if (ctx == NULL || cfg == NULL || cfg->base == 0u || cfg->size == 0u ||
        cfg->sector_size == 0u || cfg->program_unit == 0u ||
        (cfg->size % cfg->sector_size) != 0u ||
        (cfg->sector_size % cfg->program_unit) != 0u) {
        return WH_ERROR_BADARGS;
    }

    ctx->base = cfg->base;
    ctx->size = cfg->size;
    ctx->sector_size = cfg->sector_size;
    ctx->program_unit = cfg->program_unit;
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
    wt_flash_lock();
    return WH_ERROR_OK;
}

static uint32_t wt_hsm_flash_partition_size(void *context)
{
    const wt_hsm_flash_config_t *geom = wt_flash_geometry(context);

    if (geom == NULL) {
        return 0u;
    }
    return geom->sector_size;
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
    const wt_hsm_flash_config_t *geom;

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_READ, offset, size,
                                 data);
    }
    geom = wt_flash_geometry(context);
    if (!wt_flash_range_ok(geom, offset, size)) {
        return WH_ERROR_BADARGS;
    }
    if (size != 0u) {
        return wt_flash_read_checked((const uint8_t *)(geom->base + offset),
                                     data, size);
    }
    return WH_ERROR_OK;
}

static int wt_hsm_flash_program(void *context, uint32_t offset, uint32_t size,
                                const uint8_t *data)
{
    uint32_t primask;
    const wt_hsm_flash_config_t *geom = wt_flash_geometry(context);
    const wt_hsm_flash_context_t *ctx = (const wt_hsm_flash_context_t *)context;
    uint32_t written = 0u;
    int ret = WH_ERROR_OK;

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_PROGRAM, offset,
                                 size, (void *)(uintptr_t)data);
    }
    if (context == (const void *)&g_hsm_flash_ctx) {
        g_wt_flash_prog_calls++;
    }
    if (!wt_flash_range_ok(geom, offset, size)) {
        if (g_wt_flash_first_err == 0u) {
            g_wt_flash_first_err = 0x01000000u | (uint32_t)(-WH_ERROR_BADARGS);
            g_wt_flash_first_err_off = offset;
        }
        return WH_ERROR_BADARGS;
    }
    if ((offset % geom->program_unit) != 0u ||
        (size % geom->program_unit) != 0u) {
        if (g_wt_flash_first_err == 0u) {
            g_wt_flash_first_err = 0x02000000u | (uint32_t)(-WH_ERROR_BADARGS);
            g_wt_flash_first_err_off = offset;
        }
        return WH_ERROR_BADARGS;
    }
    if (size != 0u && ctx->write_locked) {
        if (g_wt_flash_first_err == 0u) {
            g_wt_flash_first_err = 0x03000000u | (uint32_t)(-WH_ERROR_LOCKED);
            g_wt_flash_first_err_off = offset;
        }
        return WH_ERROR_LOCKED;
    }

    wt_flash_unlock();
    wt_flash_clear_errors();

    while (written < size) {
        uintptr_t dst = geom->base + offset + written;
        uint32_t word[2];
        volatile uint32_t *flash_word = (volatile uint32_t *)dst;

        (void)memcpy(word, data + written, sizeof(word));

        /* One 64-bit double-word per program operation; an interrupt between
         * the two halves would break the sequence (PGSERR/SIZERR). */
        primask = wt_irq_save();
        WT_FLASH_SECCR |= WT_FLASH_CR_PG;
        flash_word[0] = word[0];
        wt_flash_barrier();
        flash_word[1] = word[1];
        wt_flash_barrier();
        wt_irq_restore(primask);
        wt_flash_wait_complete();

        if ((WT_FLASH_SECSR & WT_FLASH_SR_EOP) != 0u) {
            WT_FLASH_SECSR = WT_FLASH_SR_EOP;
        }
        WT_FLASH_SECCR &= ~WT_FLASH_CR_PG;

        if ((WT_FLASH_SECSR & WT_FLASH_SR_ALL_ERR) != 0u &&
                g_wt_flash_first_err == 0u) {
            g_wt_flash_first_err = 0x04000000u;
            g_wt_flash_first_err_off = offset + written;
            g_wt_flash_first_err_sr = WT_FLASH_SECSR;
        }
        ret = wt_flash_check_errors();
        wt_forceZero(word, sizeof(word));
        if (ret != WH_ERROR_OK) {
            break;
        }
        written += geom->program_unit;
    }

    WT_FLASH_SECCR &= ~WT_FLASH_CR_PG;
    wt_flash_lock();
    wt_flash_icache_invalidate();
    return ret;
}

static int wt_hsm_flash_erase(void *context, uint32_t offset, uint32_t size)
{
    const wt_hsm_flash_config_t *geom = wt_flash_geometry(context);
    const wt_hsm_flash_context_t *ctx = (const wt_hsm_flash_context_t *)context;
    uint32_t start;
    uint32_t end;

    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_ERASE, offset, size,
                                 NULL);
    }
    if (context == (const void *)&g_hsm_flash_ctx) {
        g_wt_flash_erase_calls++;
    }
    if (!wt_flash_range_ok(geom, offset, size)) {
        return WH_ERROR_BADARGS;
    }
    if ((offset % geom->sector_size) != 0u ||
        (size % geom->sector_size) != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (size != 0u && ctx->write_locked) {
        return WH_ERROR_LOCKED;
    }
    if (size == 0u) {
        return WH_ERROR_OK;
    }

    start = offset;
    end = offset + size;

    wt_flash_unlock();
    wt_flash_clear_errors();

    /* A wolfHSM "sector" spans several 2 KiB pages; erase one page at a
     * time, numbered within its bank (BKER selects bank 2). */
    while (start < end) {
        uintptr_t ns_addr = wt_flash_ns_addr(geom->base + start);
        uint32_t page = (uint32_t)((ns_addr - WT_FLASH_NS_BASE) /
                                   WT_FLASH_PAGE_SIZE);
        uint32_t bank = 0u;
        uint32_t page_in_bank = page;
        uint32_t cr;

        if (ns_addr >= WT_FLASH_BANK2_BASE_NS) {
            bank = 1u;
            page_in_bank = page - (WT_FLASH_BANK_SIZE / WT_FLASH_PAGE_SIZE);
        }
        if ((WT_FLASH_OPTR & WT_FLASH_OPTR_SWAP_BANK) != 0u) {
            bank ^= 1u;
        }

        cr = WT_FLASH_SECCR & ~((WT_FLASH_CR_PNB_MASK << WT_FLASH_CR_PNB_SHIFT) |
                                WT_FLASH_CR_PER | WT_FLASH_CR_PG |
                                WT_FLASH_CR_BKER);
        cr |= (page_in_bank << WT_FLASH_CR_PNB_SHIFT) | WT_FLASH_CR_PER |
              (bank != 0u ? WT_FLASH_CR_BKER : 0u);
        WT_FLASH_SECCR = cr;
        wt_flash_barrier();
        WT_FLASH_SECCR |= WT_FLASH_CR_STRT;
        wt_flash_wait_complete();

        if ((WT_FLASH_SECSR & WT_FLASH_SR_ALL_ERR) != 0u &&
                g_wt_flash_first_err == 0u) {
            g_wt_flash_first_err = 0x05000000u;
            g_wt_flash_first_err_off = start;
            g_wt_flash_first_err_sr = WT_FLASH_SECSR;
        }
        if (wt_flash_check_errors() != WH_ERROR_OK) {
            WT_FLASH_SECCR &= ~WT_FLASH_CR_PER;
            wt_flash_lock();
            wt_flash_icache_invalidate();
            return WH_ERROR_ABORTED;
        }
        start += WT_FLASH_PAGE_SIZE;
    }

    WT_FLASH_SECCR &= ~WT_FLASH_CR_PER;
    wt_flash_lock();
    wt_flash_icache_invalidate();
    return WH_ERROR_OK;
}

static int wt_hsm_flash_verify(void *context, uint32_t offset, uint32_t size,
                               const uint8_t *data)
{
    const wt_hsm_flash_config_t *geom = wt_flash_geometry(context);
    uint8_t flash_data[16];
    uint32_t checked = 0u;
    int ret = WH_ERROR_OK;

    if (data == NULL && size != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_VERIFY, offset,
                                 size, (void *)(uintptr_t)data);
    }
    if (!wt_flash_range_ok(geom, offset, size)) {
        return WH_ERROR_BADARGS;
    }
    while (checked < size && ret == WH_ERROR_OK) {
        uint32_t chunk = size - checked;

        if (chunk > sizeof(flash_data)) {
            chunk = sizeof(flash_data);
        }
        ret = wt_flash_read_checked(
                (const uint8_t *)(geom->base + offset + checked), flash_data,
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
    return ret;
}

static int wt_hsm_flash_blank_check(void *context, uint32_t offset,
                                    uint32_t size)
{
    const wt_hsm_flash_config_t *geom = wt_flash_geometry(context);
    uint8_t flash_data[16];
    uint32_t checked = 0u;
    uint32_t i;
    int ret = WH_ERROR_OK;

    if (wt_arch_thread_unprivileged()) {
        return wt_hsm_flash_gate(context, WT_SPM_KS_FLASH_BLANKCHECK, offset,
                                 size, NULL);
    }
    if (!wt_flash_range_ok(geom, offset, size)) {
        return WH_ERROR_BADARGS;
    }
    while (checked < size && ret == WH_ERROR_OK) {
        uint32_t chunk = size - checked;

        if (chunk > sizeof(flash_data)) {
            chunk = sizeof(flash_data);
        }
        ret = wt_flash_read_checked(
                (const uint8_t *)(geom->base + offset + checked), flash_data,
                chunk);
        for (i = 0u; i < chunk && ret == WH_ERROR_OK; i++) {
            if (flash_data[i] != 0xFFu) {
                ret = WH_ERROR_NOTBLANK;
            }
        }
        if (ret == WH_ERROR_OK) {
            checked += chunk;
        }
    }
    wt_forceZero(flash_data, sizeof(flash_data));
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
    /* Erase the whole vault NVM region so wh_Nvm_Init rebuilds a blank store.
     * The size comes from the immutable config, not the partition-writable
     * context; the erase honors sector alignment and the write-lock. */
    return wt_hsm_flash_erase(&g_hsm_flash_ctx, 0u, g_hsm_flash_cfg.size);
}

/* SERVICE_FWU staging into the wolfBoot update partition (WT-FWU-0002). The
 * unprivileged FWU SP crosses the privileged SVC gate to erase each target
 * sector lazily, program the candidate, and verify each block in secure flash.
 * install() arms wolfBoot's real WRITEONCE update trigger in the UPDATE
 * partition trailer (wt_fwu_wolfboot_arm_trailer), so the next boot swaps the
 * staged image; the swapped image is still gated by authenticated launch and
 * anti-rollback at boot (P6-S6). */

static const wt_hsm_flash_config_t g_fwu_flash_cfg = {
    .base = WT_FWU_UPDATE_FLASH_BASE_S,
    .size = WT_FWU_UPDATE_FLASH_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = 8u,
};
static wt_hsm_flash_context_t g_fwu_flash_ctx;
static uint32_t g_fwu_erased_sectors;
/* Each double-word programs once per erase, so staging is strictly sequential:
 * a write that skips ahead or rewrites staged data is refused. */
static uint32_t g_fwu_written_end;

static int wt_fwu_ensure_erased(uint32_t offset, uint32_t size)
{
    uint32_t sector_size = g_fwu_flash_cfg.sector_size;
    uint32_t first = offset / sector_size;
    uint32_t last = (offset + size - 1u) / sector_size;
    uint32_t s;

    for (s = first; s <= last; s++) {
        if (s < 32u && (g_fwu_erased_sectors & (1u << s)) != 0u) {
            continue;
        }
        if (wt_hsm_flash_erase(&g_fwu_flash_ctx, s * sector_size,
                               sector_size) != WH_ERROR_OK) {
            return -1;
        }
        if (s < 32u) {
            g_fwu_erased_sectors |= (1u << s);
        }
    }
    return 0;
}

static int wt_fwu_backend_begin(void *ctx)
{
    (void)ctx;
    if (wt_hsm_flash_init(&g_fwu_flash_ctx, &g_fwu_flash_cfg) != WH_ERROR_OK) {
        return -1;
    }
    g_fwu_erased_sectors = 0u;
    g_fwu_written_end = 0u;
    return 0;
}

/* Every FWU readback goes through the ECC-checked reader, so a double error
 * fails the operation instead of halting in the NMI handler. */
static int wt_fwu_read(uint32_t offset, uint8_t *data, uint32_t size)
{
    return (wt_hsm_flash_read(&g_fwu_flash_ctx, offset, size, data) ==
            WH_ERROR_OK) ? 0 : -1;
}

static int wt_fwu_backend_write(void *ctx, uint32_t offset,
                                const uint8_t *data, uint32_t size)
{
    uint32_t reserved = g_fwu_flash_cfg.size - g_fwu_flash_cfg.sector_size;

    (void)ctx;
    /* The trailer sector holds wolfBoot's swap trigger and is owned by
     * arm/disarm alone; staging data must never pre-program it. */
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
    if (wt_hsm_flash_verify(&g_fwu_flash_ctx, offset, size, data) !=
            WH_ERROR_OK) {
        return -1;
    }
    g_fwu_written_end = offset + size;
    return 0;
}

static int wt_fwu_backend_disarm(void *ctx);

static int wt_fwu_backend_arm(void *ctx, uint32_t image_size, uint32_t version)
{
    uint8_t block[16];
    uint32_t block_off = g_fwu_flash_cfg.size - (uint32_t)sizeof(block);

    (void)ctx;
    (void)image_size;
    (void)version;
    /* The wolfBoot trigger (state + magic) ends the partition; the block is
     * two 8-byte program units, so it starts 16 bytes from the end. */
    if (wt_fwu_wolfboot_arm_trailer(block, (uint32_t)sizeof(block)) != 0) {
        return -1;
    }
    if (wt_fwu_ensure_erased(block_off, (uint32_t)sizeof(block)) != 0) {
        return -1;
    }
    if (wt_hsm_flash_program(&g_fwu_flash_ctx, block_off,
                             (uint32_t)sizeof(block), block) != WH_ERROR_OK ||
            wt_hsm_flash_verify(&g_fwu_flash_ctx, block_off,
                                (uint32_t)sizeof(block), block) !=
                WH_ERROR_OK) {
        /* A partially programmed trigger must not survive a failed arm. */
        (void)wt_fwu_backend_disarm(NULL);
        return -1;
    }
    return 0;
}

static int wt_fwu_backend_disarm(void *ctx)
{
    uint32_t trailer = g_fwu_flash_cfg.size - g_fwu_flash_cfg.sector_size;

    (void)ctx;
    if (wt_hsm_flash_erase(&g_fwu_flash_ctx, trailer,
                           g_fwu_flash_cfg.sector_size) != WH_ERROR_OK) {
        return -1;
    }
    return 0;
}

/* wolfBoot image header size for this port (staged images carry it). */
#define WT_FWU_IMAGE_HEADER_SIZE 0x400u
#define WT_FWU_IMAGE_MAGIC 0x464C4F57u
#define WT_FWU_HDR_TAG_VERSION 0x0001u

static int wt_fwu_backend_verify(void *ctx, uint32_t staged_size,
                                 uint32_t *header_version)
{
    uint8_t field[8];
    uint32_t magic;
    uint32_t fw_size;
    uint32_t version = 0u;
    uint32_t offset = 8u;
    uint32_t tag;
    uint32_t len;
    int found = 0;

    (void)ctx;
    /* FINISH passes the logical size; the staged extent is it rounded up to
     * the 16-byte write alignment. */
    if (header_version == NULL ||
            staged_size < WT_FWU_IMAGE_HEADER_SIZE ||
            !wt_fwu_staged_extent_ok(staged_size, g_fwu_written_end, 16u)) {
        return -1;
    }
    if (wt_fwu_read(0u, field, 8u) != 0) {
        return -1;
    }
    memcpy(&magic, field, sizeof(magic));
    memcpy(&fw_size, field + 4u, sizeof(fw_size));
    if (magic != WT_FWU_IMAGE_MAGIC) {
        return -1;
    }
    /* The staged extent must cover the header plus the declared payload. */
    if (fw_size > staged_size - WT_FWU_IMAGE_HEADER_SIZE) {
        return -1;
    }
    while (offset + 4u <= WT_FWU_IMAGE_HEADER_SIZE) {
        if (wt_fwu_read(offset, field, 4u) != 0) {
            return -1;
        }
        if (field[0] == 0xFFu) {
            offset++;
            continue;
        }
        tag = (uint32_t)field[0] | ((uint32_t)field[1] << 8);
        len = (uint32_t)field[2] | ((uint32_t)field[3] << 8);
        if (tag == 0u) {
            break;
        }
        if (offset + 4u + len > WT_FWU_IMAGE_HEADER_SIZE) {
            return -1;
        }
        if (tag == WT_FWU_HDR_TAG_VERSION && len == sizeof(version)) {
            if (wt_fwu_read(offset + 4u, field, 4u) != 0) {
                return -1;
            }
            memcpy(&version, field, sizeof(version));
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
    /* The trailer sector is arm/disarm-owned, never staging capacity. */
    .capacity = WT_FWU_UPDATE_FLASH_SIZE - WT_FLASH_SECTOR_SIZE,
    .align = 16u,
    .verify = wt_fwu_backend_verify,
};

#if defined(WT_REMEASURE_PROBE)
/* A guest page is Non-secure, and the Secure controller refuses it
 * (SECWRPERR), so the probe tamper goes through the Non-secure bank. */
#define WT_FLASH_BASE_NS   0x40022000u
#define WT_FLASH_NSKEYR    WT_REG32(WT_FLASH_BASE_NS + 0x08u)
#define WT_FLASH_NSSR      WT_REG32(WT_FLASH_BASE_NS + 0x20u)
#define WT_FLASH_NSCR      WT_REG32(WT_FLASH_BASE_NS + 0x28u)

static int wt_flash_ns_wait(void)
{
    uint32_t sr;

    do {
        sr = WT_FLASH_NSSR;
    } while ((sr & WT_FLASH_SR_BSY) != 0u);
    WT_FLASH_NSSR = sr & (WT_FLASH_SR_ALL_ERR | WT_FLASH_SR_EOP);
    return ((sr & WT_FLASH_SR_ALL_ERR) != 0u) ? -1 : 0;
}

int wt_hsm_flash_remeasure_tamper(uintptr_t ns_base)
{
    volatile uint32_t *word = (volatile uint32_t *)ns_base;
    uint32_t off = (uint32_t)(ns_base - WT_FLASH_NS_BASE);
    uint32_t cr;
    int ret;

    if (ns_base < WT_FLASH_NS_BASE || off >= WT_FLASH_SIZE ||
            (off % WT_FLASH_SECTOR_SIZE) != 0u) {
        return -1;
    }
    if ((WT_FLASH_NSCR & WT_FLASH_CR_LOCK) != 0u) {
        WT_FLASH_NSKEYR = WT_FLASH_KEY1;
        WT_FLASH_NSKEYR = WT_FLASH_KEY2;
    }
    WT_FLASH_NSSR = WT_FLASH_SR_ALL_ERR | WT_FLASH_SR_EOP;
    cr = WT_FLASH_CR_PER |
         (((off % WT_FLASH_BANK_SIZE) / WT_FLASH_PAGE_SIZE) <<
          WT_FLASH_CR_PNB_SHIFT);
    if (off >= WT_FLASH_BANK_SIZE) {
        cr |= WT_FLASH_CR_BKER;
    }
    WT_FLASH_NSCR = cr;
    WT_FLASH_NSCR = cr | WT_FLASH_CR_STRT;
    ret = wt_flash_ns_wait();
    WT_FLASH_NSCR = 0u;
    if (ret == 0) {
        WT_FLASH_NSCR = WT_FLASH_CR_PG;
        word[0] = 0u;
        wt_flash_barrier();
        word[1] = 0u;
        wt_flash_barrier();
        ret = wt_flash_ns_wait();
        WT_FLASH_NSCR = 0u;
    }
    WT_FLASH_NSCR = WT_FLASH_CR_LOCK;
    wt_flash_icache_invalidate();
    return ret;
}
#endif

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
static const wt_hsm_flash_config_t g_conf_nvm_cfg = {
    .base = WT_CONF_NVM_FLASH_BASE_S,
    .size = WT_CONF_NVM_FLASH_SIZE,
    .sector_size = WT_FLASH_SECTOR_SIZE,
    .program_unit = 8u,
};
static wt_hsm_flash_context_t g_conf_nvm_ctx;
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
#endif /* WT_CONFORMANCE */

#if defined(WT_DEPUTY_NEG_PROBE) && (WT_DEPUTY_NEG_PROBE == 1)
/* A primitive fed a forged out-of-range offset must reject it with exactly
 * WH_ERROR_BADARGS through a delivered gate call, not a gate-level failure or
 * any other backend error. Returns 1 only on that exact outcome. */
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

/* used + noinline so the link guard in the deputyneg runner can confirm the
 * probe is present rather than inlined away under LTO. */
__attribute__((used, noinline))
int wt_platform_deputy_flash_probe(void)
{
    wt_spm_call_t call;
    const wt_hsm_flash_config_t *geom;
    uint8_t ref[16];
    uint8_t leak[16];
    uint32_t oor;
    int ok = 1;

    /* Offset whose base + offset lands in SPM-private RAM. */
    oor = (uint32_t)((uintptr_t)WT_RAM_S_BASE - g_hsm_flash_cfg.base);

    /* Reference: a legitimate in-range read of the real NVM region. */
    g_hsm_flash_ctx.base = g_hsm_flash_cfg.base;
    g_hsm_flash_ctx.size = g_hsm_flash_cfg.size;
    (void)memset(ref, 0, sizeof(ref));
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_KEYSTORE_FLASH;
    call.call_type = WT_SPM_KS_FLASH_READ;
    call.vec_idx = 0u;
    call.num_bytes = (uint32_t)sizeof(ref);
    call.buffer = ref;
    if (wt_arch_sp_trap(&call) != WT_FFM_SUCCESS || call.ret_int != WH_ERROR_OK) {
        return 0;
    }

    /* Size vector: inflate the writable size so a bound check against it would
     * pass, then confirm every primitive still refuses the SPM-targeting
     * offset via the immutable geometry (exactly WH_ERROR_BADARGS). oor is
     * sector-aligned, so the erase check rejects on range, not on alignment. */
    g_hsm_flash_ctx.size = 0xFFFFFFFFu;
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_READ, oor, 16u, leak);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_PROGRAM, oor, 16u, leak);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_ERASE, oor,
                                   g_hsm_flash_cfg.sector_size, NULL);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_VERIFY, oor, 16u, leak);
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_BLANKCHECK, oor, 16u, NULL);

    /* program_unit vector: forge a one-byte unit so a misaligned program would
     * pass an alignment check against the context; the fixed primitive uses
     * the immutable 16-byte unit and refuses. The offset stays in range, so
     * the fixed path rejects on alignment without touching the store. */
    g_hsm_flash_ctx.base = g_hsm_flash_cfg.base;
    g_hsm_flash_ctx.size = g_hsm_flash_cfg.size;
    g_hsm_flash_ctx.program_unit = 1u;
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_PROGRAM, 4u, 16u, leak);
    g_hsm_flash_ctx.program_unit = g_hsm_flash_cfg.program_unit;

    /* sector_size vector: forge a small sector so a sub-sector erase would pass
     * an alignment check against the context; the fixed primitive uses the
     * immutable sector size and refuses without erasing the store. */
    g_hsm_flash_ctx.sector_size = 16u;
    ok &= wt_deputy_expect_badargs(WT_SPM_KS_FLASH_ERASE, 0u, 16u, NULL);
    g_hsm_flash_ctx.sector_size = g_hsm_flash_cfg.sector_size;

    /* Resolver seam: every primitive selects its geometry through
     * wt_flash_geometry(). With all four context fields forged, the resolver
     * must still return the immutable config, so the base, size, sector size
     * and program unit that program, erase, verify and blank-check use are
     * never taken from partition-writable memory. This is the non-destructive
     * proof for the mutating primitives, whose base cannot be substituted
     * on-target without erasing the live store. */
    g_hsm_flash_ctx.base = (uintptr_t)WT_RAM_S_BASE;
    g_hsm_flash_ctx.size = 0xFFFFFFFFu;
    g_hsm_flash_ctx.sector_size = 16u;
    g_hsm_flash_ctx.program_unit = 1u;
    geom = wt_flash_geometry(&g_hsm_flash_ctx);
    if (geom == NULL || geom->base != g_hsm_flash_cfg.base ||
            geom->size != g_hsm_flash_cfg.size ||
            geom->sector_size != g_hsm_flash_cfg.sector_size ||
            geom->program_unit != g_hsm_flash_cfg.program_unit) {
        ok = 0;
    }

    /* Base vector (read and verify are non-destructive): point the writable
     * base at SPM RAM with an in-range offset. The fixed read and verify
     * resolve the base from the immutable config, so the read returns the NVM
     * reference and the verify matches it; taking the base from the context
     * would return or compare SPM bytes instead. */
    g_hsm_flash_ctx.base = (uintptr_t)WT_RAM_S_BASE;
    g_hsm_flash_ctx.size = 0xFFFFFFFFu;
    (void)memset(leak, 0, sizeof(leak));
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_KEYSTORE_FLASH;
    call.call_type = WT_SPM_KS_FLASH_READ;
    call.vec_idx = 0u;
    call.num_bytes = (uint32_t)sizeof(leak);
    call.buffer = leak;
    if (wt_arch_sp_trap(&call) != WT_FFM_SUCCESS || call.ret_int != WH_ERROR_OK) {
        ok = 0;
    }
    else if (memcmp(leak, ref, sizeof(ref)) != 0) {
        ok = 0;
    }

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_KEYSTORE_FLASH;
    call.call_type = WT_SPM_KS_FLASH_VERIFY;
    call.vec_idx = 0u;
    call.num_bytes = (uint32_t)sizeof(ref);
    call.buffer = ref;
    if (wt_arch_sp_trap(&call) != WT_FFM_SUCCESS || call.ret_int != WH_ERROR_OK) {
        ok = 0;
    }

    /* Restore the full context for the vault's real operations. */
    g_hsm_flash_ctx.base = g_hsm_flash_cfg.base;
    g_hsm_flash_ctx.size = g_hsm_flash_cfg.size;
    g_hsm_flash_ctx.sector_size = g_hsm_flash_cfg.sector_size;
    g_hsm_flash_ctx.program_unit = g_hsm_flash_cfg.program_unit;
    return ok;
}
#endif
