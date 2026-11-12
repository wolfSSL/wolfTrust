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

/* Host suite for port/stm32l562/hsm_flash.c and the wolfHSM store over a
 * model of the dual-bank L5 flash controller, its write-1-to-clear status and
 * ECC double errors raised both as the NMI and in ECCR. */

#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_flash.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/services/fwu_service.h"

#define FLASH_SIZE   WT_FLASH_SIZE
#define BANK         WT_FLASH_BANK_SIZE
#define PAGE         WT_FLASH_PAGE_SIZE
#define SECTOR       WT_FLASH_SECTOR_SIZE
#define PAGES        (FLASH_SIZE / PAGE)
#define HOST_S       ((uintptr_t)g_l5_flash)
#define NVM_OFF      ((uint32_t)(WT_MOCK_REAL_NVM_S - WT_FLASH_S_ALIAS_BASE))
#define CONF_OFF     ((uint32_t)(WT_MOCK_REAL_CONF_S - WT_FLASH_S_ALIAS_BASE))
#define FWU_OFF      ((uint32_t)(WT_MOCK_REAL_FWU_S - WT_FLASH_S_ALIAS_BASE))
#define NVM_SIZE     WT_HSM_NVM_FLASH_SIZE
#define FWU_SIZE     WT_FWU_UPDATE_FLASH_SIZE
#define BUSY_POLLS   3u

/* Reserved bits the model keeps set in SECSR and ECCR, so a
 * write-1-to-clear store never looks like a read of the same value. */
#define SR_TAG       (1u << 30)
#define ECCR_TAG     (1u << 26)

#define SR_ERRS      (WT_FLASH_SR_OPERR | WT_FLASH_SR_PROGERR | \
                      WT_FLASH_SR_WRPERR | WT_FLASH_SR_PGAERR | \
                      WT_FLASH_SR_SIZERR | WT_FLASH_SR_PGSERR)
#define ECCR_ECCIE   (1u << 24)
#define ECCR_ECCC2   (1u << 28)
#define ECCR_ECCD2   (1u << 29)
#define ECCR_ECCC    (1u << 30)

extern const wt_fwu_backend_t wt_fwu_flash_backend;
extern volatile uint32_t g_wt_flash_prog_calls;
extern volatile uint32_t g_wt_flash_erase_calls;
extern volatile uint32_t g_wt_flash_first_err;
extern volatile uint32_t g_wt_flash_first_err_off;
extern volatile uint32_t g_wt_flash_first_err_sr;
void NMI_Handler(void);

enum { R_KEYR, R_SR, R_CR, R_ECCR, R_OPTR, R_ICR, R_ISR, R_COUNT };

static const uintptr_t g_reg_addr[R_COUNT] = {
    (uintptr_t)WT_FLASH_BASE_S + 0x0Cu,
    (uintptr_t)WT_FLASH_BASE_S + 0x24u,
    (uintptr_t)WT_FLASH_BASE_S + 0x2Cu,
    (uintptr_t)WT_FLASH_BASE_S + 0x30u,
    (uintptr_t)WT_FLASH_BASE_S + 0x40u,
    (uintptr_t)0x50030400u,
    (uintptr_t)0x50030404u,
};

/* Controller state. A register access hands the driver a cell; whatever it
 * stored there is applied on the next access, before anything is read. */
static volatile uint32_t g_cell[R_COUNT];
static uint32_t g_shown[R_COUNT];
static volatile uint32_t g_scratch;
static uint32_t g_cr;
static uint32_t g_sr;
static uint32_t g_eccr;
static uint32_t g_optr;
static uint32_t g_icr;
static uint32_t g_busy;
static uint32_t g_icache_busy;
static int g_key_stage;
static int g_key_fault;

uint8_t g_l5_flash[FLASH_SIZE];
static uint8_t *const g_mem = g_l5_flash;
static uint8_t g_shadow[FLASH_SIZE];
static uint32_t g_page_erases[PAGES];

/* Model counters and knobs. */
static uint32_t g_key_writes;
static uint32_t g_unlocks;
static uint32_t g_programs;
static uint32_t g_prog_errors;
/* RM0438 lets an all-zero program land on a written double-word */
static uint32_t g_zero_reprograms;
static uint32_t g_ecc_flag = WT_FLASH_ECCR_ECCD;
static void ecc_latch(uint32_t flag, uint32_t bank, uint32_t bank_off);
static uint32_t g_erases;
static uint32_t g_last_pnb;
static uint32_t g_last_bker;
static uint32_t g_locked_cr_writes;
static uint32_t g_ro_writes;
static uint32_t g_unknown_regs;
static uint32_t g_icache_invalidates;
static uint32_t g_wrp_lo = 1u;
static uint32_t g_wrp_hi;
static int g_fail_program;
static int g_ecc_after_read;
static int g_ecc_raise;

/* Host stand-ins for the driver's Cortex-M asm. */
static uint32_t g_primask;
static uint32_t g_cpsid_calls;
static uint32_t g_barriers;
static uint32_t g_nmi_primask;
static uint32_t g_nmis;
static int g_wfi_armed;
static sigjmp_buf g_wfi_jmp;

/* One host page of the flash made unreadable; the first read of it raises
 * the ECC NMI for that double-word. */
/* The first checked read inside [lo, hi) raises the ECC NMI */
static uint32_t g_guard_lo;
static uint32_t g_guard_hi;
static int g_guard_armed;

/* Privilege and the SVC gate. */
static int g_unpriv;
static int g_gate_calls;
static int g_gate_reject;
static wt_spm_call_t g_gate_last;

static int g_checks;
static int g_failures;

static void check(int cond, const char *name)
{
    g_checks++;
    if (cond) {
        printf("PASS: %s\n", name);
    }
    else {
        printf("FAIL: %s\n", name);
        g_failures++;
    }
}

static uint32_t readable(int r)
{
    switch (r) {
        case R_SR:
            return g_sr | (g_busy != 0u ? WT_FLASH_SR_BSY : 0u) | SR_TAG;
        case R_CR:
            return g_cr;
        case R_ECCR:
            return g_eccr | ECCR_TAG;
        case R_OPTR:
            return g_optr;
        case R_ICR:
            return g_icr;
        case R_ISR:
            return g_icache_busy != 0u ? WT_ICACHE_SR_BUSYF : 0u;
        default:
            return 0u;
    }
}

static int wrp_page(uint32_t off)
{
    return off >= g_wrp_lo && off < g_wrp_hi;
}

static int swap_banks(void)
{
    return (g_optr & WT_FLASH_OPTR_SWAP_BANK) != 0u;
}

static void erase_start(uint32_t cr)
{
    uint32_t pnb = (cr >> WT_FLASH_CR_PNB_SHIFT) & WT_FLASH_CR_PNB_MASK;
    uint32_t bker = (cr & WT_FLASH_CR_BKER) != 0u ? 1u : 0u;
    uint32_t half = bker ^ (swap_banks() ? 1u : 0u);
    uint32_t off = half * BANK + pnb * PAGE;

    if ((cr & WT_FLASH_CR_PER) == 0u || (cr & WT_FLASH_CR_PG) != 0u) {
        g_sr |= WT_FLASH_SR_PGSERR;
        return;
    }
    g_erases++;
    g_last_pnb = pnb;
    g_last_bker = bker;
    if (wrp_page(off)) {
        g_sr |= WT_FLASH_SR_WRPERR;
        return;
    }
    (void)memset(g_mem + off, 0xFF, PAGE);
    (void)memset(g_shadow + off, 0xFF, PAGE);
    g_page_erases[off / PAGE]++;
    g_sr |= WT_FLASH_SR_EOP;
    g_busy = BUSY_POLLS;
}

static void apply_write(int r, uint32_t v)
{
    switch (r) {
        case R_KEYR:
            g_key_writes++;
            if (g_key_fault != 0) {
                break;
            }
            if (g_key_stage == 0 && v == WT_FLASH_KEY1) {
                g_key_stage = 1;
            }
            else if (g_key_stage == 1 && v == WT_FLASH_KEY2) {
                g_key_stage = 0;
                if ((g_cr & WT_FLASH_CR_LOCK) != 0u) {
                    g_cr &= ~WT_FLASH_CR_LOCK;
                    g_unlocks++;
                }
            }
            else {
                /* A wrong key locks the controller until reset. */
                g_key_fault = 1;
            }
            break;
        case R_CR:
            if ((g_cr & WT_FLASH_CR_LOCK) != 0u) {
                g_locked_cr_writes++;
                break;
            }
            g_cr = v & ~WT_FLASH_CR_STRT;
            if ((v & WT_FLASH_CR_LOCK) != 0u) {
                g_key_stage = 0;
            }
            else if ((v & WT_FLASH_CR_STRT) != 0u) {
                erase_start(v);
            }
            break;
        case R_SR:
            g_sr &= ~(v & (SR_ERRS | WT_FLASH_SR_EOP));
            break;
        case R_ECCR:
            g_eccr = (g_eccr & ~ECCR_ECCIE) | (v & ECCR_ECCIE);
            if ((v & WT_FLASH_ECCR_ECCD) != 0u && g_ecc_after_read != 0) {
                g_ecc_after_read = 0;
                g_ecc_raise = 1;
            }
            g_eccr &= ~(v & (WT_FLASH_ECCR_ECCD | ECCR_ECCD2 | ECCR_ECCC |
                             ECCR_ECCC2));
            break;
        case R_ICR:
            g_icr = v & ~WT_ICACHE_CR_CACHEINV;
            if ((v & WT_ICACHE_CR_CACHEINV) != 0u) {
                g_icache_invalidates++;
                g_icache_busy = 2u;
            }
            break;
        default:
            g_ro_writes++;
            break;
    }
}

static int dword_is(const uint8_t *p, uint8_t value)
{
    uint32_t i;

    for (i = 0u; i < 8u; i++) {
        if (p[i] != value) {
            return 0;
        }
    }
    return 1;
}

/* Program every double-word the driver stored since the last scan. */
static void scan_range(uint32_t lo, uint32_t hi)
{
    uint32_t off;
    uint32_t err;

    if (hi <= lo || memcmp(g_mem + lo, g_shadow + lo, hi - lo) == 0) {
        return;
    }
    for (off = lo; off < hi; off += 8u) {
        if (memcmp(g_mem + off, g_shadow + off, 8u) == 0) {
            continue;
        }
        err = 0u;
        if ((g_cr & WT_FLASH_CR_LOCK) != 0u ||
                (g_cr & WT_FLASH_CR_PG) == 0u) {
            err = WT_FLASH_SR_PGSERR;
        }
        else if (wrp_page(off)) {
            err = WT_FLASH_SR_WRPERR;
        }
        else if (g_fail_program != 0) {
            g_fail_program = 0;
            err = WT_FLASH_SR_PROGERR;
        }
        else if (!dword_is(g_shadow + off, 0xFFu) &&
                 !dword_is(g_mem + off, 0x00u)) {
            err = WT_FLASH_SR_PROGERR;
        }
        else if (!dword_is(g_shadow + off, 0xFFu)) {
            g_zero_reprograms++;
        }
        if (err != 0u) {
            (void)memcpy(g_mem + off, g_shadow + off, 8u);
            g_sr |= err;
            g_prog_errors++;
        }
        else {
            (void)memcpy(g_shadow + off, g_mem + off, 8u);
            g_programs++;
            g_sr |= WT_FLASH_SR_EOP;
            g_busy = BUSY_POLLS;
        }
    }
}

static void scan_flash(void)
{
    scan_range(0u, FLASH_SIZE);
}

static void model_commit(void)
{
    int r;

    for (r = 0; r < R_COUNT; r++) {
        if (g_cell[r] != g_shown[r]) {
            apply_write(r, g_cell[r]);
        }
    }
}

static void model_refresh(void)
{
    int r;

    for (r = 0; r < R_COUNT; r++) {
        g_shown[r] = readable(r);
        g_cell[r] = g_shown[r];
    }
}

volatile uint32_t* wt_mock_reg(uintptr_t address)
{
    int r;

    for (r = 0; r < R_COUNT; r++) {
        if (g_reg_addr[r] == address) {
            break;
        }
    }
    if (r == R_COUNT) {
        g_unknown_regs++;
        return &g_scratch;
    }
    model_commit();
    if (r == R_SR || r == R_CR) {
        scan_flash();
    }
    if (r == R_ECCR && g_ecc_raise != 0) {
        g_ecc_raise = 0;
        ecc_latch(g_ecc_flag, 0u, NVM_OFF);
    }
    model_refresh();
    if (r == R_SR && g_busy != 0u) {
        g_busy--;
    }
    if (r == R_ISR && g_icache_busy != 0u) {
        g_icache_busy--;
    }
    return &g_cell[r];
}

void wt_host_barrier(void)
{
    g_barriers++;
}

uint32_t wt_host_irq_save(void)
{
    return g_primask;
}

void wt_host_cpsid(void)
{
    g_cpsid_calls++;
    g_primask = 1u;
}

void wt_host_irq_restore(uint32_t primask)
{
    g_primask = primask;
}

void wt_host_wfi(void)
{
    if (g_wfi_armed != 0) {
        g_wfi_armed = 0;
        siglongjmp(g_wfi_jmp, 1);
    }
    (void)fprintf(stderr, "the ECC NMI halted outside an armed check\n");
    abort();
}

static void model_reset(void)
{
    (void)memset(g_mem, 0xFF, FLASH_SIZE);
    (void)memset(g_shadow, 0xFF, FLASH_SIZE);
    (void)memset(g_page_erases, 0, sizeof(g_page_erases));
    g_cr = WT_FLASH_CR_LOCK;
    g_sr = 0u;
    g_eccr = 0u;
    g_optr = 0u;
    g_icr = 0u;
    g_busy = 0u;
    g_icache_busy = 0u;
    g_key_stage = 0;
    g_key_fault = 0;
    g_key_writes = 0u;
    g_unlocks = 0u;
    g_programs = 0u;
    g_prog_errors = 0u;
    g_zero_reprograms = 0u;
    g_ecc_flag = WT_FLASH_ECCR_ECCD;
    g_erases = 0u;
    g_locked_cr_writes = 0u;
    g_ro_writes = 0u;
    g_unknown_regs = 0u;
    g_icache_invalidates = 0u;
    g_wrp_lo = 1u;
    g_wrp_hi = 0u;
    g_fail_program = 0;
    g_ecc_after_read = 0;
    g_ecc_raise = 0;
    g_primask = 0u;
    g_cpsid_calls = 0u;
    g_nmis = 0u;
    g_wt_flash_first_err = 0u;
    g_wt_flash_first_err_off = 0u;
    g_wt_flash_first_err_sr = 0u;
    model_refresh();
}

/* Applies the driver's last store, as the next access would. */
static void model_settle(void)
{
    model_commit();
    scan_flash();
    model_refresh();
}

static int clean_model(void)
{
    model_settle();
    return g_prog_errors == 0u && g_zero_reprograms == 0u &&
           (g_sr & SR_ERRS) == 0u &&
           g_key_fault == 0 && g_locked_cr_writes == 0u &&
           g_ro_writes == 0u && g_unknown_regs == 0u;
}

static int controller_idle(void)
{
    model_settle();
    return (g_cr & WT_FLASH_CR_LOCK) != 0u &&
           (g_cr & (WT_FLASH_CR_PG | WT_FLASH_CR_PER)) == 0u;
}

/* ADDR_ECC and BK_ECC only take a new error once ECCC and ECCD are clear */
static void ecc_latch(uint32_t flag, uint32_t bank, uint32_t bank_off)
{
    if ((g_eccr & (ECCR_ECCC | WT_FLASH_ECCR_ECCD)) == 0u) {
        g_eccr &= ~(WT_FLASH_ECCR_BK | WT_FLASH_ECCR_ADDR_MASK);
        g_eccr |= (bank != 0u ? WT_FLASH_ECCR_BK : 0u) |
                  (bank_off & ~7u & WT_FLASH_ECCR_ADDR_MASK);
    }
    g_eccr |= flag;
}

/* The double error the controller raises as an NMI on the faulting read */
static void raise_ecc_nmi(uint32_t off)
{
    uint32_t bank = (off >= BANK ? 1u : 0u) ^ (swap_banks() ? 1u : 0u);

    model_commit();
    ecc_latch(g_ecc_flag, bank, off % BANK);
    model_refresh();
    g_nmi_primask = g_primask;
    g_nmis++;
    NMI_Handler();
}

uint8_t wt_host_flash_read8(const volatile uint8_t *p)
{
    uintptr_t addr = (uintptr_t)p;

    if (g_guard_armed != 0 && addr >= HOST_S + g_guard_lo &&
            addr < HOST_S + g_guard_hi) {
        g_guard_armed = 0;
        raise_ecc_nmi((uint32_t)(addr - HOST_S));
    }
    return *p;
}

static void guard(uint32_t off)
{
    g_guard_lo = off & ~0xFFFu;
    g_guard_hi = g_guard_lo + 0x1000u;
    g_guard_armed = 1;
}

/* SVC dispatcher stand-in: re-enters the flash callback with privilege. */
int wt_arch_thread_unprivileged(void)
{
    return g_unpriv;
}

int wt_spm_sp_call(struct wt_spm_call *call)
{
    void *ctx = wt_hsm_flash_context();
    uint32_t off;
    uint32_t len;
    int ret;

    g_gate_calls++;
    g_gate_last = *call;
    if (call->op != WT_SPM_OP_KEYSTORE_FLASH) {
        return -1;
    }
    if (g_gate_reject != 0) {
        return g_gate_reject;
    }
    off = call->vec_idx;
    len = (uint32_t)call->num_bytes;
    g_unpriv = 0;
    switch (call->call_type) {
        case WT_SPM_KS_FLASH_READ:
            ret = g_wt_hsm_flash_cb.Read(ctx, off, len, call->buffer);
            break;
        case WT_SPM_KS_FLASH_PROGRAM:
            ret = g_wt_hsm_flash_cb.Program(ctx, off, len, call->buffer);
            break;
        case WT_SPM_KS_FLASH_ERASE:
            ret = g_wt_hsm_flash_cb.Erase(ctx, off, len);
            break;
        case WT_SPM_KS_FLASH_VERIFY:
            ret = g_wt_hsm_flash_cb.Verify(ctx, off, len, call->buffer);
            break;
        case WT_SPM_KS_FLASH_BLANKCHECK:
            ret = g_wt_hsm_flash_cb.BlankCheck(ctx, off, len);
            break;
        case WT_SPM_KS_FLASH_CLEANUP:
            ret = g_wt_hsm_flash_cb.Cleanup(ctx);
            break;
        default:
            ret = WH_ERROR_BADARGS;
            break;
    }
    g_unpriv = 1;
    call->ret_int = ret;
    return WT_FFM_SUCCESS;
}

int wt_fwu_wolfboot_arm_trailer(uint8_t *block, uint32_t len)
{
    if (block == NULL || len < 5u) {
        return -1;
    }
    (void)memset(block, 0xFF, len);
    block[len - 5u] = (uint8_t)WT_WOLFBOOT_IMG_STATE_UPDATING;
    block[len - 4u] = (uint8_t)(WT_WOLFBOOT_MAGIC_TRAIL & 0xFFu);
    block[len - 3u] = (uint8_t)((WT_WOLFBOOT_MAGIC_TRAIL >> 8) & 0xFFu);
    block[len - 2u] = (uint8_t)((WT_WOLFBOOT_MAGIC_TRAIL >> 16) & 0xFFu);
    block[len - 1u] = (uint8_t)((WT_WOLFBOOT_MAGIC_TRAIL >> 24) & 0xFFu);
    return 0;
}

int wt_fwu_staged_extent_ok(uint32_t staged_size, uint32_t programmed_end,
                            uint32_t align)
{
    return align != 0u && staged_size <= programmed_end &&
           programmed_end - staged_size < align;
}

static void fill(uint8_t *out, uint32_t len, uint32_t seed)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        out[i] = (uint8_t)(seed * 29u + i * 7u + 3u);
    }
}

static int all_ff(uint32_t off, uint32_t len)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        if (g_mem[off + i] != 0xFFu) {
            return 0;
        }
    }
    return 1;
}

static int vault_init(void)
{
    return g_wt_hsm_flash_cb.Init(wt_hsm_flash_context(),
                                  wt_hsm_flash_config());
}

static void test_geometry(void)
{
    const wt_hsm_flash_config_t *cfg =
        (const wt_hsm_flash_config_t *)wt_hsm_flash_config();
    wt_hsm_flash_context_t forged;
    wt_hsm_flash_config_t bad;
    uint8_t buf[16];

    model_reset();
    check(cfg->base == HOST_S + NVM_OFF && cfg->size == NVM_SIZE &&
          cfg->sector_size == SECTOR && cfg->program_unit == 8u,
          "the vault store is 16 KiB of 8 KiB sectors, 8-byte units, at "
          "0x0C038000");
    check(NVM_OFF % PAGE == 0u && NVM_OFF + NVM_SIZE <= BANK &&
          CONF_OFF == NVM_OFF + NVM_SIZE,
          "the vault and conformance NVM share the top of bank 1");
    check(FWU_OFF == BANK && FWU_SIZE % SECTOR == 0u,
          "the update slot starts bank 2");
    check(vault_init() == WH_ERROR_OK, "the vault context initialises");
    check(g_wt_hsm_flash_cb.PartitionSize(wt_hsm_flash_context()) == SECTOR,
          "a wolfHSM partition is one 8 KiB sector");

    (void)memset(&forged, 0, sizeof(forged));
    forged.base = cfg->base;
    forged.size = cfg->size;
    forged.sector_size = cfg->sector_size;
    forged.program_unit = cfg->program_unit;
    check(g_wt_hsm_flash_cb.Read(&forged, 0u, sizeof(buf), buf) ==
          WH_ERROR_BADARGS &&
          g_wt_hsm_flash_cb.Erase(&forged, 0u, SECTOR) == WH_ERROR_BADARGS &&
          g_wt_hsm_flash_cb.PartitionSize(&forged) == 0u,
          "a context the driver does not own is refused");

    bad = *cfg;
    bad.program_unit = 0u;
    check(g_wt_hsm_flash_cb.Init(&forged, &bad) == WH_ERROR_BADARGS,
          "init refuses a zero program unit");
    bad = *cfg;
    bad.size = SECTOR + PAGE;
    check(g_wt_hsm_flash_cb.Init(&forged, &bad) == WH_ERROR_BADARGS,
          "init refuses a size that is not whole sectors");
    bad = *cfg;
    bad.sector_size = 12u;
    check(g_wt_hsm_flash_cb.Init(&forged, &bad) == WH_ERROR_BADARGS,
          "init refuses a sector that is not whole program units");
    check(g_ro_writes == 0u && g_unknown_regs == 0u,
          "no access touched a read-only or unmodelled register");
}

static void test_program(void)
{
    void *ctx = wt_hsm_flash_context();
    uint8_t data[64];
    uint8_t back[64];
    uint32_t calls;
    uint32_t masks;

    model_reset();
    g_icr = WT_ICACHE_CR_EN;
    model_refresh();
    (void)vault_init();
    fill(data, sizeof(data), 1u);
    calls = g_wt_flash_prog_calls;
    masks = g_cpsid_calls;
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, sizeof(data), data) ==
          WH_ERROR_OK, "a 64-byte program succeeds");
    check(g_wt_flash_prog_calls == calls + 1u, "the program is counted");
    check(g_cpsid_calls == masks + 8u && g_primask == 0u,
          "each double-word program ran with interrupts masked");
    check(g_key_writes == 2u && g_unlocks == 1u && g_key_fault == 0,
          "SECKEYR took KEY1 then KEY2 once");
    check(g_programs == 8u, "eight 64-bit double-words were programmed");
    check(memcmp(g_mem + NVM_OFF, data, sizeof(data)) == 0,
          "the bytes landed at the vault base");
    check(controller_idle(), "PG is cleared and the controller relocked");
    check(clean_model(), "no sequence, program or key error was raised");
    check(g_icache_invalidates == 1u,
          "the enabled instruction cache was invalidated once");

    (void)memset(back, 0, sizeof(back));
    calls = g_cpsid_calls;
    check(g_wt_hsm_flash_cb.Read(ctx, 0u, sizeof(back), back) ==
          WH_ERROR_OK && memcmp(back, data, sizeof(back)) == 0,
          "the read returns what was programmed");
    check(g_cpsid_calls == calls + 1u && g_primask == 0u,
          "the read masked interrupts and restored PRIMASK");
    check(g_wt_hsm_flash_cb.Verify(ctx, 0u, sizeof(data), data) ==
          WH_ERROR_OK, "verify matches the programmed bytes");
    data[40] ^= 0x01u;
    check(g_wt_hsm_flash_cb.Verify(ctx, 0u, sizeof(data), data) ==
          WH_ERROR_NOTVERIFIED, "verify reports a one-bit difference");
    check(g_wt_hsm_flash_cb.BlankCheck(ctx, 0u, 64u) == WH_ERROR_NOTBLANK,
          "blank check sees the programmed words");
    check(g_wt_hsm_flash_cb.BlankCheck(ctx, 64u, SECTOR - 64u) ==
          WH_ERROR_OK, "blank check passes the rest of the sector");

    fill(data, sizeof(data), 2u);
    check(g_wt_hsm_flash_cb.Program(ctx, 64u, 8u, data) == WH_ERROR_OK &&
          g_programs == 9u, "a single double-word program succeeds");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 0u, NULL) == WH_ERROR_OK,
          "an empty program is accepted without data");
}

static void test_program_rules(void)
{
    void *ctx = wt_hsm_flash_context();
    uint8_t data[32];
    uint32_t erases;

    model_reset();
    (void)vault_init();
    fill(data, sizeof(data), 3u);
    check(g_wt_hsm_flash_cb.Program(ctx, 4u, 8u, data) == WH_ERROR_BADARGS,
          "an offset off the 8-byte unit is refused");
    check((g_wt_flash_first_err >> 24) == 0x02u &&
          g_wt_flash_first_err_off == 4u,
          "the alignment refusal is latched with its offset");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 12u, data) == WH_ERROR_BADARGS,
          "a length off the 8-byte unit is refused");
    check(g_wt_hsm_flash_cb.Program(ctx, NVM_SIZE - 8u, 16u, data) ==
          WH_ERROR_BADARGS, "a program past the store is refused");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 8u, NULL) == WH_ERROR_BADARGS,
          "a program without data is refused");
    check(all_ff(NVM_OFF, NVM_SIZE + WT_CONF_NVM_FLASH_SIZE) &&
          g_unlocks == 0u, "no refused program unlocked or wrote flash");
    check(g_wt_hsm_flash_cb.Program(ctx, NVM_SIZE, 0u, data) ==
          WH_ERROR_OK && controller_idle(),
          "an empty program at the end is in range");

    check(g_wt_hsm_flash_cb.WriteLock(ctx, 0u, NVM_SIZE) == WH_ERROR_OK,
          "the store write-locks");
    erases = g_erases;
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 8u, data) == WH_ERROR_LOCKED &&
          g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_LOCKED,
          "a write-locked store refuses program and erase");
    check(g_erases == erases && all_ff(NVM_OFF, 8u),
          "the locked store was not touched");
    check(g_wt_hsm_flash_cb.WriteUnlock(ctx, 0u, NVM_SIZE) == WH_ERROR_OK &&
          g_wt_hsm_flash_cb.Program(ctx, 0u, 8u, data) == WH_ERROR_OK,
          "the store programs again once unlocked");

    /* The double-word is no longer erased, so the controller refuses it. */
    g_wt_flash_first_err = 0u;
    fill(data, sizeof(data), 4u);
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 8u, data) == WH_ERROR_ABORTED,
          "a program over a written double-word aborts on PROGERR");
    check((g_wt_flash_first_err >> 24) == 0x04u &&
          (g_wt_flash_first_err_sr & WT_FLASH_SR_PROGERR) != 0u,
          "the first error latches the program step and its SECSR bits");
    model_settle();
    check((g_sr & SR_ERRS) == 0u,
          "the driver cleared PROGERR with a write-1-to-clear store");
    check(controller_idle(), "the failed program relocked the controller");

    /* Silicon accepts an all-zero program over a written double-word. */
    (void)memset(data, 0, sizeof(data));
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, 8u, data) == WH_ERROR_OK &&
          g_zero_reprograms == 1u && dword_is(g_mem + NVM_OFF, 0u),
          "an all-zero reprogram lands and the model counts it");
    check(!clean_model(), "a counted zero reprogram fails the clean check");
    g_zero_reprograms = 0u;

    g_fail_program = 1;
    check(g_wt_hsm_flash_cb.Program(ctx, 16u, 16u, data) == WH_ERROR_ABORTED,
          "a program the controller fails mid-run aborts");
    check(all_ff(NVM_OFF + 16u, 16u),
          "nothing after the failed double-word was programmed");

    g_wrp_lo = NVM_OFF;
    g_wrp_hi = NVM_OFF + PAGE;
    check(g_wt_hsm_flash_cb.Program(ctx, 32u, 8u, data) == WH_ERROR_ABORTED,
          "a program into a WRP page aborts on WRPERR");
    model_settle();
    check((g_sr & SR_ERRS) == 0u && g_key_fault == 0,
          "the WRPERR was cleared and the keys stayed valid");
}

static void test_erase(void)
{
    void *ctx = wt_hsm_flash_context();
    uint8_t data[16];
    uint32_t first = NVM_OFF / PAGE;
    uint32_t p;
    int only;

    model_reset();
    (void)vault_init();
    fill(data, sizeof(data), 5u);
    (void)memset(g_mem + NVM_OFF - PAGE, 0x11, PAGE);
    (void)memset(g_shadow + NVM_OFF - PAGE, 0x11, PAGE);
    (void)memset(g_mem + NVM_OFF, 0x22, NVM_SIZE);
    (void)memset(g_shadow + NVM_OFF, 0x22, NVM_SIZE);
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, PAGE) == WH_ERROR_BADARGS &&
          g_wt_hsm_flash_cb.Erase(ctx, PAGE, SECTOR) == WH_ERROR_BADARGS,
          "an erase off the 8 KiB sector is refused");
    check(g_wt_hsm_flash_cb.Erase(ctx, SECTOR, 2u * SECTOR) ==
          WH_ERROR_BADARGS, "an erase past the store is refused");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, 0u) == WH_ERROR_OK &&
          g_erases == 0u, "an empty erase touches nothing");

    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK,
          "the first vault sector erases");
    check(g_erases == SECTOR / PAGE && g_last_bker == 0u &&
          g_last_pnb == first + SECTOR / PAGE - 1u,
          "four bank-1 page erases ending at PNB 115");
    only = 1;
    for (p = 0u; p < PAGES; p++) {
        if ((p >= first && p < first + SECTOR / PAGE) !=
                (g_page_erases[p] == 1u)) {
            only = 0;
        }
    }
    check(only, "exactly pages 112 to 115 were erased");
    check(all_ff(NVM_OFF, SECTOR) && g_mem[NVM_OFF - 1u] == 0x11u &&
          g_mem[NVM_OFF + SECTOR] == 0x22u,
          "the neighbouring pages kept their data");
    check(controller_idle() && clean_model(),
          "PER is cleared and the controller relocked");

    check(wt_hsm_flash_format() == 0, "format erases the whole store");
    check(all_ff(NVM_OFF, NVM_SIZE) &&
          g_page_erases[first + NVM_SIZE / PAGE - 1u] == 1u &&
          g_mem[NVM_OFF - 1u] == 0x11u,
          "format erased the store's eight pages and nothing below them");

    /* With the banks swapped, bank 1 answers at the upper half. */
    model_reset();
    (void)vault_init();
    g_optr = WT_FLASH_OPTR_SWAP_BANK;
    model_refresh();
    (void)memset(g_mem + NVM_OFF, 0x33, SECTOR);
    (void)memset(g_shadow + NVM_OFF, 0x33, SECTOR);
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK &&
          g_last_bker == 1u && g_last_pnb == first + SECTOR / PAGE - 1u,
          "under SWAP_BANK the vault pages erase with BKER set");
    check(all_ff(NVM_OFF, SECTOR) &&
          g_page_erases[(BANK + NVM_OFF) / PAGE] == 0u,
          "the swapped erase hit the mapped pages, not their twins");
    check(g_wt_hsm_flash_cb.Program(ctx, 0u, sizeof(data), data) ==
          WH_ERROR_OK && memcmp(g_mem + NVM_OFF, data, sizeof(data)) == 0,
          "the swapped store programs");

    model_reset();
    (void)vault_init();
    g_wrp_lo = NVM_OFF + PAGE;
    g_wrp_hi = NVM_OFF + 2u * PAGE;
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_ABORTED,
          "an erase reaching a WRP page aborts");
    check((g_wt_flash_first_err >> 24) == 0x05u &&
          g_wt_flash_first_err_off == PAGE &&
          (g_wt_flash_first_err_sr & WT_FLASH_SR_WRPERR) != 0u,
          "the erase failure latches its page offset and WRPERR");
    check(g_erases == 2u, "the erase stopped at the protected page");
    check(controller_idle() && (g_sr & SR_ERRS) == 0u,
          "the error was cleared and the controller relocked");
}

static void test_ecc(void)
{
    void *ctx = wt_hsm_flash_context();
    uint8_t data[32];
    uint8_t back[32];
    volatile int halted = 0;

    model_reset();
    (void)vault_init();
    fill(data, sizeof(data), 6u);
    (void)g_wt_hsm_flash_cb.Program(ctx, 0u, sizeof(data), data);

    model_settle();
    g_ecc_after_read = 1;
    (void)memset(back, 0x5A, sizeof(back));
    check(g_wt_hsm_flash_cb.Read(ctx, 0u, sizeof(back), back) ==
          WH_ERROR_ABORTED, "an ECCD left in ECCR after a read aborts it");
    check(dword_is(back, 0u) && dword_is(back + 24, 0u),
          "the aborted read returned no flash bytes");
    model_settle();
    check((g_eccr & WT_FLASH_ECCR_ECCD) == 0u,
          "ECCD was cleared write-1-to-clear");
    model_settle();
    g_ecc_after_read = 1;
    check(g_wt_hsm_flash_cb.Verify(ctx, 0u, sizeof(data), data) ==
          WH_ERROR_ABORTED, "verify aborts on an ECC double error");
    model_settle();
    g_ecc_after_read = 1;
    check(g_wt_hsm_flash_cb.BlankCheck(ctx, SECTOR, 16u) ==
          WH_ERROR_ABORTED, "blank check aborts on an ECC double error");
    check(g_wt_hsm_flash_cb.Read(ctx, 0u, sizeof(back), back) ==
          WH_ERROR_OK && memcmp(back, data, sizeof(back)) == 0,
          "the next clean read succeeds");

    /* A correction left by an earlier read is cleared before the next one. */
    model_commit();
    g_eccr = ECCR_ECCC | 0x100u;
    model_refresh();
    check(g_wt_hsm_flash_cb.Read(ctx, 0u, sizeof(back), back) ==
          WH_ERROR_OK && (g_eccr & ECCR_ECCC) == 0u,
          "a checked read clears a stale ECCC");

    /* A double error no checked read is waiting for halts the core. */
    model_commit();
    g_eccr |= WT_FLASH_ECCR_ECCD | (NVM_OFF & WT_FLASH_ECCR_ADDR_MASK);
    model_refresh();
    halted = 0;
    g_wfi_armed = 1;
    if (sigsetjmp(g_wfi_jmp, 1) == 0) {
        NMI_Handler();
    }
    else {
        halted = 1;
    }
    g_wfi_armed = 0;
    check(halted == 1, "an ECC NMI outside a checked read halts");
    model_commit();
    g_eccr = 0u;
    model_refresh();
}

/* The double error raised as the NMI while the read is in flight: the
 * driver's read hook plays the NMI on the first read of the armed range. */
static void test_ecc_nmi(void)
{
    void *ctx = wt_hsm_flash_context();
    uint8_t back[32];
    volatile int halted = 0;

    guard(NVM_OFF);
    g_wfi_armed = 1;
    if (sigsetjmp(g_wfi_jmp, 1) == 0) {
        (void)memset(back, 0x5A, sizeof(back));
        check(g_wt_hsm_flash_cb.Read(ctx, 0u, sizeof(back), back) ==
              WH_ERROR_ABORTED,
              "an ECC NMI inside the read window aborts the read");
    }
    else {
        halted = 1;
    }
    g_wfi_armed = 0;
    check(halted == 0 && g_nmis == 1u,
          "the NMI handler claimed the in-window double error");
    check(g_nmi_primask == 1u, "the read ran with interrupts masked");
    check(dword_is(back, 0u), "the NMI-aborted read returned no flash bytes");
    model_settle();
    check((g_eccr & WT_FLASH_ECCR_ECCD) == 0u && g_primask == 0u,
          "ECCD was cleared and PRIMASK restored");

    /* The same error with the banks swapped reports the other bank. */
    g_optr = WT_FLASH_OPTR_SWAP_BANK;
    model_refresh();
    guard(NVM_OFF);
    halted = 0;
    g_wfi_armed = 1;
    if (sigsetjmp(g_wfi_jmp, 1) == 0) {
        check(g_wt_hsm_flash_cb.Read(ctx, 0u, sizeof(back), back) ==
              WH_ERROR_ABORTED,
              "under SWAP_BANK the NMI still matches the read window");
    }
    else {
        halted = 1;
    }
    g_wfi_armed = 0;
    check(halted == 0, "the swapped bank number was not mistaken for "
          "another bank");

    /* A stale correction elsewhere must not freeze the error's address, or
     * the in-window double error would look foreign and halt the core. */
    g_optr = 0u;
    model_settle();
    g_eccr = ECCR_ECCC | WT_FLASH_ECCR_BK | 0x100u;
    model_refresh();
    guard(NVM_OFF);
    halted = 0;
    g_wfi_armed = 1;
    if (sigsetjmp(g_wfi_jmp, 1) == 0) {
        check(g_wt_hsm_flash_cb.Read(ctx, 0u, sizeof(back), back) ==
              WH_ERROR_ABORTED,
              "a double error after a stale ECCC aborts the read");
    }
    else {
        halted = 1;
    }
    g_wfi_armed = 0;
    check(halted == 0, "the stale ECCC did not hide the in-window error");
    model_commit();
    g_eccr = 0u;
    model_refresh();
}

static void test_gate(void)
{
    void *ctx = wt_hsm_flash_context();
    uint8_t data[16];
    uint8_t back[16];
    wt_hsm_flash_context_t other;

    model_reset();
    (void)vault_init();
    fill(data, sizeof(data), 7u);
    g_gate_calls = 0;
    g_unpriv = 1;
    check(g_wt_hsm_flash_cb.Program(ctx, 8u, sizeof(data), data) ==
          WH_ERROR_OK && g_gate_calls == 1 &&
          g_gate_last.op == WT_SPM_OP_KEYSTORE_FLASH &&
          g_gate_last.call_type == WT_SPM_KS_FLASH_PROGRAM &&
          g_gate_last.vec_idx == 8u && g_gate_last.num_bytes == 16u,
          "an unprivileged program crosses the gate with its arguments");
    check(memcmp(g_mem + NVM_OFF + 8u, data, sizeof(data)) == 0,
          "and the privileged half programmed it");
    check(g_wt_hsm_flash_cb.Read(ctx, 8u, sizeof(back), back) ==
          WH_ERROR_OK && memcmp(back, data, sizeof(back)) == 0 &&
          g_gate_last.call_type == WT_SPM_KS_FLASH_READ,
          "an unprivileged read crosses the gate");
    check(g_wt_hsm_flash_cb.Verify(ctx, 8u, sizeof(data), data) ==
          WH_ERROR_OK &&
          g_gate_last.call_type == WT_SPM_KS_FLASH_VERIFY &&
          g_wt_hsm_flash_cb.BlankCheck(ctx, SECTOR, 16u) == WH_ERROR_OK &&
          g_gate_last.call_type == WT_SPM_KS_FLASH_BLANKCHECK,
          "unprivileged verify and blank check cross the gate");
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_OK &&
          g_gate_last.call_type == WT_SPM_KS_FLASH_ERASE &&
          all_ff(NVM_OFF, SECTOR),
          "an unprivileged erase crosses the gate");
    check(g_wt_hsm_flash_cb.Cleanup(ctx) == WH_ERROR_OK &&
          g_gate_last.call_type == WT_SPM_KS_FLASH_CLEANUP,
          "an unprivileged cleanup crosses the gate");

    g_gate_calls = 0;
    (void)memset(&other, 0, sizeof(other));
    check(g_wt_hsm_flash_cb.Read(&other, 0u, sizeof(back), back) ==
          WH_ERROR_BADARGS && g_gate_calls == 0,
          "only the vault context may take the gate");

    g_gate_reject = -7;
    g_wt_flash_gate_aborts = 0u;
    g_wt_flash_gate_abort_info = 0u;
    check(g_wt_hsm_flash_cb.Erase(ctx, 0u, SECTOR) == WH_ERROR_ABORTED,
          "a gate the SPM refuses aborts the request");
    check(g_wt_flash_gate_aborts == 1u &&
          g_wt_flash_gate_abort_info ==
          (((uint32_t)WT_SPM_KS_FLASH_ERASE << 24) | 0x00FFFFF9u),
          "the refusal is counted and its sub-op and code latched");
    g_gate_reject = 0;
    g_unpriv = 0;
}

static void test_conf_nvm(void)
{
    uint8_t buf[256];
    uint8_t back[256];

    model_reset();
    (void)memset(g_mem + NVM_OFF, 0x44, NVM_SIZE);
    (void)memset(g_shadow + NVM_OFF, 0x44, NVM_SIZE);
    fill(buf, sizeof(buf), 8u);
    check(wt_conf_nvm_flash_sync(buf, sizeof(buf), 1) == 0,
          "the conformance NVM stores");
    check(memcmp(g_mem + CONF_OFF, buf, sizeof(buf)) == 0 &&
          all_ff(CONF_OFF + sizeof(buf), WT_CONF_NVM_FLASH_SIZE - sizeof(buf)),
          "the store erased its sector and programmed the buffer");
    check(g_mem[NVM_OFF + NVM_SIZE - 1u] == 0x44u,
          "the vault store below it was not touched");
    (void)memset(back, 0, sizeof(back));
    check(wt_conf_nvm_flash_sync(back, sizeof(back), 0) == 0 &&
          memcmp(back, buf, sizeof(back)) == 0, "the conformance NVM loads");
    buf[0] ^= 0xFFu;
    check(wt_conf_nvm_flash_sync(buf, sizeof(buf), 1) == 0 &&
          g_mem[CONF_OFF] == buf[0],
          "a second store rewrites the sector");
    check(wt_conf_nvm_flash_sync(buf, 12u, 1) != 0,
          "a length off the 8-byte unit is refused");
    check(wt_conf_nvm_flash_sync(buf, WT_CONF_NVM_FLASH_SIZE + 8u, 0) != 0 &&
          wt_conf_nvm_flash_sync(NULL, 8u, 0) != 0 &&
          wt_conf_nvm_flash_sync(buf, 0u, 0) != 0,
          "an oversized, empty or missing buffer is refused");
    check(clean_model() && controller_idle(),
          "the conformance NVM left no error and a locked controller");
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Runs one FWU step with an ECC double error armed at off: returns the
 * step's result, or 99 when the NMI halted the core instead. */
static int fwu_ecc_step(int step, uint32_t off, const uint8_t *image)
{
    const wt_fwu_backend_t *be = &wt_fwu_flash_backend;
    uint32_t version = 0u;
    volatile int ret = 99;

    guard(off);
    g_wfi_armed = 1;
    if (sigsetjmp(g_wfi_jmp, 1) == 0) {
        if (step == 0) {
            ret = be->write(NULL, 0x700u, image + 0x400u, 0x100u);
        }
        else if (step == 1) {
            ret = be->arm(NULL, 0x700u, 7u);
        }
        else {
            ret = be->verify(NULL, 0x700u, &version);
        }
    }
    g_wfi_armed = 0;
    g_guard_armed = 0;
    model_settle();
    return ret;
}

static void test_fwu(void)
{
    const wt_fwu_backend_t *be = &wt_fwu_flash_backend;
    static uint8_t image[0x600];
    uint32_t version = 0u;
    uint32_t trailer = FWU_OFF + FWU_SIZE;
    uint32_t erases;
    uint32_t off;
    uint32_t len;
    int staged;

    model_reset();
    check(be->capacity == FWU_SIZE - SECTOR && be->align == 16u,
          "staging keeps the trailer sector out of its capacity");
    (void)memset(image, 0xFF, sizeof(image));
    put32(image, 0x464C4F57u);
    put32(image + 4u, (uint32_t)sizeof(image) - 0x400u);
    image[8] = 0x01u;
    image[9] = 0x00u;
    image[10] = 0x04u;
    image[11] = 0x00u;
    put32(image + 12u, 7u);
    image[16] = 0x00u;
    image[17] = 0x00u;
    fill(image + 0x400u, 0x200u, 9u);

    check(be->begin(NULL) == 0, "staging begins");
    check(be->write(NULL, 0u, image, sizeof(image)) == 0,
          "the image stages into the update slot");
    check(memcmp(g_mem + FWU_OFF, image, sizeof(image)) == 0 &&
          g_page_erases[FWU_OFF / PAGE] == 1u && g_last_bker == 1u &&
          g_last_pnb == SECTOR / PAGE - 1u,
          "the first slot sector was erased in bank 2 and programmed");
    erases = g_erases;
    check(be->write(NULL, sizeof(image) + 0x100u, image + 0x400u, 0x100u)
              != 0 && g_erases == erases,
          "a block that skips ahead of the staged extent is refused");
    check(be->write(NULL, sizeof(image), image + 0x400u, 0x100u) == 0 &&
          g_erases == erases,
          "a later block in the sector is not erased again");
    check(be->verify(NULL, sizeof(image) + 0x100u, &version) == 0 &&
          version == 7u,
          "verify reads the header version");
    /* Stage on to 8 bytes short of the trailer sector, so each refusal
     * below comes from the trailer bound, not the staged-extent check. */
    off = (uint32_t)sizeof(image) + 0x100u;
    staged = 1;
    while (staged != 0 && off < FWU_SIZE - SECTOR - 8u) {
        len = FWU_SIZE - SECTOR - 8u - off;
        if (len > 0x100u) {
            len = 0x100u;
        }
        staged = (be->write(NULL, off, image + 0x400u, len) == 0) ? 1 : 0;
        off += len;
    }
    check(staged != 0, "the slot stages contiguously up to the trailer sector");
    check(be->write(NULL, FWU_SIZE - SECTOR - 8u, image, 16u) != 0 &&
          all_ff(trailer - SECTOR, SECTOR),
          "a write from the staged end across into the trailer sector is refused");
    check(be->write(NULL, FWU_SIZE - SECTOR - 8u, image, 8u) == 0 &&
          be->write(NULL, FWU_SIZE - SECTOR, image, 16u) != 0 &&
          all_ff(trailer - SECTOR, SECTOR),
          "a write starting at the trailer sector is refused");

    /* A complete stage shorter than the header passes the extent check, so
     * only the header-size check can refuse it. */
    check(be->begin(NULL) == 0 && be->write(NULL, 0u, image, 0x3F0u) == 0,
          "a stage shorter than the header is written");
    check(be->verify(NULL, 0x3F0u, &version) != 0,
          "verify refuses a stage shorter than the header");

    check(be->arm(NULL, sizeof(image), 7u) == 0,
          "install arms the wolfBoot trigger");
    check(g_mem[trailer - 5u] == WT_WOLFBOOT_IMG_STATE_UPDATING &&
          g_mem[trailer - 4u] == 0x42u && g_mem[trailer - 3u] == 0x4Fu &&
          g_mem[trailer - 2u] == 0x4Fu && g_mem[trailer - 1u] == 0x54u,
          "the trigger is the state byte and BOOT at the slot's last bytes");
    check(all_ff(trailer - SECTOR, SECTOR - 16u) &&
          g_mem[FWU_OFF + FWU_SIZE] == 0xFFu,
          "nothing else in or past the slot was written");
    check(be->disarm(NULL) == 0 && all_ff(trailer - SECTOR, SECTOR),
          "disarm erases the trailer sector");
    check(clean_model() && controller_idle(),
          "staging left no error and a locked controller");

    /* An ECC double error in any FWU readback fails the step, never halts;
     * the image is staged again so each step reaches its readback. */
    check(be->begin(NULL) == 0 &&
          be->write(NULL, 0u, image, sizeof(image)) == 0 &&
          be->write(NULL, sizeof(image), image + 0x400u, 0x100u) == 0,
          "the image is staged again for the ECC cases");
    check(fwu_ecc_step(2, FWU_OFF, image) == -1,
          "an ECC error in the staged header fails verify");
    check(fwu_ecc_step(0, FWU_OFF + 0x700u, image) == -1,
          "an ECC error reading back a staged block fails the write");
    check(fwu_ecc_step(1, trailer - 16u, image) == -1 &&
          all_ff(trailer - SECTOR, SECTOR),
          "an ECC error reading back the trigger fails and disarms install");
    check(g_nmis >= 3u, "each FWU readback took its ECC NMI");
}

#define OBJECTS      20u
#define OBJECT_MAX   300u
#define ROUNDS       3u

static whNvmFlashContext g_nf_ctx;
static whNvmFlashConfig g_nf_cfg;
static whNvmContext g_nvm;
static whNvmConfig g_nvm_cfg;
static whNvmCb g_nvm_cb = WH_NVM_FLASH_CB;
static uint8_t g_pattern[OBJECT_MAX];

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

/* Fill, read back, destroy and refill until the store compacts into its
 * other partition, then reopen it as a reboot would and read it back. */
static void test_store(void)
{
    whNvmMetadata meta;
    uint8_t readback[OBJECT_MAX];
    whNvmId victims[OBJECTS / 2u];
    uint32_t round;
    uint32_t i;
    uint32_t len;
    uint32_t erases_at_open;
    int ret;

    model_reset();
    ret = nvm_open();
    check(ret == WH_ERROR_OK, "the wolfHSM store opens on blank flash");
    erases_at_open = g_erases;
    for (round = 0u; ret == WH_ERROR_OK && round < ROUNDS; round++) {
        for (i = 0u; ret == WH_ERROR_OK && i < OBJECTS; i++) {
            len = 1u + ((i * 37u + round * 11u) % OBJECT_MAX);
            (void)memset(&meta, 0, sizeof(meta));
            meta.id = (whNvmId)(0x100u + i);
            meta.access = WH_NVM_ACCESS_ANY;
            meta.flags = WH_NVM_FLAGS_NONE;
            meta.len = (whNvmSize)len;
            fill(g_pattern, len, meta.id + round);
            ret = wh_Nvm_AddObjectWithReclaim(&g_nvm, &meta, (whNvmSize)len,
                                              g_pattern);
        }
        for (i = 0u; ret == WH_ERROR_OK && i < OBJECTS; i++) {
            len = 1u + ((i * 37u + round * 11u) % OBJECT_MAX);
            fill(g_pattern, len, 0x100u + i + round);
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
    check(ret == WH_ERROR_OK, "three fill, read and destroy rounds");
    check(g_erases > erases_at_open,
          "the store compacted into its other partition");
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_Cleanup(&g_nvm);
    }
    if (ret == WH_ERROR_OK) {
        ret = nvm_open();
    }
    for (i = 1u; ret == WH_ERROR_OK && i < OBJECTS; i += 2u) {
        len = 1u + ((i * 37u + (ROUNDS - 1u) * 11u) % OBJECT_MAX);
        fill(g_pattern, len, 0x100u + i + ROUNDS - 1u);
        ret = wh_Nvm_Read(&g_nvm, (whNvmId)(0x100u + i), 0u, (whNvmSize)len,
                          readback);
        if (ret == WH_ERROR_OK && memcmp(readback, g_pattern, len) != 0) {
            ret = WH_ERROR_NOTVERIFIED;
        }
    }
    check(ret == WH_ERROR_OK, "a reopened store reads every survivor back");
    printf("  programs=%u erases=%u\n", (unsigned)g_programs,
           (unsigned)g_erases);
    check(clean_model(),
          "no double-word was programmed twice or out of sequence");
    check(all_ff(CONF_OFF, WT_CONF_NVM_FLASH_SIZE) &&
          all_ff(NVM_OFF - PAGE, PAGE),
          "the store stayed inside its 16 KiB");
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    test_geometry();
    test_program();
    test_program_rules();
    test_erase();
    test_ecc();
    test_ecc_nmi();
    test_gate();
    test_conf_nvm();
    test_fwu();
    test_store();
    printf("%s: %d checks, %d failures\n",
           (g_failures == 0) ? "PASS" : "FAIL", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
