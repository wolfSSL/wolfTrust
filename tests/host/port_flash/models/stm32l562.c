/* stm32l562.c
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

/* The STM32L562 dual-bank flash controller beneath flash_drv.c: key unlock,
 * double-word programs, page erases by PNB and BKER, write-1-to-clear status,
 * the ECCR NMI, and whether each array access ran with interrupts masked. */

#include <string.h>

#include "flash_array.h"
#include "memory_map.h"
#include "stm32l562_model.h"

#define REG_NSKEYR  0x08u
#define REG_SECKEYR 0x0Cu
#define REG_NSSR    0x20u
#define REG_SECSR   0x24u
#define REG_NSCR    0x28u
#define REG_SECCR   0x2Cu
#define REG_ECCR    0x30u
#define REG_OPTR    0x40u
#define SR_EOP      (1u << 0)
#define SR_PROGERR  (1u << 3)
#define SR_WRPERR   (1u << 4)
#define SR_PGSERR   (1u << 7)
#define SR_BSY      (1u << 16)
/* Reserved bits mark the views the model handed out: one the driver wrote
 * lacks the mark, so a write-1-to-clear is told from a read. */
#define SR_MARK     (1u << 31)
#define ECCR_MARK   (1u << 27)
#define CR_PG       (1u << 0)
#define CR_PER      (1u << 1)
#define CR_PNB_SHIFT 3u
#define CR_PNB_MASK 0x7Fu
#define CR_BKER     (1u << 11)
#define CR_STRT     (1u << 16)
#define CR_EOPIE    (1u << 24)
#define CR_LOCK     (1u << 31)
#define KEY1        0x45670123u
#define KEY2        0xCDEF89ABu
#define ECCR_ADDR   0x0007FFFFu
#define ECCR_BK     (1u << 21)
#define ECCR_ECCIE  (1u << 24)
#define ECCR_ECCC   (1u << 30)
#define ECCR_ECCD   (1u << 31)
#define OPTR_SWAP   (1u << 20)
#define OPTR_DBANK  (1u << 22)
#define ICACHE_EN   (1u << 0)
#define ICACHE_INV  (1u << 1)
#define PAGES_PER_SECTOR (WT_FLASH_SECTOR_SIZE / WT_FLASH_PAGE_SIZE)
#define MAX_PROTECTED 4u

typedef struct l5_ctl {
    uint32_t keyr;
    uint32_t sr;
    uint32_t sr_view;
    uint32_t cr;
    uint32_t cr_seen;
    int key_stage;
    uint32_t strobes;
    uintptr_t unit_base;
    uint8_t unit[WT_FLASH_PROGRAM_UNIT];
} l5_ctl_t;

static l5_ctl_t g_sec;
static l5_ctl_t g_ns;
static uint32_t g_eccr;
static uint32_t g_eccr_view;
static uint32_t g_optr;
static uint32_t g_scratch;
static uint32_t g_icache_cr;
static uint32_t g_icache_sr;
static int g_icache_stuck;
static int g_busy_mode;
static int g_busy_latched;
static uint32_t g_busy_cr_writes;
static uint32_t g_locked_cr_writes;
static int g_keys_ignored;
static uintptr_t g_ecc_bad_base;
static uint32_t g_ecc_bad_size;
static int g_ecc_stale;
static int g_irq_depth;
static uint32_t g_unmasked_array_accesses;
static uint32_t g_erase_fail_sr;
static uint32_t g_page_erases;
static uint32_t g_sequence_errors;
static uintptr_t g_protected[MAX_PROTECTED];
static uint32_t g_protected_count;
static uint32_t g_page_erase_count[WT_FLASH_SIZE / WT_FLASH_PAGE_SIZE];
/* Page erases of one sector are handed to the array as one sector erase,
 * so its per-sector counts mean the same on every port. */
static uintptr_t g_pending_sector;
static uint32_t g_pending_mask;

void NMI_Handler(void);

void wt_l5_model_reset(void)
{
    (void)memset(&g_sec, 0, sizeof(g_sec));
    (void)memset(&g_ns, 0, sizeof(g_ns));
    g_sec.cr = CR_LOCK;
    g_ns.cr = CR_LOCK;
    g_sec.cr_seen = CR_LOCK;
    g_ns.cr_seen = CR_LOCK;
    g_busy_cr_writes = 0u;
    g_locked_cr_writes = 0u;
    g_eccr = 0u;
    g_optr = OPTR_DBANK;
    g_icache_cr = ICACHE_EN;
    g_icache_sr = 0u;
    g_icache_stuck = 0;
    g_busy_mode = 0;
    g_busy_latched = 0;
    g_keys_ignored = 0;
    g_ecc_bad_size = 0u;
    g_ecc_stale = 0;
    g_erase_fail_sr = 0u;
    g_protected_count = 0u;
    g_pending_mask = 0u;
    g_page_erases = 0u;
    g_sequence_errors = 0u;
    (void)memset(g_page_erase_count, 0, sizeof(g_page_erase_count));
}

static void model_init(void)
{
    static int done;

    if (done == 0) {
        done = 1;
        wt_l5_model_reset();
    }
}

uint32_t wt_flash_model_irq_save(void)
{
    g_irq_depth++;
    return (uint32_t)(g_irq_depth - 1);
}

void wt_flash_model_irq_restore(uint32_t primask)
{
    g_irq_depth = (int)primask;
}

static void note_array_access(void)
{
    if (g_irq_depth == 0) {
        g_unmasked_array_accesses++;
    }
}

static void note_operation(void)
{
    if (g_busy_mode == 2) {
        g_busy_latched = 1;
    }
}

/* The physical bank a CR bank select names, after SWAP_BANK. */
static uintptr_t bank_base_ns(uint32_t cr)
{
    uint32_t bank = ((cr & CR_BKER) != 0u) ? 1u : 0u;

    if ((g_optr & OPTR_SWAP) != 0u) {
        bank ^= 1u;
    }
    return WT_FLASH_NS_BASE + bank * WT_FLASH_BANK_SIZE;
}

static int page_protected(uintptr_t ns_page)
{
    uint32_t i;

    for (i = 0u; i < g_protected_count; i++) {
        if (g_protected[i] == ns_page) {
            return 1;
        }
    }
    return 0;
}

static int erase_now(uintptr_t ns, uint32_t size)
{
    return fa_erase(WT_FLASH_TO_S_ALIAS(ns), size);
}

/* A sector left partly erased is erased page by page. */
static void flush_pending(void)
{
    uint32_t p;

    for (p = 0u; p < PAGES_PER_SECTOR && g_pending_mask != 0u; p++) {
        if ((g_pending_mask & (1u << p)) != 0u) {
            (void)erase_now(g_pending_sector + p * WT_FLASH_PAGE_SIZE,
                            WT_FLASH_PAGE_SIZE);
        }
    }
    g_pending_mask = 0u;
}

static void run_erase(l5_ctl_t* c, int coalesce)
{
    uint32_t page = (c->cr >> CR_PNB_SHIFT) & CR_PNB_MASK;
    uintptr_t ns = bank_base_ns(c->cr) + page * WT_FLASH_PAGE_SIZE;
    uintptr_t sector = ns & ~(uintptr_t)(WT_FLASH_SECTOR_SIZE - 1u);
    uint32_t bit = 1u << ((ns - sector) / WT_FLASH_PAGE_SIZE);
    int rc = FA_OK;

    if ((c->cr & CR_LOCK) != 0u || (c->cr & CR_PER) == 0u ||
            (c->cr & CR_PG) != 0u) {
        c->sr |= SR_PGSERR;
        g_sequence_errors++;
        return;
    }
    if (page_protected(ns) != 0) {
        c->sr |= SR_WRPERR;
        return;
    }
    g_page_erases++;
    g_page_erase_count[(ns - WT_FLASH_NS_BASE) / WT_FLASH_PAGE_SIZE]++;
    if (coalesce == 0 || fa_map(WT_FLASH_TO_S_ALIAS(sector),
                                WT_FLASH_SECTOR_SIZE) == NULL) {
        rc = erase_now(ns, WT_FLASH_PAGE_SIZE);
    }
    else {
        if (g_pending_mask != 0u && g_pending_sector != sector) {
            flush_pending();
        }
        g_pending_sector = sector;
        g_pending_mask |= bit;
        if (g_pending_mask == (1u << PAGES_PER_SECTOR) - 1u) {
            g_pending_mask = 0u;
            rc = erase_now(sector, WT_FLASH_SECTOR_SIZE);
        }
    }
    if (rc != FA_OK) {
        c->sr |= (g_erase_fail_sr != 0u) ? g_erase_fail_sr : SR_WRPERR;
        return;
    }
    if ((c->cr & CR_EOPIE) != 0u) {
        c->sr |= SR_EOP;
    }
    note_operation();
}

static void write_keyr(l5_ctl_t* c)
{
    if (c->key_stage == 0 && c->keyr == KEY1) {
        c->key_stage = 1;
    }
    else if (c->key_stage == 1 && c->keyr == KEY2) {
        c->key_stage = 0;
        if (g_keys_ignored == 0) {
            c->cr &= ~CR_LOCK;
        }
    }
    else {
        c->key_stage = 0;
    }
    c->keyr = 0u;
}

static void settle_ctl(l5_ctl_t* c, int coalesce)
{
    /* RM0438: a CR write while BSY is set stalls the bus on silicon. */
    if ((c->sr & SR_BSY) != 0u && c->cr != c->cr_seen) {
        g_busy_cr_writes++;
        c->cr = c->cr_seen;
    }
    /* A locked CR ignores writes; only the key sequence clears LOCK. */
    if ((c->cr_seen & CR_LOCK) != 0u && c->cr != c->cr_seen) {
        g_locked_cr_writes++;
        c->cr = c->cr_seen;
    }
    if (c->keyr != 0u) {
        write_keyr(c);
    }
    if ((c->sr_view & SR_MARK) == 0u) {
        c->sr &= ~(c->sr_view & ~SR_BSY);
    }
    if ((c->cr & CR_STRT) != 0u) {
        c->cr &= ~CR_STRT;
        run_erase(c, coalesce);
    }
    if ((c->cr & CR_LOCK) != 0u && coalesce != 0) {
        flush_pending();
    }
    if (g_busy_mode == 1 || g_busy_latched != 0) {
        c->sr |= SR_BSY;
    }
    c->sr_view = c->sr | SR_MARK;
    c->cr_seen = c->cr;
}

/* Register side effects run on the next access, as the driver writes
 * through the pointer the accessor returned. */
static void settle(void)
{
    model_init();
    settle_ctl(&g_sec, 1);
    settle_ctl(&g_ns, 0);
    if ((g_eccr_view & ECCR_MARK) == 0u) {
        g_eccr = (g_eccr & ~(g_eccr_view & (ECCR_ECCC | ECCR_ECCD))) & ~ECCR_ECCIE;
        g_eccr |= g_eccr_view & ECCR_ECCIE;
        if ((g_eccr & (ECCR_ECCC | ECCR_ECCD)) == 0u) {
            g_eccr &= ECCR_ECCIE;
        }
    }
    g_eccr_view = g_eccr | ECCR_MARK;
    if ((g_icache_cr & ICACHE_INV) != 0u) {
        g_icache_cr &= ~ICACHE_INV;
        g_icache_sr = (g_icache_stuck != 0) ? 1u : 0u;
    }
}

volatile uint32_t* wt_mock_flash_reg(uint32_t offset)
{
    settle();
    switch (offset) {
        case REG_NSKEYR:
            return &g_ns.keyr;
        case REG_SECKEYR:
            return &g_sec.keyr;
        case REG_NSSR:
            return &g_ns.sr_view;
        case REG_SECSR:
            return &g_sec.sr_view;
        case REG_NSCR:
            return &g_ns.cr;
        case REG_SECCR:
            return &g_sec.cr;
        case REG_ECCR:
            return &g_eccr_view;
        case REG_OPTR:
            return &g_optr;
        default:
            return &g_scratch;
    }
}

volatile uint32_t* wt_mock_icache_reg(uint32_t offset)
{
    settle();
    return (offset == 0u) ? &g_icache_cr : &g_icache_sr;
}

uint8_t wt_mock_flash_rd8(uintptr_t address)
{
    const uint8_t* p;
    uintptr_t ns = address & ~0x04000000u;
    uint32_t bank;

    settle();
    note_array_access();
    if (g_ecc_bad_size != 0u && address >= g_ecc_bad_base &&
            address < g_ecc_bad_base + g_ecc_bad_size) {
        bank = (ns >= WT_FLASH_NS_BASE + WT_FLASH_BANK_SIZE) ? 1u : 0u;
        if ((g_optr & OPTR_SWAP) != 0u) {
            bank ^= 1u;
        }
        g_eccr = (g_eccr & ECCR_ECCIE) | ECCR_ECCD | (bank != 0u ? ECCR_BK : 0u) |
                 (uint32_t)(((ns - WT_FLASH_NS_BASE) % WT_FLASH_BANK_SIZE) &
                            ~(uintptr_t)7u & ECCR_ADDR);
        g_eccr_view = g_eccr | ECCR_MARK;
        NMI_Handler();
        settle();
        return 0xFFu;
    }
    if (g_ecc_stale != 0) {
        g_eccr |= ECCR_ECCC;
        g_eccr_view = g_eccr | ECCR_MARK;
    }
    p = fa_map(address, 1u);
    return (p == NULL) ? 0xFFu : *p;
}

static void wr32_ctl(l5_ctl_t* c, uintptr_t address, uint32_t value)
{
    if ((c->cr & CR_LOCK) != 0u || (c->cr & CR_PG) == 0u ||
            (c->cr & CR_PER) != 0u) {
        c->sr |= SR_PGSERR;
        g_sequence_errors++;
        return;
    }
    if (c->strobes == 0u) {
        c->unit_base = address;
    }
    if (address != c->unit_base + 4u * c->strobes ||
            (c->unit_base % WT_FLASH_PROGRAM_UNIT) != 0u) {
        c->sr |= SR_PGSERR;
        g_sequence_errors++;
        c->strobes = 0u;
        return;
    }
    (void)memcpy(c->unit + 4u * c->strobes, &value, sizeof(value));
    c->strobes++;
    if (c->strobes == WT_FLASH_PROGRAM_UNIT / 4u) {
        c->strobes = 0u;
        if (fa_program(WT_FLASH_TO_S_ALIAS(c->unit_base & ~0x04000000u),
                       c->unit, WT_FLASH_PROGRAM_UNIT) != FA_OK) {
            c->sr |= SR_PROGERR;
        }
        else if ((c->cr & CR_EOPIE) != 0u) {
            c->sr |= SR_EOP;
        }
        note_operation();
    }
}

/* The Secure alias is driven by SECCR, the Non-secure one by NSCR. */
void wt_mock_flash_wr32(uintptr_t address, uint32_t value)
{
    settle();
    note_array_access();
    if ((address & 0x04000000u) != 0u) {
        wr32_ctl(&g_sec, address, value);
    }
    else {
        wr32_ctl(&g_ns, address, value);
    }
}

void wt_l5_model_ecc_bad(uintptr_t s_addr, uint32_t size)
{
    g_ecc_bad_base = s_addr;
    g_ecc_bad_size = size;
}

void wt_l5_model_ecc_stale(int stale)
{
    g_ecc_stale = stale;
}

void wt_l5_model_fail_erases_with(uint32_t sr_bits)
{
    g_erase_fail_sr = sr_bits;
}

void wt_l5_model_protect_page(uintptr_t ns_page)
{
    if (g_protected_count < MAX_PROTECTED) {
        g_protected[g_protected_count++] = ns_page;
    }
}

void wt_l5_model_swap_bank(int swapped)
{
    model_init();
    if (swapped != 0) {
        g_optr |= OPTR_SWAP;
    }
    else {
        g_optr &= ~OPTR_SWAP;
    }
}

void wt_l5_model_icache_stuck(int stuck)
{
    g_icache_stuck = stuck;
    if (stuck == 0) {
        g_icache_sr = 0u;
    }
}

/* Control-register writes the driver issued while the register was locked. */
uint32_t wt_l5_model_locked_cr_writes(void)
{
    settle();
    return g_locked_cr_writes;
}

/* Control-register writes the driver issued while the controller was busy. */
uint32_t wt_l5_model_busy_cr_writes(void)
{
    settle();
    return g_busy_cr_writes;
}

/* 0 idle, 1 busy from now on, 2 busy once the next program or erase runs. */
void wt_l5_model_busy(int mode)
{
    g_busy_mode = mode;
    g_busy_latched = 0;
    if (mode == 0) {
        g_sec.sr &= ~SR_BSY;
        g_ns.sr &= ~SR_BSY;
    }
}

void wt_l5_model_keys_ignored(int ignored)
{
    g_keys_ignored = ignored;
}

int wt_l5_model_locked(void)
{
    settle();
    return (g_sec.cr & CR_LOCK) != 0u;
}

int wt_l5_model_pg_set(void)
{
    settle();
    return (g_sec.cr & CR_PG) != 0u;
}

uint32_t wt_l5_model_page_erases(void)
{
    return g_page_erases;
}

/* How often the physical page at that Non-secure address was erased. */
uint32_t wt_l5_model_page_erased(uintptr_t ns_page)
{
    uintptr_t off = ns_page - WT_FLASH_NS_BASE;

    return (ns_page < WT_FLASH_NS_BASE || off >= WT_FLASH_SIZE) ? 0u :
        g_page_erase_count[off / WT_FLASH_PAGE_SIZE];
}

uint32_t wt_l5_model_sequence_errors(void)
{
    return g_sequence_errors;
}

uint32_t wt_l5_model_unmasked_array_accesses(void)
{
    return g_unmasked_array_accesses;
}

int wt_l5_model_irq_depth(void)
{
    return g_irq_depth;
}
