/* stm32h563.c
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

/* A model of the STM32H563 flash controller beneath the production
 * flash_drv.c: the key sequence unlocks CR, a program needs PG set and
 * four strobes into an unprogrammed quad-word, an erase takes PNB and
 * BKSEL from CR on STRT, errors latch in SR until CCR clears them, the
 * ICACHE invalidate completes at once unless held busy, the controller
 * can be held busy or made to ignore the unlock keys, an ECC-marked
 * quad-word raises the NMI through ECCDETR on its first byte, and every
 * array access records whether interrupts were masked. */

#include <string.h>

#include "flash_array.h"
#include "memory_map.h"
#include "stm32h563_model.h"

#define REG_KEYR    0x08u
#define REG_SR      0x24u
#define REG_CR      0x2Cu
#define REG_CCR     0x34u
#define REG_OPTSR   0x50u
#define REG_ECCDETR 0x104u
#define SR_BSY      (1u << 0)
#define SR_DBNE     (1u << 3)
#define SR_EOP      (1u << 16)
#define SR_WRPE     (1u << 17)
#define SR_PGSE     (1u << 18)
#define CR_LOCK     (1u << 0)
#define CR_PG       (1u << 1)
#define CR_SER      (1u << 2)
#define CR_STRT     (1u << 5)
#define CR_PNB_SHIFT 6u
#define CR_PNB_MASK 0x7Fu
#define CR_BKSEL    (1u << 31)
#define KEY1        0x45670123u
#define KEY2        0xCDEF89ABu
#define ICACHE_EN   (1u << 0)
#define ICACHE_INV  (1u << 1)
#define ECCD        (1u << 31)
#define ECC_BANK    (1u << 22)
#define BANK2_NS    0x08100000u

static uint32_t g_keyr;
static uint32_t g_sr;
static uint32_t g_cr = CR_LOCK;
static uint32_t g_ccr;
static uint32_t g_optsr;
static uint32_t g_eccdetr;
static uint32_t g_scratch;
static uint32_t g_icache_cr = ICACHE_EN;
static uint32_t g_icache_sr;
static int g_icache_stuck;
static int g_busy_mode;
static int g_busy_latched;
static int g_keys_ignored;
static int g_key_stage;
static uint32_t g_strobes;
static uintptr_t g_unit_base;
static uint8_t g_unit[WT_FLASH_PROGRAM_UNIT];
static uintptr_t g_ecc_bad_base;
static uint32_t g_ecc_bad_size;
static int g_irq_depth;
static uint32_t g_unmasked_array_accesses;
static uint32_t g_max_irq_depth;
static uint32_t g_erase_fail_sr;

void NMI_Handler(void);

uint32_t wt_flash_model_irq_save(void)
{
    g_irq_depth++;
    if ((uint32_t)g_irq_depth > g_max_irq_depth) {
        g_max_irq_depth = (uint32_t)g_irq_depth;
    }
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

static void run_erase(void)
{
    uint32_t sector = (g_cr >> CR_PNB_SHIFT) & CR_PNB_MASK;
    uintptr_t ns = WT_FLASH_NS_BASE + sector * WT_FLASH_SECTOR_SIZE;

    if ((g_cr & CR_BKSEL) != 0u) {
        ns += WT_FLASH_BANK_SIZE;
    }
    if ((g_cr & CR_LOCK) != 0u || (g_cr & CR_SER) == 0u) {
        g_sr |= SR_PGSE;
        return;
    }
    if (fa_erase(WT_FLASH_TO_S_ALIAS(ns), WT_FLASH_SECTOR_SIZE) != FA_OK) {
        g_sr |= (g_erase_fail_sr != 0u) ? g_erase_fail_sr : SR_WRPE;
        return;
    }
    g_sr |= SR_EOP;
    note_operation();
}

static void write_cr(uint32_t value)
{
    if ((g_cr & CR_LOCK) != 0u && (value & CR_LOCK) == 0u) {
        value |= CR_LOCK;
    }
    g_cr = value;
    if ((g_cr & CR_STRT) != 0u) {
        g_cr &= ~CR_STRT;
        run_erase();
    }
}

static void write_keyr(uint32_t value)
{
    if (g_key_stage == 0 && value == KEY1) {
        g_key_stage = 1;
    }
    else if (g_key_stage == 1 && value == KEY2) {
        g_key_stage = 0;
        if (g_keys_ignored == 0) {
            g_cr &= ~CR_LOCK;
        }
    }
    else {
        g_key_stage = 0;
    }
}

static void settle(void);

volatile uint32_t* wt_mock_flash_reg(uint32_t offset)
{
    settle();
    switch (offset) {
        case REG_KEYR:
            return &g_keyr;
        case REG_SR:
            return &g_sr;
        case REG_CR:
            return &g_cr;
        case REG_CCR:
            return &g_ccr;
        case REG_OPTSR:
            return &g_optsr;
        case REG_ECCDETR:
            return &g_eccdetr;
        default:
            return &g_scratch;
    }
}

/* Register side effects run on the next access, as the driver writes
 * through the pointer the accessor returned. */
static void settle(void)
{
    if (g_keyr != 0u) {
        write_keyr(g_keyr);
        g_keyr = 0u;
    }
    if (g_ccr != 0u) {
        g_sr &= ~g_ccr;
        g_ccr = 0u;
    }
    if ((g_cr & CR_STRT) != 0u) {
        write_cr(g_cr);
    }
    if (g_busy_mode == 1 || g_busy_latched != 0) {
        g_sr |= SR_BSY;
    }
    if ((g_icache_cr & ICACHE_INV) != 0u) {
        g_icache_cr &= ~ICACHE_INV;
        g_icache_sr = (g_icache_stuck != 0) ? 1u : 0u;
    }
    if ((g_eccdetr & ECCD) != 0u && g_eccdetr == ECCD) {
        /* Writing ECCD clears it. */
        g_eccdetr = 0u;
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

    settle();
    note_array_access();
    if (g_ecc_bad_size != 0u && address >= g_ecc_bad_base &&
            address < g_ecc_bad_base + g_ecc_bad_size) {
        uintptr_t ns = address & ~0x04000000u;

        g_eccdetr = ECCD | ((ns >= BANK2_NS) ? ECC_BANK : 0u) |
                    (uint32_t)((ns & 0x000FFFFFu) >> 4);
        NMI_Handler();
        /* The handler's write-one-to-clear has landed. */
        g_eccdetr = 0u;
        return 0xFFu;
    }
    p = fa_map(address, 1u);
    return (p == NULL) ? 0xFFu : *p;
}

void wt_mock_flash_wr32(uintptr_t address, uint32_t value)
{
    settle();
    note_array_access();
    if ((g_cr & CR_LOCK) != 0u || (g_cr & CR_PG) == 0u) {
        g_sr |= SR_PGSE;
        return;
    }
    if (g_strobes == 0u) {
        g_unit_base = address;
    }
    if (address != g_unit_base + 4u * g_strobes) {
        g_sr |= SR_PGSE;
        g_strobes = 0u;
        return;
    }
    (void)memcpy(g_unit + 4u * g_strobes, &value, sizeof(value));
    g_strobes++;
    if (g_strobes == WT_FLASH_PROGRAM_UNIT / 4u) {
        g_strobes = 0u;
        if (fa_program(g_unit_base, g_unit, WT_FLASH_PROGRAM_UNIT) != FA_OK) {
            g_sr |= SR_PGSE;
        }
        else {
            g_sr |= SR_EOP;
        }
        note_operation();
    }
}

void wt_h5_model_ecc_bad(uintptr_t s_addr, uint32_t size)
{
    g_ecc_bad_base = s_addr;
    g_ecc_bad_size = size;
}

void wt_h5_model_fail_erases_with(uint32_t sr_bits)
{
    g_erase_fail_sr = sr_bits;
}

void wt_h5_model_icache_stuck(int stuck)
{
    g_icache_stuck = stuck;
    if (stuck == 0) {
        g_icache_sr = 0u;
    }
}

/* 0 idle, 1 busy from now on, 2 busy once the next program or erase runs. */
void wt_h5_model_busy(int mode)
{
    g_busy_mode = mode;
    g_busy_latched = 0;
    if (mode == 0) {
        g_sr &= ~SR_BSY;
    }
}

void wt_h5_model_keys_ignored(int ignored)
{
    g_keys_ignored = ignored;
}

int wt_h5_model_locked(void)
{
    settle();
    return (g_cr & CR_LOCK) != 0u;
}

uint32_t wt_h5_model_unmasked_array_accesses(void)
{
    return g_unmasked_array_accesses;
}

int wt_h5_model_irq_depth(void)
{
    return g_irq_depth;
}
