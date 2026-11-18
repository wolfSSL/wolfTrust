/* flash_drv.c
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

/* STM32L562 internal flash primitives (flash_port.h): double-word programs
 * and 2 KiB page erases through the Secure controller registers, reads
 * through an ECC-contained window, the ICACHE invalidated after every
 * change. The remeasure probe's tamper goes through the Non-secure ones. */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "flash_port.h"
#include "memory_map.h"
#include "wolftrust/zeroize.h"
#include "wolfhsm/wh_error.h"

/* Every controller and array access goes through these so the host model
 * can stand behind them; on the part they are the plain volatile accesses. */
#ifndef WT_FLASH_REG
#define WT_FLASH_REG(offset) (*(volatile uint32_t *)(0x50022000u + (offset)))
#define WT_ICACHE_REG(offset) (*(volatile uint32_t *)(0x50030400u + (offset)))
#define WT_FLASH_RD8(address) (*(const volatile uint8_t *)(address))
#define WT_FLASH_WR32(address, value) \
    (*(volatile uint32_t *)(address) = (value))
#endif

#define WT_FLASH_NSKEYR        WT_FLASH_REG(0x08u)
#define WT_FLASH_SECKEYR       WT_FLASH_REG(0x0Cu)
#define WT_FLASH_NSSR          WT_FLASH_REG(0x20u)
#define WT_FLASH_SECSR         WT_FLASH_REG(0x24u)
#define WT_FLASH_NSCR          WT_FLASH_REG(0x28u)
#define WT_FLASH_SECCR         WT_FLASH_REG(0x2Cu)
#define WT_FLASH_ECCR          WT_FLASH_REG(0x30u)
#define WT_FLASH_OPTR          WT_FLASH_REG(0x40u)
#define WT_ICACHE_CR           WT_ICACHE_REG(0x00u)
#define WT_ICACHE_SR           WT_ICACHE_REG(0x04u)

#define WT_FLASH_SR_EOP        (1u << 0)
#define WT_FLASH_SR_OPERR      (1u << 1)
#define WT_FLASH_SR_PROGERR    (1u << 3)
#define WT_FLASH_SR_WRPERR     (1u << 4)
#define WT_FLASH_SR_PGAERR     (1u << 5)
#define WT_FLASH_SR_SIZERR     (1u << 6)
#define WT_FLASH_SR_PGSERR     (1u << 7)
#define WT_FLASH_SR_BSY        (1u << 16)
#define WT_FLASH_SR_ALL_ERR    (WT_FLASH_SR_OPERR | WT_FLASH_SR_PROGERR | \
                                WT_FLASH_SR_WRPERR | WT_FLASH_SR_PGAERR | \
                                WT_FLASH_SR_SIZERR | WT_FLASH_SR_PGSERR)
#define WT_FLASH_CR_PG         (1u << 0)
#define WT_FLASH_CR_PER        (1u << 1)
#define WT_FLASH_CR_PNB_SHIFT  3u
#define WT_FLASH_CR_PNB_MASK   0x7Fu
#define WT_FLASH_CR_BKER       (1u << 11)
#define WT_FLASH_CR_STRT       (1u << 16)
#define WT_FLASH_CR_LOCK       (1u << 31)
#define WT_FLASH_KEY1          0x45670123u
#define WT_FLASH_KEY2          0xCDEF89ABu
/* DBANK=1 reports through ECCC and ECCD; ADDR_ECC and BK_ECC hold until
 * both clear (RM0438). */
#define WT_FLASH_ECCR_ADDR_MASK 0x0007FFFFu
#define WT_FLASH_ECCR_BK       (1u << 21)
#define WT_FLASH_ECCR_ECCIE    (1u << 24)
#define WT_FLASH_ECCR_ECCC     (1u << 30)
#define WT_FLASH_ECCR_ECCD     (1u << 31)
#define WT_FLASH_OPTR_SWAP_BANK (1u << 20)
#define WT_ICACHE_CR_EN        (1u << 0)
#define WT_ICACHE_CR_CACHEINV  (1u << 1)
#define WT_ICACHE_SR_BUSYF     (1u << 0)
#define WT_FLASH_BANK2_BASE_NS (WT_FLASH_NS_BASE + WT_FLASH_BANK_SIZE)
#define WT_FLASH_IDLE_SPINS    0x00200000u

/* The raw FLASH_SECSR error bits of the first failed program or erase. */
volatile uint32_t g_wt_flash_first_err_sr __attribute__((used));
static volatile uint32_t g_flash_ecc_active;
static volatile uint32_t g_flash_ecc_detected;
static volatile uint32_t g_flash_ecc_bank;
static volatile uint32_t g_flash_ecc_start;
static volatile uint32_t g_flash_ecc_end;

#if defined(__ARM_EABI__)
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
#else
/* The host model records the interrupt state the driver asks for. */
uint32_t wt_flash_model_irq_save(void);
void wt_flash_model_irq_restore(uint32_t primask);

static void wt_flash_barrier(void)
{
}

static uint32_t wt_irq_save(void)
{
    return wt_flash_model_irq_save();
}

static void wt_irq_restore(uint32_t primask)
{
    wt_flash_model_irq_restore(primask);
}
#endif

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
#if defined(__ARM_EABI__)
        __asm__ volatile ("wfi");
#endif
    }
}

static uintptr_t wt_flash_ns_addr(uintptr_t addr)
{
    return addr & ~0x04000000u;
}

static uint32_t wt_flash_bank(uintptr_t ns_addr)
{
    uint32_t bank = ns_addr >= WT_FLASH_BANK2_BASE_NS ? 1u : 0u;

    if ((WT_FLASH_OPTR & WT_FLASH_OPTR_SWAP_BANK) != 0u) {
        bank ^= 1u;
    }
    return bank;
}

/* An ECC double error inside the window is contained by the NMI handler;
 * one anywhere else still halts. ADDR_ECC is the failing double-word's byte
 * offset in its bank, so the window is exactly the double-words read. */
int wt_port_flash_read(uintptr_t s_addr, uint8_t *dst, uint32_t size)
{
    uintptr_t ns_address;
    uint32_t primask;
    uint32_t bank_off;
    uint32_t i;
    int ret = WH_ERROR_OK;

    primask = wt_irq_save();
    ns_address = wt_flash_ns_addr(s_addr);
    g_flash_ecc_bank = wt_flash_bank(ns_address);
    bank_off = (uint32_t)((ns_address - WT_FLASH_NS_BASE) % WT_FLASH_BANK_SIZE);
    g_flash_ecc_start = bank_off & ~7u;
    g_flash_ecc_end = (bank_off + size + 7u) & ~7u;
    g_flash_ecc_detected = 0u;
    wt_flash_ecc_clear();
    g_flash_ecc_active = 1u;
    wt_flash_barrier();

    for (i = 0u; i < size; i++) {
        dst[i] = WT_FLASH_RD8(s_addr + i);
    }
    wt_flash_barrier();
    g_flash_ecc_active = 0u;

    if (g_flash_ecc_detected != 0u ||
        (WT_FLASH_ECCR & WT_FLASH_ECCR_ECCD) != 0u) {
        ret = WH_ERROR_ABORTED;
        (void)memset(dst, 0, size);
    }
    wt_flash_ecc_clear();
    wt_flash_barrier();
    wt_irq_restore(primask);

    return ret;
}

static int wt_flash_wait_idle(void)
{
    uint32_t spins = 0u;

    while ((WT_FLASH_SECSR & WT_FLASH_SR_BSY) != 0u &&
            spins < WT_FLASH_IDLE_SPINS) {
        spins++;
    }
    return (spins < WT_FLASH_IDLE_SPINS) ? 0 : -1;
}

/* RM0438: a SECCR or NSCR write stalls the bus while BSY is set, so a timed-out
 * operation leaves the control register for the reset to recover. */
static int wt_flash_sec_idle(void)
{
    return ((WT_FLASH_SECSR & WT_FLASH_SR_BSY) == 0u) ? 1 : 0;
}

/* SECSR flags are write-1-to-clear. */
static void wt_flash_clear_errors(void)
{
    WT_FLASH_SECSR = WT_FLASH_SR_ALL_ERR | WT_FLASH_SR_EOP;
}

static int wt_flash_check_errors(void)
{
    if ((WT_FLASH_SECSR & WT_FLASH_SR_ALL_ERR) != 0u) {
        if (g_wt_flash_first_err_sr == 0u) {
            g_wt_flash_first_err_sr = WT_FLASH_SECSR;
        }
        wt_flash_clear_errors();
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

static int wt_flash_unlock(void)
{
    uint32_t spins = 0u;

    if (wt_flash_wait_idle() != 0) {
        return -1;
    }
    if ((WT_FLASH_SECCR & WT_FLASH_CR_LOCK) != 0u) {
        WT_FLASH_SECKEYR = WT_FLASH_KEY1;
        wt_flash_barrier();
        WT_FLASH_SECKEYR = WT_FLASH_KEY2;
        wt_flash_barrier();
        while ((WT_FLASH_SECCR & WT_FLASH_CR_LOCK) != 0u &&
                spins < WT_FLASH_IDLE_SPINS) {
            spins++;
        }
    }
    return ((WT_FLASH_SECCR & WT_FLASH_CR_LOCK) == 0u) ? 0 : -1;
}

static void wt_flash_lock(void)
{
    if (wt_flash_wait_idle() == 0 &&
            (WT_FLASH_SECCR & WT_FLASH_CR_LOCK) == 0u) {
        WT_FLASH_SECCR |= WT_FLASH_CR_LOCK;
    }
}

/* The ICACHE caches data reads from flash too, so a read-back of a
 * just-programmed unit can hit the stale line (RM0438). */
static int wt_flash_icache_invalidate(void)
{
    uint32_t spins = 0u;
    int ret = 0;

    if ((WT_ICACHE_CR & WT_ICACHE_CR_EN) != 0u) {
        WT_ICACHE_CR |= WT_ICACHE_CR_CACHEINV;
        while ((WT_ICACHE_SR & WT_ICACHE_SR_BUSYF) != 0u &&
                spins < WT_FLASH_IDLE_SPINS) {
            spins++;
        }
        wt_flash_barrier();
        if ((WT_ICACHE_SR & WT_ICACHE_SR_BUSYF) != 0u) {
            ret = -1;
        }
    }
    return ret;
}

/* One double-word per step, with interrupts held off for the step: an
 * interrupt between the two halves breaks the sequence (PGSERR/SIZERR). */
static int wt_flash_program_unit(uintptr_t dst, const uint8_t *src)
{
    uint32_t word[2];
    uint32_t primask;
    int ret;

    (void)memcpy(word, src, sizeof(word));
    primask = wt_irq_save();
    WT_FLASH_SECCR |= WT_FLASH_CR_PG;
    WT_FLASH_WR32(dst, word[0]);
    wt_flash_barrier();
    WT_FLASH_WR32(dst + 4u, word[1]);
    wt_flash_barrier();
    ret = (wt_flash_wait_idle() == 0) ? WH_ERROR_OK : WH_ERROR_ABORTED;
    if ((WT_FLASH_SECSR & WT_FLASH_SR_EOP) != 0u) {
        WT_FLASH_SECSR = WT_FLASH_SR_EOP;
    }
    if (wt_flash_sec_idle() != 0) {
        WT_FLASH_SECCR &= ~WT_FLASH_CR_PG;
    }
    if (ret == WH_ERROR_OK) {
        ret = wt_flash_check_errors();
    }
    wt_irq_restore(primask);
    wt_forceZero(word, sizeof(word));
    return ret;
}

int wt_port_flash_program(uintptr_t s_addr, const uint8_t *src, uint32_t size)
{
    uint32_t written = 0u;
    int ret = WH_ERROR_OK;

    if (wt_flash_unlock() != 0) {
        return WH_ERROR_ABORTED;
    }
    wt_flash_clear_errors();
    while (ret == WH_ERROR_OK && written < size) {
        ret = wt_flash_program_unit(s_addr + written, src + written);
        written += WT_FLASH_PROGRAM_UNIT;
    }
    if (wt_flash_sec_idle() != 0) {
        WT_FLASH_SECCR &= ~WT_FLASH_CR_PG;
    }
    wt_flash_lock();
    if (wt_flash_icache_invalidate() != 0 && ret == WH_ERROR_OK) {
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

/* A wolfHSM sector spans four 2 KiB pages, each numbered within its bank. */
int wt_port_flash_erase(uintptr_t s_addr, uint32_t size)
{
    uint32_t start = 0u;
    int ret = WH_ERROR_OK;

    if (wt_flash_unlock() != 0) {
        return WH_ERROR_ABORTED;
    }
    wt_flash_clear_errors();
    while (ret == WH_ERROR_OK && start < size) {
        uintptr_t ns_addr = wt_flash_ns_addr(s_addr + start);
        uint32_t page = (uint32_t)(((ns_addr - WT_FLASH_NS_BASE) %
                                    WT_FLASH_BANK_SIZE) / WT_FLASH_PAGE_SIZE);
        uint32_t primask;
        uint32_t cr;

        primask = wt_irq_save();
        cr = WT_FLASH_SECCR & ~((WT_FLASH_CR_PNB_MASK << WT_FLASH_CR_PNB_SHIFT) |
                                WT_FLASH_CR_PER | WT_FLASH_CR_PG |
                                WT_FLASH_CR_BKER);
        cr |= (page << WT_FLASH_CR_PNB_SHIFT) | WT_FLASH_CR_PER |
              (wt_flash_bank(ns_addr) != 0u ? WT_FLASH_CR_BKER : 0u);
        WT_FLASH_SECCR = cr;
        wt_flash_barrier();
        WT_FLASH_SECCR |= WT_FLASH_CR_STRT;
        ret = (wt_flash_wait_idle() == 0) ? WH_ERROR_OK : WH_ERROR_ABORTED;
        if (ret == WH_ERROR_OK) {
            ret = wt_flash_check_errors();
        }
        wt_irq_restore(primask);
        start += WT_FLASH_PAGE_SIZE;
    }
    if (wt_flash_sec_idle() != 0) {
        WT_FLASH_SECCR &= ~WT_FLASH_CR_PER;
    }
    wt_flash_lock();
    if (wt_flash_icache_invalidate() != 0 && ret == WH_ERROR_OK) {
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

int wt_port_flash_blank_check(uintptr_t s_addr, uint32_t size)
{
    uint8_t flash_data[WT_FLASH_PROGRAM_UNIT];
    uint32_t checked = 0u;
    uint32_t i;
    int ret = WH_ERROR_OK;

    while (checked < size && ret == WH_ERROR_OK) {
        uint32_t chunk = size - checked;

        if (chunk > (uint32_t)sizeof(flash_data)) {
            chunk = (uint32_t)sizeof(flash_data);
        }
        ret = wt_port_flash_read(s_addr + checked, flash_data, chunk);
        for (i = 0u; i < chunk && ret == WH_ERROR_OK; i++) {
            if (flash_data[i] != 0xFFu) {
                ret = WH_ERROR_NOTBLANK;
            }
        }
        checked += chunk;
    }
    wt_forceZero(flash_data, sizeof(flash_data));
    return ret;
}

/* Bounded: a reset that follows must not cut a program short, and a wedged
 * controller must still let the reset happen. */
void wt_port_flash_quiesce(void)
{
    wt_flash_lock();
}

#if defined(WT_REMEASURE_PROBE)
static int wt_flash_ns_wait(void)
{
    uint32_t spins = 0u;

    while ((WT_FLASH_NSSR & WT_FLASH_SR_BSY) != 0u &&
            spins < WT_FLASH_IDLE_SPINS) {
        spins++;
    }
    if (spins >= WT_FLASH_IDLE_SPINS ||
            (WT_FLASH_NSSR & WT_FLASH_SR_ALL_ERR) != 0u) {
        WT_FLASH_NSSR = WT_FLASH_SR_ALL_ERR | WT_FLASH_SR_EOP;
        return WH_ERROR_ABORTED;
    }
    WT_FLASH_NSSR = WT_FLASH_SR_EOP;
    return WH_ERROR_OK;
}

/* The guest images sit under the Non-secure watermark, so the tamper erases
 * and programs through the Non-secure controller registers. */
int wt_port_flash_probe_tamper(uintptr_t ns_addr)
{
    uint32_t off = (uint32_t)(ns_addr - WT_FLASH_NS_BASE);
    uint32_t primask;
    uint32_t spins;
    uint32_t page;
    uint32_t cr;
    int ret = WH_ERROR_OK;

    if (ns_addr < WT_FLASH_NS_BASE || off >= WT_FLASH_SIZE ||
            (off % WT_FLASH_SECTOR_SIZE) != 0u) {
        return WH_ERROR_BADARGS;
    }
    if ((WT_FLASH_NSCR & WT_FLASH_CR_LOCK) != 0u) {
        WT_FLASH_NSKEYR = WT_FLASH_KEY1;
        wt_flash_barrier();
        WT_FLASH_NSKEYR = WT_FLASH_KEY2;
        wt_flash_barrier();
        spins = 0u;
        while ((WT_FLASH_NSCR & WT_FLASH_CR_LOCK) != 0u &&
                spins < WT_FLASH_IDLE_SPINS) {
            spins++;
        }
        if ((WT_FLASH_NSCR & WT_FLASH_CR_LOCK) != 0u) {
            return WH_ERROR_ABORTED;
        }
    }
    WT_FLASH_NSSR = WT_FLASH_SR_ALL_ERR | WT_FLASH_SR_EOP;
    for (page = 0u; ret == WH_ERROR_OK &&
            page < WT_FLASH_SECTOR_SIZE / WT_FLASH_PAGE_SIZE; page++) {
        cr = WT_FLASH_CR_PER |
             ((((off + page * WT_FLASH_PAGE_SIZE) % WT_FLASH_BANK_SIZE) /
               WT_FLASH_PAGE_SIZE) << WT_FLASH_CR_PNB_SHIFT);
        if (wt_flash_bank(ns_addr) != 0u) {
            cr |= WT_FLASH_CR_BKER;
        }
        WT_FLASH_NSCR = cr;
        WT_FLASH_NSCR = cr | WT_FLASH_CR_STRT;
        ret = wt_flash_ns_wait();
        if ((WT_FLASH_NSSR & WT_FLASH_SR_BSY) == 0u) {
            WT_FLASH_NSCR = 0u;
        }
    }
    if (ret == WH_ERROR_OK) {
        primask = wt_irq_save();
        WT_FLASH_NSCR = WT_FLASH_CR_PG;
        WT_FLASH_WR32(ns_addr, 0u);
        wt_flash_barrier();
        WT_FLASH_WR32(ns_addr + 4u, 0u);
        wt_flash_barrier();
        ret = wt_flash_ns_wait();
        if ((WT_FLASH_NSSR & WT_FLASH_SR_BSY) == 0u) {
            WT_FLASH_NSCR = 0u;
        }
        wt_irq_restore(primask);
    }
    if ((WT_FLASH_NSSR & WT_FLASH_SR_BSY) == 0u) {
        WT_FLASH_NSCR = WT_FLASH_CR_LOCK;
    }
    if (wt_flash_icache_invalidate() != 0 && ret == WH_ERROR_OK) {
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}
#endif
