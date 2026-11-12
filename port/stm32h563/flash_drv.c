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

/* STM32H563 internal flash primitives (flash_port.h): quad-word programs
 * and sector erases on the controller, reads through an ECC-contained
 * window, the ICACHE invalidated after every change. */

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
#include "stm32h563_regs.h"
#define WT_FLASH_REG(offset) \
    (*(volatile uint32_t *)(WT_FLASH_BASE_S + (offset)))
#define WT_ICACHE_REG(offset) (*(volatile uint32_t *)(0x50030400u + (offset)))
#define WT_FLASH_RD8(address) (*(const volatile uint8_t *)(address))
#define WT_FLASH_WR32(address, value) \
    (*(volatile uint32_t *)(address) = (value))
#endif

#define WT_FLASH_KEYR          WT_FLASH_REG(0x08u)
#define WT_FLASH_STATUS        WT_FLASH_REG(0x24u)
#define WT_FLASH_CR            WT_FLASH_REG(0x2Cu)
#define WT_FLASH_CCR           WT_FLASH_REG(0x34u)
#define WT_FLASH_OPTSR_CUR     WT_FLASH_REG(0x50u)
#define WT_FLASH_ECCDETR       WT_FLASH_REG(0x104u)
#define WT_ICACHE_CR           WT_ICACHE_REG(0x00u)
#define WT_ICACHE_SR           WT_ICACHE_REG(0x04u)

#define WT_FLASH_SR_BSY        (1u << 0)
#define WT_FLASH_SR_DBNE       (1u << 3)
#define WT_FLASH_SR_EOP        (1u << 16)
#define WT_FLASH_SR_WRPE       (1u << 17)
#define WT_FLASH_SR_PGSE       (1u << 18)
#define WT_FLASH_SR_STRBE      (1u << 19)
#define WT_FLASH_SR_INCE       (1u << 20)
#define WT_FLASH_SR_OPTE       (1u << 21)
#define WT_FLASH_SR_OPTWE      (1u << 22)
#define WT_FLASH_SR_ALL_ERR    (WT_FLASH_SR_WRPE | WT_FLASH_SR_PGSE | \
                                WT_FLASH_SR_STRBE | WT_FLASH_SR_INCE | \
                                WT_FLASH_SR_OPTE | WT_FLASH_SR_OPTWE)
#define WT_FLASH_CCR_CLR_ALL   (WT_FLASH_SR_DBNE | WT_FLASH_SR_EOP | \
                                WT_FLASH_SR_ALL_ERR)

#define WT_FLASH_CR_LOCK       (1u << 0)
#define WT_FLASH_CR_PG         (1u << 1)
#define WT_FLASH_CR_SER        (1u << 2)
#define WT_FLASH_CR_BER        (1u << 3)
#define WT_FLASH_CR_STRT       (1u << 5)
#define WT_FLASH_CR_PNB_SHIFT  6u
#define WT_FLASH_CR_PNB_MASK   0x7Fu
#define WT_FLASH_CR_MER        (1u << 15)
#define WT_FLASH_CR_BKSEL      (1u << 31)

#define WT_FLASH_KEY1          0x45670123u
#define WT_FLASH_KEY2          0xCDEF89ABu

#define WT_ICACHE_CR_EN        (1u << 0)
#define WT_ICACHE_CR_CACHEINV  (1u << 1)
#define WT_ICACHE_SR_BUSYF     (1u << 0)
#define WT_FLASH_BANK2_BASE_NS 0x08100000u
#define WT_FLASH_TOP_NS        0x081FFFFFu
#define WT_FLASH_BANK_SECTORS  128u
#define WT_FLASH_SWAP_BANK     (1u << 31)
#define WT_FLASH_ECC_ADDR_MASK 0x0000FFFFu
#define WT_FLASH_ECC_BANK      (1u << 22)
#define WT_FLASH_ECCD          (1u << 31)
#define WT_FLASH_IDLE_SPINS    0x00200000u

/* The raw FLASH_SR error bits of the first failed program or erase. */
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

void NMI_Handler(void)
{
    uint32_t ecc = WT_FLASH_ECCDETR;
    uint32_t bank = (ecc & WT_FLASH_ECC_BANK) != 0u ? 1u : 0u;
    uint32_t address = ecc & WT_FLASH_ECC_ADDR_MASK;

    if ((ecc & WT_FLASH_ECCD) != 0u && g_flash_ecc_active != 0u &&
        bank == g_flash_ecc_bank && address >= g_flash_ecc_start &&
        address < g_flash_ecc_end) {
        g_flash_ecc_detected = 1u;
        WT_FLASH_ECCDETR |= WT_FLASH_ECCD;
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

    if ((WT_FLASH_OPTSR_CUR & WT_FLASH_SWAP_BANK) != 0u) {
        bank ^= 1u;
    }
    return bank;
}

/* An ECC double error inside the window is contained by the NMI handler;
 * one anywhere else still halts. The window is only open for this copy. */
int wt_port_flash_read(uintptr_t s_addr, uint8_t *dst, uint32_t size)
{
    uintptr_t ns_address;
    uint32_t primask;
    uint32_t i;
    int ret = WH_ERROR_OK;

    primask = wt_irq_save();
    ns_address = wt_flash_ns_addr(s_addr);
    g_flash_ecc_bank = wt_flash_bank(ns_address);
    g_flash_ecc_start = (uint32_t)((ns_address & 0x000FFFFFu) >> 4);
    g_flash_ecc_end = (uint32_t)(((ns_address & 0x000FFFFFu) + size + 15u) >> 4);
    g_flash_ecc_detected = 0u;
    WT_FLASH_ECCDETR |= WT_FLASH_ECCD;
    g_flash_ecc_active = 1u;
    wt_flash_barrier();

    for (i = 0u; i < size; i++) {
        dst[i] = WT_FLASH_RD8(s_addr + i);
    }
    wt_flash_barrier();
    g_flash_ecc_active = 0u;

    if (g_flash_ecc_detected != 0u ||
        (WT_FLASH_ECCDETR & WT_FLASH_ECCD) != 0u) {
        ret = WH_ERROR_ABORTED;
        (void)memset(dst, 0, size);
    }
    WT_FLASH_ECCDETR |= WT_FLASH_ECCD;
    wt_flash_barrier();
    wt_irq_restore(primask);

    return ret;
}

static int wt_flash_wait_idle(void)
{
    uint32_t spins = 0u;

    while ((WT_FLASH_STATUS & (WT_FLASH_SR_BSY | WT_FLASH_SR_DBNE)) != 0u &&
            spins < WT_FLASH_IDLE_SPINS) {
        spins++;
    }
    return (spins < WT_FLASH_IDLE_SPINS) ? 0 : -1;
}

static void wt_flash_clear_errors(void)
{
    WT_FLASH_CCR = WT_FLASH_CCR_CLR_ALL;
}

static int wt_flash_check_errors(void)
{
    if ((WT_FLASH_STATUS & WT_FLASH_SR_ALL_ERR) != 0u) {
        if (g_wt_flash_first_err_sr == 0u) {
            g_wt_flash_first_err_sr = WT_FLASH_STATUS;
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
    if ((WT_FLASH_CR & WT_FLASH_CR_LOCK) != 0u) {
        WT_FLASH_KEYR = WT_FLASH_KEY1;
        wt_flash_barrier();
        WT_FLASH_KEYR = WT_FLASH_KEY2;
        wt_flash_barrier();
        while ((WT_FLASH_CR & WT_FLASH_CR_LOCK) != 0u &&
                spins < WT_FLASH_IDLE_SPINS) {
            spins++;
        }
    }
    return ((WT_FLASH_CR & WT_FLASH_CR_LOCK) == 0u) ? 0 : -1;
}

static void wt_flash_lock(void)
{
    (void)wt_flash_wait_idle();
    if ((WT_FLASH_CR & WT_FLASH_CR_LOCK) == 0u) {
        WT_FLASH_CR |= WT_FLASH_CR_LOCK;
    }
}

/* The H563 ICACHE caches data reads from flash too, so a read-back of a
 * just-programmed unit can hit the stale pre-program line; RM0481 requires
 * an invalidate whenever flash content changes under an enabled ICACHE. */
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
        /* Still busy past the bound: the cache may hold the old content. */
        if ((WT_ICACHE_SR & WT_ICACHE_SR_BUSYF) != 0u) {
            ret = -1;
        }
    }
    return ret;
}

/* One quad-word per step, with interrupts held off for the step so no
 * handler can touch the controller between the four strobes. */
static int wt_flash_program_unit(uintptr_t dst, const uint8_t *src)
{
    uint32_t word[4];
    uint32_t primask;
    uint32_t i;
    int ret;

    (void)memcpy(word, src, sizeof(word));
    primask = wt_irq_save();
    WT_FLASH_CR |= WT_FLASH_CR_PG;
    for (i = 0u; i < 4u; i++) {
        WT_FLASH_WR32(dst + 4u * i, word[i]);
        wt_flash_barrier();
    }
    ret = (wt_flash_wait_idle() == 0) ? WH_ERROR_OK : WH_ERROR_ABORTED;
    if ((WT_FLASH_STATUS & WT_FLASH_SR_EOP) != 0u) {
        WT_FLASH_CCR = WT_FLASH_SR_EOP;
    }
    WT_FLASH_CR &= ~WT_FLASH_CR_PG;
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
    WT_FLASH_CR &= ~WT_FLASH_CR_PG;
    wt_flash_lock();
    if (wt_flash_icache_invalidate() != 0 && ret == WH_ERROR_OK) {
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

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
        uint32_t sector = (uint32_t)((ns_addr - WT_FLASH_NS_BASE) /
                                     WT_FLASH_SECTOR_SIZE);
        uint32_t sector_in_bank = sector;
        uint32_t primask;
        uint32_t cr;

        if (ns_addr >= WT_FLASH_BANK2_BASE_NS && ns_addr <= WT_FLASH_TOP_NS) {
            sector_in_bank = sector - WT_FLASH_BANK_SECTORS;
        }
        primask = wt_irq_save();
        cr = WT_FLASH_CR & ~((WT_FLASH_CR_PNB_MASK << WT_FLASH_CR_PNB_SHIFT) |
                             WT_FLASH_CR_SER | WT_FLASH_CR_BER |
                             WT_FLASH_CR_PG | WT_FLASH_CR_MER |
                             WT_FLASH_CR_BKSEL);
        cr |= (sector_in_bank << WT_FLASH_CR_PNB_SHIFT) | WT_FLASH_CR_SER |
              (wt_flash_bank(ns_addr) != 0u ? WT_FLASH_CR_BKSEL : 0u);
        WT_FLASH_CR = cr;
        wt_flash_barrier();
        WT_FLASH_CR |= WT_FLASH_CR_STRT;
        ret = (wt_flash_wait_idle() == 0) ? WH_ERROR_OK : WH_ERROR_ABORTED;
        if (ret == WH_ERROR_OK) {
            ret = wt_flash_check_errors();
        }
        wt_irq_restore(primask);
        start += WT_FLASH_SECTOR_SIZE;
    }
    WT_FLASH_CR &= ~WT_FLASH_CR_SER;
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
int wt_port_flash_probe_tamper(uintptr_t ns_addr)
{
    uint8_t block[WT_FLASH_PROGRAM_UNIT];
    uintptr_t s_addr = WT_FLASH_TO_S_ALIAS(ns_addr);
    int ret;

    if ((ns_addr % WT_FLASH_SECTOR_SIZE) != 0u) {
        return WH_ERROR_BADARGS;
    }
    ret = wt_port_flash_erase(s_addr, WT_FLASH_SECTOR_SIZE);
    if (ret == WH_ERROR_OK) {
        (void)memset(block, 0x00, sizeof(block));
        ret = wt_port_flash_program(s_addr, block, (uint32_t)sizeof(block));
    }
    return ret;
}
#endif
