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

/* Host suite for port/stm32l562/gtzc.c: the boot attribution and its
 * read-back over a GTZC model whose registers can refuse a write. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memory_map.h"
#include "gtzc.h"

static int checks;
static int failures;

#define EXPECT(cond, what) \
    do { \
        checks++; \
        if (!(cond)) { \
            (void)fprintf(stderr, "line %d: %s\n", __LINE__, (what)); \
            failures++; \
        } \
    } while (0)

#define M1_WORDS 24u
#define M2_WORDS 8u

/* Register state, the cells the driver writes, and per-bit faults: a stuck
 * bit always reads 1, a dead bit always reads 0. */
static uint32_t g_m1[M1_WORDS];
static uint32_t g_m2[M2_WORDS];
static volatile uint32_t g_c1[M1_WORDS];
static volatile uint32_t g_c2[M2_WORDS];
static uint32_t g_stuck1[M1_WORDS];
static uint32_t g_seccfgr2;
static volatile uint32_t g_c_seccfgr2;
static uint32_t g_seccfgr2_stuck;
static uint32_t g_seccfgr2_dead;
static uint32_t g_ahb1enr;
static volatile uint32_t g_c_ahb1enr;
static uint32_t g_ccr[16];
static volatile uint32_t g_c_ccr[16];
static uint32_t g_ccr_dead[16];
static volatile uint32_t g_scratch;
static uint32_t g_unknown_regs;

static void commit(void)
{
    uint32_t i;

    for (i = 0u; i < M1_WORDS; i++) {
        g_m1[i] = g_c1[i] | g_stuck1[i];
        g_c1[i] = g_m1[i];
    }
    for (i = 0u; i < M2_WORDS; i++) {
        g_m2[i] = g_c2[i];
    }
    g_seccfgr2 = (g_c_seccfgr2 | g_seccfgr2_stuck) & ~g_seccfgr2_dead;
    g_c_seccfgr2 = g_seccfgr2;
    g_ahb1enr = g_c_ahb1enr;
    for (i = 0u; i < 16u; i++) {
        g_ccr[i] = g_c_ccr[i] & ~g_ccr_dead[i];
        g_c_ccr[i] = g_ccr[i];
    }
}

volatile uint32_t* wt_mock_mpcbb(int controller)
{
    commit();
    return (controller == 1) ? g_c1 : g_c2;
}

volatile uint32_t* wt_mock_reg(uintptr_t address)
{
    uint32_t ch;

    commit();
    if (address == (uintptr_t)WT_GTZC_TZSC_BASE_S + 0x14u) {
        return &g_c_seccfgr2;
    }
    if (address == (uintptr_t)WT_RCC_BASE_S + 0x48u) {
        return &g_c_ahb1enr;
    }
    for (ch = 0u; ch < 8u; ch++) {
        if (address == (uintptr_t)WT_DMA1_BASE_S + 0x08u + 0x14u * ch) {
            return &g_c_ccr[ch];
        }
        if (address == (uintptr_t)WT_DMA2_BASE_S + 0x08u + 0x14u * ch) {
            return &g_c_ccr[8u + ch];
        }
    }
    g_unknown_regs++;
    return &g_scratch;
}

static void reset(void)
{
    (void)memset((void*)g_c1, 0, sizeof(g_c1));
    (void)memset((void*)g_c2, 0, sizeof(g_c2));
    (void)memset(g_stuck1, 0, sizeof(g_stuck1));
    g_c_seccfgr2 = 0u;
    g_seccfgr2_stuck = 0u;
    g_seccfgr2_dead = 0u;
    g_c_ahb1enr = 0u;
    (void)memset((void*)g_c_ccr, 0, sizeof(g_c_ccr));
    (void)memset(g_ccr_dead, 0, sizeof(g_ccr_dead));
    g_c_ccr[3] = WT_DMA_CCR_EN;
    commit();
}

static int block_secure(uintptr_t address)
{
    uint32_t block;

    if (address >= WT_GTZC_SRAM2_BASE) {
        block = (uint32_t)((address - WT_GTZC_SRAM2_BASE) / 256u);
        return (g_m2[block / 32u] >> (block % 32u)) & 1u;
    }
    block = (uint32_t)((address - WT_GTZC_SRAM1_BASE) / 256u);
    return (g_m1[block / 32u] >> (block % 32u)) & 1u;
}

int main(void)
{
    const uintptr_t guest_end = WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE;
    const uint32_t first_guest = (uint32_t)((WT_RAM_NS_BASE -
                                             WT_GTZC_SRAM1_BASE) / 256u);
    uintptr_t a;
    int spm_ok = 1;
    int guests_ok = 1;
    int dma_ok;
    uint32_t ch;

    reset();
    EXPECT(wt_l5_gtzc_init() == 0, "the boot attribution reads back");
    commit();
    for (a = WT_GTZC_SRAM1_BASE; a < WT_RAM_NS_BASE; a += 256u) {
        spm_ok &= block_secure(a);
    }
    for (a = WT_RAM_NS_BASE; a < guest_end; a += 256u) {
        guests_ok &= !block_secure(a);
    }
    EXPECT(spm_ok, "the SPM's SRAM below the guests is Secure");
    EXPECT(guests_ok, "every guest RAM block is Non-secure");
    EXPECT((g_seccfgr2 & WT_GTZC_SECCFGR2_USART1SEC) == 0u &&
           (g_seccfgr2 & WT_GTZC_SECCFGR2_RNGSEC) != 0u &&
           (g_seccfgr2 & WT_GTZC_SECCFGR2_SDMMC1SEC) != 0u,
           "USART1 is Non-secure, the RNG and the SDMMC1 bus master Secure");
    EXPECT((g_ahb1enr & WT_RCC_AHB1ENR_GTZCEN) != 0u, "the GTZC clock is on");
    dma_ok = 1;
    for (ch = 0u; ch < 16u; ch++) {
        dma_ok &= (g_ccr[ch] == (WT_DMA_CCR_SECM | WT_DMA_CCR_PRIV));
    }
    EXPECT(dma_ok, "every DMA channel is disabled, Secure and privileged");

    reset();
    g_stuck1[first_guest / 32u] = 1u << (first_guest % 32u);
    EXPECT(wt_l5_gtzc_init() != 0,
           "a guest RAM block that stays Secure fails the read-back");

    reset();
    g_seccfgr2_stuck = WT_GTZC_SECCFGR2_USART1SEC;
    EXPECT(wt_l5_gtzc_init() != 0,
           "a USART1SEC that stays set fails the read-back");

    reset();
    g_ccr_dead[12] = WT_DMA_CCR_SECM;
    EXPECT(wt_l5_gtzc_init() != 0,
           "a DMA channel that stays Non-secure fails the read-back");

    reset();
    g_seccfgr2_dead = WT_GTZC_SECCFGR2_RNGSEC;
    EXPECT(wt_l5_gtzc_init() != 0,
           "an SPM peripheral that stays Non-secure fails the read-back");

    reset();
    g_seccfgr2_dead = WT_GTZC_SECCFGR2_SDMMC1SEC;
    EXPECT(wt_l5_gtzc_init() != 0,
           "an SDMMC1 that stays Non-secure fails the read-back");

    EXPECT(g_unknown_regs == 0u, "only RCC AHB1ENR, TZSC SECCFGR2 and the DMA CCRs were used");
    (void)printf("stm32l562 gtzc: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
