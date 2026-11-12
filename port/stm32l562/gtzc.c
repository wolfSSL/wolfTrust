/* gtzc.c
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

#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "stm32l562_regs.h"
#include "gtzc.h"

#define WT_GTZC_SECCFGR2_SPM (WT_GTZC_SECCFGR2_AESSEC | \
                              WT_GTZC_SECCFGR2_HASHSEC | \
                              WT_GTZC_SECCFGR2_RNGSEC | \
                              WT_GTZC_SECCFGR2_PKASEC | \
                              WT_GTZC_SECCFGR2_SDMMC1SEC)

/* Locate the MPCBB vector word and bit that attribute one SRAM block. */
static volatile uint32_t* wt_gtzc_block(uintptr_t address, uint32_t* bit)
{
    uint32_t block;

    if (address >= WT_GTZC_SRAM2_BASE) {
        block = (uint32_t)((address - WT_GTZC_SRAM2_BASE) / WT_GTZC_BLOCK_SIZE);
        *bit = 1u << (block % 32u);
        return &WT_GTZC_MPCBB2_VCTR[block / 32u];
    }
    block = (uint32_t)((address - WT_GTZC_SRAM1_BASE) / WT_GTZC_BLOCK_SIZE);
    *bit = 1u << (block % 32u);
    return &WT_GTZC_MPCBB1_VCTR[block / 32u];
}

void wt_l5_gtzc_set_range(uintptr_t base, uintptr_t end, int secure)
{
    volatile uint32_t* word;
    uint32_t bit;
    uintptr_t address;

    for (address = base; address < end; address += WT_GTZC_BLOCK_SIZE) {
        word = wt_gtzc_block(address, &bit);
        if (secure != 0) {
            *word |= bit;
        }
        else {
            *word &= ~bit;
        }
    }
}

#define WT_DMA_CCR_SPM (WT_DMA_CCR_SECM | WT_DMA_CCR_PRIV)

/* The MPCBB curtain moves per dispatch, but a DMA master is not the CPU: a
 * transfer a guest armed could land in the next guest's window. Guests get no
 * DMA, so every channel is held disabled, Secure and privileged. */
static int wt_l5_dma_secure(void)
{
    static const uint32_t bases[2] = { WT_DMA1_BASE_S, WT_DMA2_BASE_S };
    uint32_t b;
    uint32_t ch;
    int ok = 1;

    WT_RCC_AHB1ENR |= WT_RCC_AHB1ENR_DMA1EN | WT_RCC_AHB1ENR_DMA2EN;
    (void)WT_RCC_AHB1ENR;
    for (b = 0u; b < 2u; ++b) {
        for (ch = 0u; ch < WT_DMA_CHANNELS; ++ch) {
            WT_DMA_CCR(bases[b], ch) = 0u;
            WT_DMA_CCR(bases[b], ch) = WT_DMA_CCR_SPM;
        }
    }
    for (b = 0u; b < 2u; ++b) {
        for (ch = 0u; ch < WT_DMA_CHANNELS; ++ch) {
            if ((WT_DMA_CCR(bases[b], ch) &
                    (WT_DMA_CCR_SPM | WT_DMA_CCR_EN)) != WT_DMA_CCR_SPM) {
                ok = 0;
            }
        }
    }
    return ok;
}

/* WT-FFM-0068: read the whole attribution back, so a register that did not
 * take halts boot: the SPM's peripherals and SRAM must be Secure, the guest
 * RAM and the shared console Non-secure. */
static int wt_gtzc_attribution_ok(void)
{
    volatile uint32_t* word;
    uint32_t bit;
    uintptr_t address;
    uintptr_t guest_end = WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE;

    if ((WT_GTZC_TZSC_SECCFGR2 & WT_GTZC_SECCFGR2_SPM) !=
            WT_GTZC_SECCFGR2_SPM ||
            (WT_GTZC_TZSC_SECCFGR2 & WT_GTZC_SECCFGR2_USART1SEC) != 0u) {
        return 0;
    }
    for (address = WT_GTZC_SRAM1_BASE; address < guest_end;
            address += WT_GTZC_BLOCK_SIZE) {
        word = wt_gtzc_block(address, &bit);
        if (((*word & bit) != 0u) != (address < WT_RAM_NS_BASE)) {
            return 0;
        }
    }
    return 1;
}

int wt_l5_gtzc_init(void)
{
    uint32_t i;

    WT_RCC_AHB1ENR |= WT_RCC_AHB1ENR_GTZCEN;
    (void)WT_RCC_AHB1ENR;

    for (i = 0u; i < WT_GTZC_MPCBB1_WORDS; ++i) {
        WT_GTZC_MPCBB1_VCTR[i] = 0xFFFFFFFFu;
    }
    for (i = 0u; i < WT_GTZC_MPCBB2_WORDS; ++i) {
        WT_GTZC_MPCBB2_VCTR[i] = 0xFFFFFFFFu;
    }
    wt_l5_gtzc_set_range(WT_RAM_NS_BASE,
                         WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE, 0);

    WT_GTZC_TZSC_SECCFGR2 = (WT_GTZC_TZSC_SECCFGR2 &
                             ~WT_GTZC_SECCFGR2_USART1SEC) |
                            WT_GTZC_SECCFGR2_SPM;
    if (wt_l5_dma_secure() != 1) {
        return -1;
    }
    return (wt_gtzc_attribution_ok() == 1) ? 0 : -1;
}
