/* board.c
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

/* STM32H563 peripheral probe (WT-FFM-0068) for the shared bare-metal guest:
 * a privileged Non-secure guest pokes the SPM's RNG through its Non-secure
 * alias, proves a Non-secure GPDMA copy works, then needs every copy out of
 * the Secure image and Secure SRAM refused with nothing landed. */

#include <stddef.h>
#include <stdint.h>

#include "board.h"

#if defined(WT_PERIPH_NEG_PROBE)

#define PERIPH_RNG_CR_NS     ((volatile uint32_t*)GUEST_PERIPH_NS_ADDR)
#define PERIPH_RNG_CR_IE     (1u << 3)
#define PERIPH_RCC_AHB1ENR   ((volatile uint32_t*)0x44020C88u)
#define PERIPH_GPDMA1_NS     0x40020000u
#define PERIPH_CH0(off)      ((volatile uint32_t*)(PERIPH_GPDMA1_NS + 0x50u + (off)))
#define PERIPH_SENTINEL      0xA5A5A5A5u
#define PERIPH_WORDS         4u

/* The runner layout's Secure image and the SPM's SRAM. */
#ifndef GUEST_PERIPH_SECURE_IMAGE
#define GUEST_PERIPH_SECURE_IMAGE 0x08060000u
#endif
#ifndef GUEST_PERIPH_SECURE_SRAM
#define GUEST_PERIPH_SECURE_SRAM  0x20030000u
#endif

#define PERIPH_SR_TCF        (1u << 8)
#define PERIPH_SR_DTEF       (1u << 10)
#define PERIPH_SR_ULEF       (1u << 11)
#define PERIPH_SR_USEF       (1u << 12)
#define PERIPH_SR_FLAGS      0x7F00u
#define PERIPH_SR_ERRORS     (PERIPH_SR_DTEF | PERIPH_SR_ULEF | PERIPH_SR_USEF)

#define PERIPH_VERDICT_BLOCKED      2
#define PERIPH_VERDICT_LEAKED       3
#define PERIPH_VERDICT_INCONCLUSIVE 4

enum {
    PERIPH_DMA_DENIED = 0,
    PERIPH_DMA_LEAKED = 1,
    PERIPH_DMA_INCONCLUSIVE = 2
};

static volatile uint32_t g_periph_src[PERIPH_WORDS];
static volatile uint32_t g_periph_dst[PERIPH_WORDS];

/* One word-wide copy on a freshly reset channel 0; returns the final status. */
static uint32_t periph_dma_copy(uint32_t src)
{
    uint32_t sr = 0u;
    uint32_t i;

    for (i = 0u; i < PERIPH_WORDS; i++) {
        g_periph_dst[i] = PERIPH_SENTINEL;
    }
    *PERIPH_CH0(0x14u) = 0u;
    *PERIPH_CH0(0x0Cu) = PERIPH_SR_FLAGS;
    *PERIPH_CH0(0x40u) = 2u | (1u << 3) | (2u << 16) | (1u << 19);
    *PERIPH_CH0(0x44u) = 1u << 9;
    *PERIPH_CH0(0x48u) = sizeof(g_periph_dst);
    *PERIPH_CH0(0x4Cu) = src;
    *PERIPH_CH0(0x50u) = (uint32_t)(uintptr_t)g_periph_dst;
    __asm volatile("dsb" ::: "memory");
    *PERIPH_CH0(0x14u) = 1u;
    for (i = 0u; i < 100000u; i++) {
        sr = *PERIPH_CH0(0x10u);
        if ((sr & (PERIPH_SR_TCF | PERIPH_SR_ERRORS)) != 0u) {
            break;
        }
    }
    *PERIPH_CH0(0x14u) = 0u;
    __asm volatile("dsb" ::: "memory");
    return sr;
}

/* The control copy between Non-secure buffers must complete exactly, or the
 * denials that follow would prove nothing about the DMA path. */
static int periph_dma_control_ok(void)
{
    uint32_t sr;
    uint32_t i;

    for (i = 0u; i < PERIPH_WORDS; i++) {
        g_periph_src[i] = 0x11223344u + i;
    }
    sr = periph_dma_copy((uint32_t)(uintptr_t)g_periph_src);
    if ((sr & PERIPH_SR_TCF) == 0u || (sr & PERIPH_SR_ERRORS) != 0u) {
        return 0;
    }
    for (i = 0u; i < PERIPH_WORDS; i++) {
        if (g_periph_dst[i] != g_periph_src[i]) {
            return 0;
        }
    }
    return 1;
}

/* Denial is a transfer error with nothing written or, where the source is
 * known to be nonzero, a completed copy of zeros; any other data leaked. */
static int periph_dma_secure_copy(uint32_t src, int zero_fill_ok)
{
    uint32_t sr;
    uint32_t i;
    int untouched = 1;
    int zeroed = 1;
    int rc = PERIPH_DMA_INCONCLUSIVE;

    sr = periph_dma_copy(src);
    for (i = 0u; i < PERIPH_WORDS; i++) {
        if (g_periph_dst[i] != PERIPH_SENTINEL) {
            untouched = 0;
        }
        if (g_periph_dst[i] != 0u) {
            zeroed = 0;
        }
        if (g_periph_dst[i] != PERIPH_SENTINEL && g_periph_dst[i] != 0u) {
            rc = PERIPH_DMA_LEAKED;
        }
    }
    if (rc != PERIPH_DMA_LEAKED) {
        if ((sr & PERIPH_SR_DTEF) != 0u && untouched != 0) {
            rc = PERIPH_DMA_DENIED;
        }
        else if (zero_fill_ok != 0 && (sr & PERIPH_SR_TCF) != 0u &&
                 zeroed != 0) {
            rc = PERIPH_DMA_DENIED;
        }
    }
    return rc;
}

int guest_board_periph_probe(void)
{
    int leaked = 0;
    int inconclusive = 0;
    int rc;

    *PERIPH_RCC_AHB1ENR |= 1u;
    if (*PERIPH_RNG_CR_NS != 0u) {
        leaked = 1;
    }
    /* A NS-writable alias reads back what NS wrote, whatever the Secure
     * side has CR set to; RAZ/WI reads 0. */
    *PERIPH_RNG_CR_NS = PERIPH_RNG_CR_IE;
    __asm volatile("dsb" ::: "memory");
    if ((*PERIPH_RNG_CR_NS & PERIPH_RNG_CR_IE) != 0u) {
        leaked = 1;
        *PERIPH_RNG_CR_NS = 0u;
    }
    if (periph_dma_control_ok() == 0) {
        inconclusive = 1;
    }
    else {
        /* The signed image header starts with nonzero magic. */
        rc = periph_dma_secure_copy(GUEST_PERIPH_SECURE_IMAGE, 1);
        leaked |= (rc == PERIPH_DMA_LEAKED);
        inconclusive |= (rc == PERIPH_DMA_INCONCLUSIVE);
        rc = periph_dma_secure_copy(GUEST_PERIPH_SECURE_SRAM, 0);
        leaked |= (rc == PERIPH_DMA_LEAKED);
        inconclusive |= (rc == PERIPH_DMA_INCONCLUSIVE);
    }
    if (leaked != 0) {
        return PERIPH_VERDICT_LEAKED;
    }
    if (inconclusive != 0) {
        return PERIPH_VERDICT_INCONCLUSIVE;
    }
    return PERIPH_VERDICT_BLOCKED;
}

#endif /* WT_PERIPH_NEG_PROBE */
