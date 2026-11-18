/* rng_drv.c
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

/* The STM32L562 RNG on HSI48, driven directly, behind the shared entropy
 * callback. */

#include <stdint.h>

#include "rng_port.h"
#include "stm32l562_regs.h"
#include "wolftrust/zeroize.h"

#define WT_RNG_SPINS 0x00100000u
/* SEIS and CEIS stay latched after a seed or clock fault recovers (RM0438). */
#define WT_RNG_SR_ERRORS (WT_RNG_SR_SECS | WT_RNG_SR_CECS | \
                          WT_RNG_SR_SEIS | WT_RNG_SR_CEIS)

static int wt_rng_wait_ready(void)
{
    uint32_t spins = 0u;
    uint32_t status = WT_RNG_SR;

    while ((status & WT_RNG_SR_DRDY) == 0u && spins < WT_RNG_SPINS &&
            (status & WT_RNG_SR_ERRORS) == 0u) {
        ++spins;
        status = WT_RNG_SR;
    }
    return ((status & WT_RNG_SR_ERRORS) == 0u &&
            (status & WT_RNG_SR_DRDY) != 0u) ? 0 : -1;
}

/* A seed or clock error can race the status poll, so every word re-checks
 * SR after the read before it is served (RM0438). */
static int wt_rng_read_word(uint32_t* word)
{
    int ret = wt_rng_wait_ready();

    if (ret == 0) {
        *word = WT_RNG_DR;
        if ((WT_RNG_SR & WT_RNG_SR_ERRORS) != 0u) {
            *word = 0u;
            ret = -1;
        }
    }
    return ret;
}

int wt_port_rng_init(void)
{
    uint32_t discard = 0u;
    uint32_t spins = 0u;
    int ret;

    WT_RCC_CRRCR |= WT_RCC_CRRCR_HSI48ON;
    while ((WT_RCC_CRRCR & WT_RCC_CRRCR_HSI48RDY) == 0u &&
            spins < WT_RNG_SPINS) {
        ++spins;
    }
    if ((WT_RCC_CRRCR & WT_RCC_CRRCR_HSI48RDY) == 0u) {
        return -1;
    }
    /* CLK48MSEL 00 clocks the RNG from HSI48. */
    WT_RCC_CCIPR1 &= ~WT_RCC_CCIPR1_CLK48MSEL_MASK;
    WT_RCC_AHB2ENR |= WT_RCC_AHB2ENR_RNGEN;
    (void)WT_RCC_AHB2ENR;

    /* The configuration and HTCR are written while CONDRST holds the reset. */
    WT_RNG_CR = WT_RNG_CR_CONFIG_48MHZ | WT_RNG_CR_CONDRST;
    WT_RNG_HTCR = WT_RNG_HTCR_KEY;
    WT_RNG_HTCR = WT_RNG_HTCR_48MHZ;
    WT_RNG_CR = WT_RNG_CR_CONFIG_48MHZ | WT_RNG_CR_RNGEN;
    spins = 0u;
    while ((WT_RNG_CR & WT_RNG_CR_CONDRST) != 0u && spins < WT_RNG_SPINS) {
        ++spins;
    }
    /* The first word after enable is discarded, as RM0438 advises. */
    ret = wt_rng_read_word(&discard);
    wt_forceZero(&discard, sizeof(discard));
    return ret;
}

int wt_port_rng_fill(unsigned char* out, unsigned int sz)
{
    unsigned int done = 0u;
    unsigned int i;
    uint32_t word = 0u;
    int ret = 0;

    while (ret == 0 && done < sz) {
        ret = wt_rng_read_word(&word);
        for (i = 0u; ret == 0 && i < 4u && done < sz; ++i, ++done) {
            out[done] = (unsigned char)(word >> (i * 8u));
        }
    }
    wt_forceZero(&word, sizeof(word));
    return ret;
}
