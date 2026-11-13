/* rng_entropy.c
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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "stm32l562_regs.h"

#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/arch.h"
#include "wolftrust/zeroize.h"

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

#define WT_RNG_SPINS 0x00100000u
/* SEIS and CEIS stay latched after a seed or clock fault recovers (RM0438). */
#define WT_RNG_SR_ERRORS (WT_RNG_SR_SECS | WT_RNG_SR_CECS | \
                          WT_RNG_SR_SEIS | WT_RNG_SR_CEIS)

static bool s_rng_ready;
/* A seed or clock error is latched: no later request is served. */
static bool s_rng_failed;

static int wt_rng_wait_ready(void)
{
    uint32_t spins = 0u;
    uint32_t status = WT_RNG_SR;

    while ((status & WT_RNG_SR_DRDY) == 0u && spins < WT_RNG_SPINS) {
        if ((status & WT_RNG_SR_ERRORS) != 0u) {
            break;
        }
        ++spins;
        status = WT_RNG_SR;
    }
    if ((status & WT_RNG_SR_ERRORS) != 0u ||
            (status & WT_RNG_SR_DRDY) == 0u) {
        s_rng_failed = true;
        return -1;
    }
    return 0;
}

/* A seed or clock error can race the status poll, so every word re-checks
 * SR after the read before it is served (RM0438). */
static int wt_rng_read_word(uint32_t *word)
{
    int ret = wt_rng_wait_ready();

    if (ret == 0) {
        *word = WT_RNG_DR;
        if ((WT_RNG_SR & WT_RNG_SR_ERRORS) != 0u) {
            *word = 0u;
            s_rng_failed = true;
            ret = -1;
        }
    }
    return ret;
}

static int wt_rng_init(void)
{
    uint32_t discard = 0u;
    uint32_t spins = 0u;
    int ret;

    WT_RCC_CRRCR |= WT_RCC_CRRCR_HSI48ON;
    while ((WT_RCC_CRRCR & WT_RCC_CRRCR_HSI48RDY) == 0u &&
            spins < WT_RNG_SPINS) {
        ++spins;
    }
    /* CLK48MSEL 00 clocks the RNG from HSI48. */
    WT_RCC_CCIPR1 &= ~WT_RCC_CCIPR1_CLK48MSEL_MASK;
    WT_RCC_AHB2ENR |= WT_RCC_AHB2ENR_RNGEN;
    (void)WT_RCC_AHB2ENR;

    /* The configuration and HTCR are written while CONDRST holds the reset */
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

int wolftrust_rng_generate_block_direct(unsigned char *output, unsigned int sz)
{
    unsigned int done = 0u;
    unsigned int i;
    uint32_t word = 0u;
    int ret = 0;

    if ((output == NULL && sz != 0u) || s_rng_failed) {
        return -1;
    }
    if (!s_rng_ready) {
        if (wt_rng_init() != 0) {
            return -1;
        }
        s_rng_ready = true;
    }
    while (ret == 0 && done < sz) {
        ret = wt_rng_read_word(&word);
        if (ret == 0) {
            for (i = 0u; i < 4u && done < sz; ++i, ++done) {
                output[done] = (unsigned char)(word >> (i * 8u));
            }
        }
    }
    wt_forceZero(&word, sizeof(word));
    return ret;
}

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz)
{
    /* A confined keystore partition cannot touch the RNG peripheral or its
     * clock; the SVC dispatcher runs the direct half privileged. */
    if (wt_arch_thread_unprivileged()) {
        wt_spm_call_t call;

        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_KEYSTORE_ENTROPY;
        call.buffer = output;
        call.num_bytes = sz;
        if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS) {
            return -1;
        }
        return call.ret_int;
    }
    return wolftrust_rng_generate_block_direct(output, sz);
}
