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

/* Host suite for port/stm32l562/rng_entropy.c over an RCC and RNG model: a
 * SECS or CECS error, or a DRDY that never comes, latches the source shut, so
 * each case runs in its own process. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

enum { R_CRRCR, R_CCIPR1, R_AHB2ENR, R_CR, R_SR, R_DR, R_HTCR, R_COUNT };

static const uintptr_t g_reg_addr[R_COUNT] = {
    (uintptr_t)WT_RCC_BASE_S + 0x98u,
    (uintptr_t)WT_RCC_BASE_S + 0x88u,
    (uintptr_t)WT_RCC_BASE_S + 0x4Cu,
    (uintptr_t)WT_RNG_BASE_S + 0x00u,
    (uintptr_t)WT_RNG_BASE_S + 0x04u,
    (uintptr_t)WT_RNG_BASE_S + 0x08u,
    (uintptr_t)WT_RNG_BASE_S + 0x10u,
};

/* RNG_CR[29:4] is configuration, applied only under CONDRST (RM0438) */
#define CR_CFG_MASK  0x3FFFFFF0u

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

/* A register access hands the driver a cell; whatever it stored there is
 * applied on the next access, before anything is read. */
static volatile uint32_t g_cell[R_COUNT];
static uint32_t g_shown[R_COUNT];
static volatile uint32_t g_scratch;

static uint32_t g_crrcr;
static uint32_t g_hsi48_polls;
static uint32_t g_ccipr1 = WT_RCC_CCIPR1_CLK48MSEL_MASK;
static uint32_t g_ahb2enr;
static uint32_t g_cr = 0x00871F00u;
static uint32_t g_cfg = 0x00871F00u;
static uint32_t g_htcr = 0x000072ACu;
static uint32_t g_bad_cfg_writes;
static int g_htcr_keyed;
/* Knob: the next DR read returns zero, 1 with a racing seed error, 2 as
 * a genuine zero word */
static int g_zero_race;
static uint32_t g_condrst_polls;
static int g_conditioned;
static uint32_t g_words;
static uint32_t g_dr_reads;
static uint32_t g_bad_dr_reads;
static uint32_t g_condrst_writes;
static uint32_t g_unknown_regs;

/* Knobs. */
static int g_hsi48_dead;
static uint32_t g_fault_bits;
/* SEIS and CEIS: latched in SR beside DRDY, and set by a DR read on demand. */
static uint32_t g_sticky_bits;
static uint32_t g_sticky_on_dr;

static int g_unpriv;
static int g_gate_calls;
static int g_gate_reject;

static int running(void)
{
    return (g_crrcr & WT_RCC_CRRCR_HSI48RDY) != 0u &&
           (g_ccipr1 & WT_RCC_CCIPR1_CLK48MSEL_MASK) == 0u &&
           (g_ahb2enr & WT_RCC_AHB2ENR_RNGEN) != 0u &&
           (g_cr & WT_RNG_CR_RNGEN) != 0u && g_conditioned != 0 &&
           (g_cr & WT_RNG_CR_CONDRST) == 0u &&
           g_cfg == WT_RNG_CR_CONFIG_48MHZ && g_htcr == WT_RNG_HTCR_48MHZ &&
           g_bad_cfg_writes == 0u;
}

static uint32_t readable(int r)
{
    switch (r) {
        case R_CRRCR:
            return g_crrcr;
        case R_CCIPR1:
            return g_ccipr1;
        case R_AHB2ENR:
            return g_ahb2enr;
        case R_CR:
            return g_cr;
        case R_HTCR:
            return g_htcr;
        case R_SR:
            return g_fault_bits | g_sticky_bits |
                   ((running() && g_fault_bits == 0u) ?
                    WT_RNG_SR_DRDY : 0u);
        case R_DR:
            if (running() && g_fault_bits == 0u) {
                return 0xA5000000u | (g_words + 1u);
            }
            return 0u;
        default:
            return 0u;
    }
}

static void apply_write(int r, uint32_t v)
{
    switch (r) {
        case R_CRRCR:
            g_crrcr = (g_crrcr & WT_RCC_CRRCR_HSI48RDY) |
                      (v & WT_RCC_CRRCR_HSI48ON);
            if ((v & WT_RCC_CRRCR_HSI48ON) != 0u && g_hsi48_dead == 0) {
                g_hsi48_polls = 2u;
            }
            break;
        case R_CCIPR1:
            g_ccipr1 = v;
            break;
        case R_AHB2ENR:
            g_ahb2enr = v;
            break;
        case R_CR:
            if ((v & WT_RNG_CR_CONDRST) != 0u) {
                g_condrst_writes++;
                g_conditioned = 0;
                g_cfg = v & CR_CFG_MASK;
                g_cr = v;
            }
            else if ((v & CR_CFG_MASK) != g_cfg) {
                g_bad_cfg_writes++;
                g_cr = v;
            }
            else if ((g_cr & WT_RNG_CR_CONDRST) != 0u) {
                /* Clearing CONDRST starts conditioning; it reads back set
                 * until the reset completes. */
                g_cr = v | WT_RNG_CR_CONDRST;
                g_condrst_polls = 2u;
            }
            else {
                g_cr = v;
            }
            break;
        case R_HTCR:
            if (v == WT_RNG_HTCR_KEY) {
                g_htcr_keyed = 1;
            }
            else if (g_htcr_keyed != 0 &&
                     (g_cr & WT_RNG_CR_CONDRST) != 0u) {
                g_htcr = v;
                g_htcr_keyed = 0;
            }
            else {
                g_bad_cfg_writes++;
            }
            break;
        default:
            break;
    }
}

volatile uint32_t* wt_mock_reg(uintptr_t address)
{
    int good_read = 0;
    int zero_now = 0;
    int r;
    int i;

    for (r = 0; r < R_COUNT; r++) {
        if (g_reg_addr[r] == address) {
            break;
        }
    }
    if (r == R_COUNT) {
        g_unknown_regs++;
        return &g_scratch;
    }
    for (i = 0; i < R_COUNT; i++) {
        if (g_cell[i] != g_shown[i]) {
            apply_write(i, g_cell[i]);
        }
    }
    if (r == R_CRRCR && g_hsi48_polls != 0u && --g_hsi48_polls == 0u) {
        g_crrcr |= WT_RCC_CRRCR_HSI48RDY;
    }
    if (r == R_CR && g_condrst_polls != 0u && --g_condrst_polls == 0u) {
        g_cr &= ~WT_RNG_CR_CONDRST;
        g_conditioned = 1;
    }
    if (r == R_DR) {
        g_dr_reads++;
        g_sticky_bits |= g_sticky_on_dr;
        g_sticky_on_dr = 0u;
        if (g_zero_race != 0) {
            zero_now = 1;
        }
        else {
            good_read = readable(R_DR) != 0u;
            if (!good_read) {
                g_bad_dr_reads++;
            }
        }
    }
    for (i = 0; i < R_COUNT; i++) {
        g_shown[i] = readable(i);
        g_cell[i] = g_shown[i];
    }
    if (zero_now != 0) {
        if (g_zero_race == 1) {
            g_fault_bits |= WT_RNG_SR_SECS;
        }
        g_zero_race = 0;
        for (i = 0; i < R_COUNT; i++) {
            g_shown[i] = readable(i);
            g_cell[i] = g_shown[i];
        }
        g_shown[R_DR] = 0u;
        g_cell[R_DR] = 0u;
        g_words++;
    }
    if (good_read) {
        g_words++;
    }
    return &g_cell[r];
}

int wt_arch_thread_unprivileged(void)
{
    return g_unpriv;
}

/* SVC dispatcher stand-in: runs the direct half with privilege. */
int wt_spm_sp_call(struct wt_spm_call *call)
{
    g_gate_calls++;
    if (call->op != WT_SPM_OP_KEYSTORE_ENTROPY || g_gate_reject != 0) {
        return -1;
    }
    g_unpriv = 0;
    call->ret_int = wolftrust_rng_generate_block_direct(
        (unsigned char *)call->buffer, (unsigned int)call->num_bytes);
    g_unpriv = 1;
    return WT_FFM_SUCCESS;
}

/* out[0..len) must be the words starting at word number first. */
static int served_from(const unsigned char *out, unsigned int len,
                       uint32_t first)
{
    uint32_t w;
    unsigned int i;

    for (i = 0u; i < len; ++i) {
        w = 0xA5000000u | (first + i / 4u);
        if (out[i] != (unsigned char)(w >> (8u * (i % 4u)))) {
            return 0;
        }
    }
    return 1;
}

static void test_default(void)
{
    unsigned char out[40];
    uint32_t before;

    EXPECT(wolftrust_rng_generate_block(NULL, 4u) != 0,
           "a request without a buffer is refused");
    EXPECT(g_dr_reads == 0u && g_condrst_writes == 0u,
           "the refusal did not touch the RNG");
    EXPECT(wolftrust_rng_generate_block(NULL, 0u) == 0,
           "an empty request needs no buffer and does not latch");

    memset(out, 0, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, 10u) == 0,
           "the first request initialises the RNG and serves");
    EXPECT((g_crrcr & (WT_RCC_CRRCR_HSI48ON | WT_RCC_CRRCR_HSI48RDY)) ==
           (WT_RCC_CRRCR_HSI48ON | WT_RCC_CRRCR_HSI48RDY),
           "HSI48 was switched on and came ready");
    EXPECT((g_ccipr1 & WT_RCC_CCIPR1_CLK48MSEL_MASK) == 0u,
           "CLK48MSEL selects HSI48");
    EXPECT((g_ahb2enr & WT_RCC_AHB2ENR_RNGEN) != 0u,
           "the RNG bus clock is on");
    EXPECT(g_condrst_writes == 1u && g_conditioned != 0,
           "the RNG took one conditioning reset");
    EXPECT(g_cfg == WT_RNG_CR_CONFIG_48MHZ && g_htcr == WT_RNG_HTCR_48MHZ &&
           g_bad_cfg_writes == 0u,
           "CR and HTCR took AN4230's 48 MHz setting under CONDRST");
    EXPECT(served_from(out, 10u, 2u),
           "the first word after enable was discarded");
    EXPECT(g_words == 4u, "the discard and three served words were read");
    EXPECT(out[10] == 0u, "no byte past the request was written");
    EXPECT(g_bad_dr_reads == 0u, "DR was never read without DRDY");

    before = g_words;
    memset(out, 0, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "a second request serves");
    EXPECT(g_condrst_writes == 1u, "the RNG is initialised only once");
    EXPECT(g_words == before + 10u, "40 bytes take ten fresh words");
    EXPECT(served_from(out, sizeof(out), before + 1u),
           "unused bytes of an earlier word are never served");

    /* A confined partition reaches the RNG through the SVC gate. */
    g_unpriv = 1;
    before = g_words;
    memset(out, 0, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, 8u) == 0 && g_gate_calls == 1,
           "an unprivileged request crosses the gate");
    EXPECT(served_from(out, 8u, before + 1u),
           "and the privileged half served it");
    g_gate_reject = 1;
    before = g_dr_reads;
    EXPECT(wolftrust_rng_generate_block(out, 8u) != 0 &&
           g_dr_reads == before, "a refused gate serves nothing");
    g_unpriv = 0;
    g_gate_reject = 0;
    EXPECT(g_unknown_regs == 0u, "no unmodelled register was touched");
}

/* A seed error mid-stream fails the request and every later one. */
/* DRDY was seen, then the seed error won the race and DR reads zero. */
static void test_zero(void)
{
    unsigned char out[16];
    uint32_t before;

    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "the RNG serves before the race");
    g_zero_race = 1;
    (void)memset(out, 0x5A, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a zero DR after DRDY fails the request");
    EXPECT(out[0] == 0x5Au && out[1] == 0x5Au && out[2] == 0x5Au &&
           out[3] == 0x5Au, "the zero word was not served");
    before = g_dr_reads;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0 &&
           g_dr_reads == before, "the source stays shut after the race");
}

/* A genuine zero word is served, and the source keeps serving. */
static void test_zerovalid(void)
{
    unsigned char out[8];

    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "the RNG serves before the zero word");
    g_zero_race = 2;
    (void)memset(out, 0x5A, sizeof(out));
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0 &&
           out[0] == 0u && out[1] == 0u && out[2] == 0u && out[3] == 0u,
           "a zero word with SECS and CECS clear is served");
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "the source keeps serving after a zero word");
}

/* The discarded first word after enable races too. */
static void test_zeroinit(void)
{
    unsigned char out[8];

    g_zero_race = 1;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a zero first word fails initialisation");
    g_zero_race = 0;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "and latches the source shut");
}

static void test_seed(void)
{
    unsigned char out[16];
    uint32_t before;

    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "the RNG serves before the seed error");
    g_fault_bits = WT_RNG_SR_SECS;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a seed error fails the request");
    g_fault_bits = 0u;
    before = g_dr_reads;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "the source stays shut after the seed error clears");
    EXPECT(g_dr_reads == before, "no word is read after the latch");
    EXPECT(g_bad_dr_reads == 0u, "DR was never read without DRDY");
}

/* SEIS and CEIS stay latched after the fault clears; a nonzero word read
 * while either is set is never served. */
static void test_sticky(int on_read)
{
    unsigned char out[16];
    unsigned int i;
    int served = 0;

    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) == 0,
           "the RNG serves before the sticky error");
    (void)memset(out, 0, sizeof(out));
    if (on_read != 0) {
        g_sticky_on_dr = WT_RNG_SR_CEIS;
    }
    else {
        g_sticky_bits = WT_RNG_SR_SEIS;
    }
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           on_read ? "a nonzero word read as CEIS latches is not served" :
                     "SEIS beside DRDY fails the request");
    for (i = 0u; i < sizeof(out); i++) {
        served |= (out[i] != 0u);
    }
    EXPECT(served == 0, "no byte of the failed request reached the caller");
    g_sticky_bits = 0u;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "the source stays shut after a sticky error");
}

/* A clock error during init fails it and latches the source. */
static void test_clock(void)
{
    unsigned char out[16];

    g_fault_bits = WT_RNG_SR_CECS;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "a clock error fails the first request");
    EXPECT(g_dr_reads == 0u, "the discarded first word was never read");
    g_fault_bits = 0u;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "the source stays shut once the clock recovers");
    EXPECT(g_condrst_writes == 1u, "the failed RNG is not reinitialised");
    EXPECT(g_dr_reads == 0u, "no word is ever read");
}

/* HSI48 never comes ready, so DRDY never comes: the spins run out. */
static void test_timeout(void)
{
    unsigned char out[16];

    g_hsi48_dead = 1;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "an RNG without its kernel clock times out");
    EXPECT(g_dr_reads == 0u, "no word was read from the stalled RNG");
    g_hsi48_dead = 0;
    g_crrcr |= WT_RCC_CRRCR_HSI48RDY;
    EXPECT(wolftrust_rng_generate_block(out, sizeof(out)) != 0,
           "the source stays shut after a timeout");
    EXPECT(g_dr_reads == 0u, "nothing is read after the latch");
}

int main(int argc, char **argv)
{
    const char *which = (argc > 1) ? argv[1] : "default";

    if (strcmp(which, "seed") == 0) {
        test_seed();
    }
    else if (strcmp(which, "clock") == 0) {
        test_clock();
    }
    else if (strcmp(which, "seis") == 0) {
        test_sticky(0);
    }
    else if (strcmp(which, "ceisread") == 0) {
        test_sticky(1);
    }
    else if (strcmp(which, "timeout") == 0) {
        test_timeout();
    }
    else if (strcmp(which, "zero") == 0) {
        test_zero();
    }
    else if (strcmp(which, "zeroinit") == 0) {
        test_zeroinit();
    }
    else if (strcmp(which, "zerovalid") == 0) {
        test_zerovalid();
    }
    else {
        test_default();
    }
    (void)printf("stm32l562 rng %s: %d checks, %d failures\n", which, checks,
                 failures);
    return failures == 0 ? 0 : 1;
}
