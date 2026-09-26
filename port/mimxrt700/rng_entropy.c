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

#include "mimxrt798_regs.h"

#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/arch.h"

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

#define WT_TRNG_ENT_SPINS 0x00200000u

static bool s_rng_ready;

/* A latched ERR voids the source even while an older page is still valid. */
static int wt_trng_wait_page(void)
{
    uint32_t spins = 0u;
    uint32_t mctl = WT_TRNG_MCTL;

    while ((mctl & (WT_TRNG_MCTL_ENT_VAL | WT_TRNG_MCTL_ERR)) == 0u &&
            spins < WT_TRNG_ENT_SPINS) {
        ++spins;
        mctl = WT_TRNG_MCTL;
    }
    if ((mctl & WT_TRNG_MCTL_ERR) != 0u ||
            (mctl & WT_TRNG_MCTL_ENT_VAL) == 0u) {
        return -1;
    }
    return 0;
}

static int wt_trng_init(void)
{
    /* Leave the ROM's ring-oscillator tuning in place; a generation is
     * requested by dropping PRGM and waiting for the entropy-valid flag. */
    WT_TRNG_MCTL &= ~WT_TRNG_MCTL_PRGM;
    return wt_trng_wait_page();
}

/* Every page is read whole: reading its last word starts the next
 * generation, so words a request does not use are dropped, never served to
 * a later request. */
static int wt_trng_fill(unsigned char *output, unsigned int sz)
{
    uint32_t page[WT_TRNG_ENT_COUNT];
    volatile uint32_t* wipe = page;
    unsigned int done = 0u;
    unsigned int chunk;
    unsigned int i;
    int ret = 0;

    while (ret == 0 && done < sz) {
        ret = wt_trng_wait_page();
        if (ret == 0) {
            for (i = 0u; i < WT_TRNG_ENT_COUNT; ++i) {
                page[i] = WT_TRNG_ENT(i);
            }
            chunk = sz - done;
            if (chunk > (unsigned int)sizeof(page)) {
                chunk = (unsigned int)sizeof(page);
            }
            (void)memcpy(output + done, page, chunk);
            done += chunk;
        }
    }
    for (i = 0u; i < WT_TRNG_ENT_COUNT; ++i) {
        wipe[i] = 0u;
    }
    return ret;
}

int wolftrust_rng_generate_block_direct(unsigned char *output, unsigned int sz)
{
    if (output == NULL && sz != 0u) {
        return -1;
    }
    if (!s_rng_ready) {
        if (wt_trng_init() != 0) {
            return -1;
        }
        s_rng_ready = true;
    }
    if (sz == 0u) {
        return 0;
    }
    return wt_trng_fill(output, sz);
}

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz)
{
    /* A confined keystore partition cannot touch the TRNG; the SVC
     * dispatcher runs the direct half privileged. */
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
