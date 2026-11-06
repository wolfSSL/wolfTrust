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

/* Entropy for the wolfCrypt DRBG on the QEMU machines, which model no
 * TRNG the Secure world can reach: a counter-seeded generator that is
 * explicitly a test source. Silicon ports must provide a real one. */

#if !defined(WT_QEMU_TEST_ENTROPY) || (WT_QEMU_TEST_ENTROPY != 1)
#error "the QEMU test entropy source is only for emulated targets"
#endif

#include "wolftrust/arch.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

static uint64_t s_state;

static uint64_t read_cntpct(void)
{
    uint64_t v;

    __asm__ volatile("isb\n\tmrs %0, CNTPCT_EL0" : "=r"(v));
    return v;
}

static uint64_t next_word(void)
{
    uint64_t x = s_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    s_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

int wolftrust_rng_generate_block_direct(unsigned char *output, unsigned int sz)
{
    unsigned int i;
    uint64_t word = 0u;

    if (output == NULL && sz != 0u) {
        return -1;
    }
    if (s_state == 0u) {
        s_state = read_cntpct() | 1u;
    }
    for (i = 0u; i < sz; i++) {
        if ((i % sizeof(word)) == 0u) {
            word = next_word() ^ read_cntpct();
        }
        output[i] = (unsigned char)(word >> (8u * (i % sizeof(word))));
    }
    return 0;
}

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz)
{
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
