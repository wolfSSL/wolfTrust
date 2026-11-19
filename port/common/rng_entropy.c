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

/* The CUSTOM_RAND_GENERATE_BLOCK entropy source every port shares: the
 * privilege gate, the lazy init and the failure policy over the port's
 * rng_port.h source. */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "rng_port.h"
#include "wolftrust/arch.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/zeroize.h"

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

static bool s_rng_ready;
/* A request the source failed may still complete later (a DMA page, a
 * generation in flight), so the source is never asked again before reset. */
static bool s_rng_failed;

int wolftrust_rng_generate_block_direct(unsigned char *output, unsigned int sz)
{
    int ret = 0;

    if (output == NULL && sz != 0u) {
        return -1;
    }
    if (s_rng_failed) {
        ret = -1;
    }
    if (ret == 0 && !s_rng_ready) {
        if (wt_port_rng_init() != 0) {
            ret = -1;
        }
        else {
            s_rng_ready = true;
        }
    }
    if (ret == 0 && sz != 0u && wt_port_rng_fill(output, sz) != 0) {
        s_rng_failed = true;
        ret = -1;
    }
    if (ret != 0 && output != NULL && sz != 0u) {
        wt_forceZero(output, sz);
    }
    return ret;
}

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz)
{
    /* A confined keystore partition cannot touch the entropy source; the SVC
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
