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

/* The MIMXRT700 TRNG behind the shared entropy callback. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mimxrt798_regs.h"
#include "rng_port.h"

#define WT_TRNG_ENT_SPINS 0x00200000u

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

int wt_port_rng_init(void)
{
    /* Leave the ROM's ring-oscillator tuning in place; a generation is
     * requested by dropping PRGM and waiting for the entropy-valid flag. */
    WT_TRNG_MCTL &= ~WT_TRNG_MCTL_PRGM;
    return wt_trng_wait_page();
}

/* Every page is read whole: reading its last word starts the next
 * generation, so words a request does not use are dropped, never served to
 * a later request. */
int wt_port_rng_fill(unsigned char *out, unsigned int sz)
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
            (void)memcpy(out + done, page, chunk);
            done += chunk;
        }
    }
    for (i = 0u; i < WT_TRNG_ENT_COUNT; ++i) {
        wipe[i] = 0u;
    }
    return ret;
}
