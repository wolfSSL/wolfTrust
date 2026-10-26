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

#include "mcxn947_regs.h"

#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/arch.h"

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

#define WT_ELS_SPINS      0x00200000u
#define WT_ELS_PAGE_WORDS 16u

static bool s_rng_ready;
/* A request that outlives its deadline may still complete by DMA, so the page
 * is static rather than stack and the engine is never asked again. */
static bool s_rng_failed;
static uint32_t s_els_page[WT_ELS_PAGE_WORDS]
    __attribute__((aligned(WT_ELS_RND_ALIGN)));
/* Read over the debug port by the hardware runner. */
volatile uint32_t g_wt_els_errors __attribute__((used));
volatile uint32_t g_wt_els_last_status __attribute__((used));
volatile uint32_t g_wt_els_last_err __attribute__((used));

static int wt_els_wait_idle(void)
{
    uint32_t spins = 0u;
    uint32_t status = WT_ELS_STATUS;

    while ((status & WT_ELS_STATUS_BUSY) != 0u && spins < WT_ELS_SPINS) {
        ++spins;
        status = WT_ELS_STATUS;
    }
    if ((status & (WT_ELS_STATUS_BUSY | WT_ELS_STATUS_ERR |
                   WT_ELS_STATUS_LOCKED)) != 0u) {
        g_wt_els_errors++;
        g_wt_els_last_status = status;
        g_wt_els_last_err = WT_ELS_ERR_STATUS;
        return -1;
    }
    return 0;
}

static int wt_els_init(void)
{
    WT_ELS_CTRL = WT_ELS_CTRL_EN;
    return wt_els_wait_idle();
}

/* One RND_REQ fills a whole page the ELS writes by DMA; words a request does
 * not use are wiped, never served to a later request. */
static int wt_els_rnd_page(uint32_t *page)
{
    int ret;

    ret = wt_els_wait_idle();
    if (ret == 0) {
        WT_ELS_DMA_RES0 = (uint32_t)(uintptr_t)page;
        WT_ELS_DMA_RES0_LEN = WT_ELS_PAGE_WORDS * (uint32_t)sizeof(uint32_t);
        WT_ELS_CMDCFG0 = 0u;
        WT_ELS_CTRL = WT_ELS_CTRL_EN | WT_ELS_CTRL_START |
                      WT_ELS_CTRL_CMD(WT_ELS_CMD_RND_REQ);
        ret = wt_els_wait_idle();
        if (ret != 0) {
            s_rng_failed = true;
            WT_ELS_ERR_STATUS_CLR = WT_ELS_ERR_STATUS_CLR_ALL;
        }
    }
    return ret;
}

static int wt_els_fill(unsigned char *output, unsigned int sz)
{
    uint32_t *page = s_els_page;
    volatile uint32_t* wipe = s_els_page;
    unsigned int done = 0u;
    unsigned int chunk;
    unsigned int i;
    int ret = 0;

    while (ret == 0 && done < sz) {
        ret = wt_els_rnd_page(page);
        if (ret == 0) {
            chunk = sz - done;
            if (chunk > (unsigned int)sizeof(s_els_page)) {
                chunk = (unsigned int)sizeof(s_els_page);
            }
            (void)memcpy(output + done, page, chunk);
            done += chunk;
        }
    }
    for (i = 0u; i < WT_ELS_PAGE_WORDS; ++i) {
        wipe[i] = 0u;
    }
    return ret;
}

int wolftrust_rng_generate_block_direct(unsigned char *output, unsigned int sz)
{
    if ((output == NULL && sz != 0u) || s_rng_failed) {
        return -1;
    }
    if (!s_rng_ready) {
        if (wt_els_init() != 0) {
            return -1;
        }
        s_rng_ready = true;
    }
    if (sz == 0u) {
        return 0;
    }
    return wt_els_fill(output, sz);
}

int wolftrust_rng_generate_block(unsigned char *output, unsigned int sz)
{
    /* A confined keystore partition cannot touch the ELS; the SVC
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
