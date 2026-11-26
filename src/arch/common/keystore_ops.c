/* keystore_ops.c
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

#include "wolftrust/spm_ops.h"

#include "wolfhsm/wh_flash.h"

#include <stdint.h>

/* Port seams: the vault's NVM flash callbacks and context singleton
 * (hsm_flash.c) and the TRNG entropy source (rng_entropy.c). */
extern const whFlashCb g_wt_hsm_flash_cb;
void *wt_hsm_flash_context(void);
int wolftrust_rng_generate_block_direct(unsigned char *output,
                                        unsigned int sz);

#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
volatile uint32_t g_wt_ks_last_flash __attribute__((used));
volatile uint32_t g_wt_ks_last_flash_off __attribute__((used));
volatile uint32_t g_wt_ks_flash_ops __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_count __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_subop __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_buf __attribute__((used));
volatile uint32_t g_wt_ks_dom_reject_len __attribute__((used));
#endif

static int wt_keystore_flash(const wt_secure_domain_t* domain,
                             const wt_spm_call_t* call)
{
    /* The flash context is the vault's singleton, never caller-supplied. */
    void* ctx = wt_hsm_flash_context();
    int sub = call->call_type;
    uint32_t off = call->vec_idx;
    uint32_t len = (uint32_t)call->num_bytes;
    int ret = -1;

    if (sub == WT_SPM_KS_FLASH_READ) {
        if (wt_secure_domain_contains(domain, (uintptr_t)call->buffer,
                                      call->num_bytes, 1) != 0) {
            ret = g_wt_hsm_flash_cb.Read(ctx, off, len,
                                         (uint8_t*)call->buffer);
        }
    }
    else if (sub == WT_SPM_KS_FLASH_PROGRAM || sub == WT_SPM_KS_FLASH_VERIFY) {
        if (wt_secure_domain_contains(domain, (uintptr_t)call->buffer,
                                      call->num_bytes, 0) == 0) {
            ret = -1;
        }
        else if (sub == WT_SPM_KS_FLASH_PROGRAM) {
            ret = g_wt_hsm_flash_cb.Program(ctx, off, len,
                                            (const uint8_t*)call->buffer);
        }
        else {
            ret = g_wt_hsm_flash_cb.Verify(ctx, off, len,
                                           (const uint8_t*)call->buffer);
        }
    }
    else if (sub == WT_SPM_KS_FLASH_ERASE) {
        ret = g_wt_hsm_flash_cb.Erase(ctx, off, len);
    }
    else if (sub == WT_SPM_KS_FLASH_BLANKCHECK) {
        ret = g_wt_hsm_flash_cb.BlankCheck(ctx, off, len);
    }
    else if (sub == WT_SPM_KS_FLASH_CLEANUP) {
        ret = g_wt_hsm_flash_cb.Cleanup(ctx);
    }
#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
    g_wt_ks_flash_ops++;
    /* -1 left untouched: a failed domain check or an unknown sub-op. */
    if (ret == -1) {
        g_wt_ks_dom_reject_count++;
        g_wt_ks_dom_reject_subop = (uint32_t)sub;
        g_wt_ks_dom_reject_buf = (uint32_t)(uintptr_t)call->buffer;
        g_wt_ks_dom_reject_len = len;
    }
#endif
    return ret;
}

int wt_spm_keystore_op(const wt_secure_domain_t* domain, wt_spm_call_t* call)
{
    int ret = -1;

    if (call->op == WT_SPM_OP_KEYSTORE_FLASH) {
        ret = wt_keystore_flash(domain, call);
    }
    else if (wt_secure_domain_contains(domain, (uintptr_t)call->buffer,
                                       call->num_bytes, 1) != 0) {
        ret = wolftrust_rng_generate_block_direct(
            (unsigned char*)call->buffer, (unsigned int)call->num_bytes);
    }
#if defined(WT_FFM_FORENSICS) && (WT_FFM_FORENSICS == 1)
    if (ret != 0 && ret != 1 && g_wt_ks_last_flash == 0u) {
        g_wt_ks_last_flash = ((uint32_t)call->call_type << 24) |
                             ((uint32_t)ret & 0x00FFFFFFu);
        g_wt_ks_last_flash_off = call->vec_idx;
    }
#endif
    return ret;
}
