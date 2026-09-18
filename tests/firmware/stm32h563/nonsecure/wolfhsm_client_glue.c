/* wolfhsm_client_glue.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Guest-side wolfHSM client glue (baremetal dual-UART harness).
 *
 * The transport is the SPM-mediated PSA path (WT-FFM-0054): every wolfHSM
 * wire packet is one synchronous psa_call to SERVICE_HSM through the
 * OS-neutral FF-M client core. The former shared-RAM CSR window and the raw
 * WolfTrust_HSM_Submit/Poll CMSE veneers are retired from this guest.
 *
 * Also provides:
 *  - wolfhsm_guest_init(): initialises the wolfHSM client context so
 *    wh_Client_CryptoCb can forward wc_* calls to the secure-side HSM.
 *  - wolftrust_guest_rng_stub(): the CUSTOM_RAND_GENERATE_BLOCK hook.
 *  - wc_GenerateSeed + a minimal bump allocator, filling in for the absent
 *    libc on this baremetal guest.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"

#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolftrust/hsm_psa_transport.h"

/* SERVICE_HSM from the platform manifest (port/stm32h563/manifest.json). */
#define WT_SERVICE_HSM_SID     4102u
#define WT_SERVICE_HSM_VERSION 1u

static wt_hsm_psa_transport_ctx_t g_guest_tx;

static const wt_hsm_psa_transport_cfg_t g_guest_tx_cfg = {
    .sid = WT_SERVICE_HSM_SID,
    .version = WT_SERVICE_HSM_VERSION,
};

/* ---------------------------------------------------------------------------
 * wolfHSM client context and configuration (module-level singletons)
 * ---------------------------------------------------------------------------*/
static whClientContext    g_client_ctx;
static whClientConfig     g_client_cfg;
static whCommClientConfig g_comm_cfg;
static int                g_client_ready;

/* ---------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------*/

/* Initialise the wolfHSM client and register the crypto-callback device.
 *
 * Call this once from Reset_Handler (or equivalent early-init code) after
 * .data/.bss are ready.  wc_* calls will be routed to the secure HSM once
 * this returns WH_ERROR_OK. */
int wolfhsm_guest_init(void)
{
    int rc;

    g_client_ready = 0;

    g_comm_cfg.transport_cb      = &wt_hsm_psa_transport_cb;
    g_comm_cfg.transport_context = &g_guest_tx;
    g_comm_cfg.transport_config  = &g_guest_tx_cfg;
    /* wolfTrust maps guest 0 to wolfHSM client namespace 1. */
    g_comm_cfg.client_id         = 1u;

    g_client_cfg.comm = &g_comm_cfg;

    rc = wh_Client_Init(&g_client_ctx, &g_client_cfg);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    g_client_ready = 1;

    return WH_ERROR_OK;
}

/* Return a pointer to the initialised client context for callers that need
 * direct access to wolfHSM client API functions. */
whClientContext *wolfhsm_guest_client(void)
{
    return &g_client_ctx;
}

/* ---------------------------------------------------------------------------
 * RNG stub — CUSTOM_RAND_GENERATE_BLOCK hook
 *
 * user_settings.h maps CUSTOM_RAND_GENERATE_BLOCK to this function.  Some
 * wolfCrypt paths still call the entropy hook directly even when the crypto-cb
 * device is selected, so delegate to the same secure-side wolfHSM client after
 * wolfhsm_guest_init() has completed.  Before init, fail closed.
 * ---------------------------------------------------------------------------*/
int wolftrust_guest_rng_stub(unsigned char *output, unsigned int sz)
{

    if (output == NULL && sz != 0u) {
        return WH_ERROR_BADARGS;
    }
    /* Boot can race a Secure Partition restart window; one failed init must
     * not be terminal — retry the connect on demand. */
    if (g_client_ready == 0 && wolfhsm_guest_init() != WH_ERROR_OK) {
        return -1;
    }

    return wh_Client_RngGenerate(&g_client_ctx, output, sz);
}

/* ---------------------------------------------------------------------------
 * wc_GenerateSeed — wolfCrypt OS seed hook
 *
 * wolfCrypt's random.c compiles PollAndReSeed() regardless of
 * CUSTOM_RAND_GENERATE_BLOCK; that function references wc_GenerateSeed to
 * reseed the DRBG.  In normal HSM-delegated operation the code path is never
 * reached, but the linker requires the symbol.  Delegate to the same HSM-backed
 * hook used by CUSTOM_RAND_GENERATE_BLOCK.
 *
 * Signature matches wolfSSL's wolfssl/wolfcrypt/random.h: OS_Seed is a
 * typedef struct, byte is uint8_t, word32 is uint32_t.
 * ---------------------------------------------------------------------------*/
#include "wolfssl/wolfcrypt/random.h"

int wc_GenerateSeed(OS_Seed *os, byte *output, word32 sz)
{
    (void)os;
    return wolftrust_guest_rng_stub((unsigned char *)output, (unsigned int)sz);
}

/* ---------------------------------------------------------------------------
 * Minimal bump-pointer heap for wolfCrypt memory.c
 *
 * wolfCrypt's memory.c calls malloc/free/realloc for internal buffers (e.g.
 * DRBG state, ECC key scratch).  The guest has no C library heap; we provide
 * a trivial bump allocator backed by a static pool.  free() and realloc() are
 * stubs sufficient for the crypto-cb delegation path where actual computation
 * stays in the secure world and the guest only formats request messages.
 *
 * Pool size: 3 KiB covers the cryptocb-delegation path (DRBG state, small
 * key formatting buffers). Larger values starve the NS stack — 8 KiB used
 * up half of the guest's 16 KiB RAM and crashed the wolfCrypt benchmark
 * with a wild-PC fault from stack overflow.
 * ---------------------------------------------------------------------------*/
#define WT_HEAP_POOL_SZ (3u * 1024u)

static uint8_t  s_heap_pool[WT_HEAP_POOL_SZ];
static uint32_t s_heap_offset = 0u;

void *malloc(size_t size)
{
    uint32_t aligned;

    if (size == 0u) {
        return NULL;
    }
    /* Round up to 8-byte alignment for all targets. */
    aligned = (uint32_t)((size + 7u) & ~7u);
    if (s_heap_offset + aligned > WT_HEAP_POOL_SZ) {
        return NULL; /* OOM — increase WT_HEAP_POOL_SZ */
    }
    void *ptr = (void *)&s_heap_pool[s_heap_offset];
    s_heap_offset += aligned;
    return ptr;
}

void free(void *ptr)
{
    /* Bump allocator: no individual free.  Acceptable because crypto-cb
     * delegation path creates and destroys keys within single operations. */
    (void)ptr;
}

void *realloc(void *ptr, size_t size)
{
    /* Simple fallback: allocate a fresh block and copy from old.
     * Safe for wolfCrypt usage patterns where realloc is rare. */
    void *new_ptr;
    if (size == 0u) {
        free(ptr);
        return NULL;
    }
    new_ptr = malloc(size);
    if (new_ptr != NULL && ptr != NULL) {
        memcpy(new_ptr, ptr, size); /* may copy more than originally alloc'd */
    }
    return new_ptr;
}
