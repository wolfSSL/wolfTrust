/* wt_hsm.c
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

/*
 * wolfHSM service module — Wave 3.
 *
 * Owns:
 *   - The shared flash-backed NVM context.
 *   - The shared NVM serialisation lock (callbacks in wt_hsm_lock.c).
 *   - Per-guest whServerContext instances driven by per-guest tasklets.
 *
 * What this file does NOT own:
 *   - The NS-side transport (src/client/hsm_psa_transport.c over SERVICE_HSM).
 *   - Lock callback implementations (Wave 3B, wt_hsm_lock.c).
 *
 * Heap strategy:
 *   The secure profile defines NO_WOLFSSL_MEMORY + WOLFSSL_NO_MALLOC. There
 *   is no malloc/sbrk path and no wolfCrypt static heap arena; accidental
 *   XMALLOC users fail closed. The HSM server, NVM and crypto state used here
 *   is static, stack-owned, or caller-provided.
 */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/ecc.h"

/* wolfHSM headers. */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_lock.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_crypto.h"

/* wolfTrust headers. */
#include "wolftrust/types.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/rollback.h"
#include "wolftrust/sched/tasklet.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/nvm_store.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/vault_service.h"

#include "wolftrust/port_nvm.h"
#include "psa/lifecycle.h"

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef WOLFHSM_CFG_THREADSAFE
#error "wolfTrust requires WOLFHSM_CFG_THREADSAFE for shared wolfHSM state"
#endif

/* -------------------------------------------------------------------------
 * Per-tasklet secure stacks. Target builds may override WT_CO_STACK_SIZE
 * after measuring stack high-water marks for their HSM workload.
 *
 * Keep a guard area immediately below each descending stack.  Hardware PSPLIM
 * should trap a real underflow before this area is used, but the guard prevents
 * adjacent service metadata from being corrupted on emulators or during early
 * bring-up when stack-limit handling is incomplete.
 * ---------------------------------------------------------------------- */
#define WT_HSM_STACK_UNDERFLOW_GUARD_SIZE 256u

typedef struct wt_hsm_stack_slot {
    uint8_t guard[WT_HSM_STACK_UNDERFLOW_GUARD_SIZE];
    uint8_t stack[WT_CO_STACK_SIZE];
} wt_hsm_stack_slot_t;

static wt_hsm_stack_slot_t g_co_stack_slots[WT_MAX_GUESTS]
    __attribute__((aligned(8)));

/* -------------------------------------------------------------------------
 * Per-guest state.
 * ---------------------------------------------------------------------- */
typedef struct wt_hsm_guest {
    whServerContext           server;
    whServerCryptoContext     crypto;
    /* Transport config storage kept alive for the server context lifetime. */
    void                     *transport_ctx;
    const whTransportServerCb *transport_cb;
    const void               *transport_cfg;
    whCommServerConfig        comm_cfg;
    whServerConfig            server_cfg;
    wt_tasklet_t             *tasklet;
    bool                      ready;
} wt_hsm_guest_t;

static wt_hsm_guest_t g_guests[WT_MAX_GUESTS];

#define WT_HSM_ATTEST_KEY_ID 0xF0u
#define WT_HSM_ATTEST_PUBLIC_KEY_SIZE 65u

static whServerContext g_attest_server;
static whServerCryptoContext g_attest_crypto;
static whCommServerConfig g_attest_comm_cfg;
static whServerConfig g_attest_server_cfg;
static uint8_t g_attest_public_key[WT_HSM_ATTEST_PUBLIC_KEY_SIZE];
static int g_attest_init_status = WH_ERROR_NOTREADY;
static bool g_attest_init_attempted;
static bool g_attest_ready;

/* The shared NVM store, lock, lifecycle latch, and rollback floors moved to
 * the engine-independent src/services/nvm_store.c (wolftrust/nvm_store.h). */

#if defined(WT_VAULT_FOREIGN_PROBE)
/* Negative test: make the first provisioning look blocked, as if a
 * NONMODIFIABLE IAK from an older firmware occupied the slot, so the real
 * recovery path runs exactly once (self-heal when unlocked, fail closed when
 * WT_VAULT_PROBE_SECURED forces a locked lifecycle). */
static int g_foreign_probe_fired;
#endif

/* -------------------------------------------------------------------------
 * Forward declaration — tasklet body defined below.
 * ---------------------------------------------------------------------- */
static void wt_hsm_tasklet_main(void *arg);

/* =========================================================================
 * wt_hsm_init
 * ====================================================================== */
/* Wire the NVM flash-log config, bring up the shared NVM context, and bind the
 * vault, sealer, and key backends. Re-callable: wt_hsm_vault_format runs it
 * again against a freshly erased pool. The lockConfig path is mandatory because
 * per-guest tasklets share one wolfHSM NVM context. */
static int wt_hsm_bind_store(void)
{
    int rc;

    rc = wt_nvm_store_bind();
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    if (wt_hsm_vault_init(&g_wt_nvm_ctx) == 0) {
        wt_vault_service_set_backend(&wt_hsm_vault_backend);
        if (wt_hsm_seal_init(&g_wt_nvm_ctx) == 0) {
            wt_hsm_vault_set_sealer(&wt_hsm_sealer);
        }
        else {
            /* Reinit on the format/recovery path can fail after a prior
             * success; drop the sealer so sealed writes fail closed rather
             * than run with a stale or zero key. */
            wt_hsm_vault_set_sealer(NULL);
        }
        /* Keys live in the wolfHSM server keystore, reached through the
         * SERVICE_HSM relay (WT-FFM-0054) — the vault has no key backend, so
         * its key ops stay fail-closed. Only the RANDOM face is served. */
        wt_vault_service_set_rng(wt_hsm_vault_random);
    }

    return 0;
}

/* Erase the whole vault region and rebuild a blank store. Caller must have
 * checked wt_nvm_reformat_allowed() -- this destroys every object, including
 * WRITE_ONCE storage and the sealed device key. */
static int wt_hsm_vault_format(void)
{
    int rc;

    rc = wt_hsm_flash_format();
    if (rc == 0) {
        rc = wt_hsm_bind_store();
    }
    if (rc == 0) {
        wt_nvm_mark_reformatted();
    }
    return rc;
}

/* Vault-domain RNG (WT-FFM-0054): a wolfCrypt DRBG owned by the privileged
 * vault domain, installed on SERVICE_VAULT's RANDOM face at boot. Kept
 * separate from the wolfHSM server keystore — the single crypto backend for
 * keys — because this is entropy plumbing, not key storage. */
static WC_RNG g_vault_rng;
static int g_vault_rng_ready;

psa_status_t wt_hsm_vault_random(uint8_t* out, size_t len)
{
    if (out == NULL || len == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (g_vault_rng_ready == 0) {
        if (wc_InitRng_ex(&g_vault_rng, NULL, INVALID_DEVID) != 0) {
            return PSA_ERROR_GENERIC_ERROR;
        }
        g_vault_rng_ready = 1;
    }
    if (wc_RNG_GenerateBlock(&g_vault_rng, out, (word32)len) != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

int wt_hsm_init(void)
{
    int rc;

    rc = wolfCrypt_Init();
    if (rc != 0) {
        return rc;
    }

    rc = g_wt_hsm_flash_cb.Init(wt_hsm_flash_context(),
                                wt_hsm_flash_config());
    if (rc != 0) {
        return rc;
    }

    /* Initialise the shared NVM lock once, before wh_Nvm_Init wires it in. */
    wt_mutex_init(&g_wt_nvm_lock_mutex);

    return wt_hsm_bind_store();
}

/* =========================================================================
 * wt_hsm_tasklet_main
 *
 * Runs indefinitely inside a per-guest tasklet.  Calls
 * wh_Server_HandleRequestMessage once per iteration and blocks if no
 * request is pending (WH_ERROR_NOTREADY) or on unexpected errors.
 * ====================================================================== */
static void wt_hsm_tasklet_main(void *arg)
{
    wt_guest_id_t   gid = (wt_guest_id_t)(uintptr_t)arg;
    wt_hsm_guest_t *g   = &g_guests[gid];

#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* Key provisioning touches the shared persistent store and therefore
     * must run from a coroutine that can own the wolfHSM NVM mutex. The
     * bootstrap path runs this tasklet before guest dispatch; this fallback
     * also keeps a direct HSM-driven startup safe on ports without that hook. */
    if (!g_attest_ready) {
        if (wt_hsm_attest_init() != WH_ERROR_OK) {
            for (;;) {
                wt_tasklet_block();
            }
        }
    }
#endif

    for (;;) {
        int rc = wh_Server_HandleRequestMessage(&g->server);
        if (rc == WH_ERROR_NOTREADY) {
            wt_tasklet_block();
        }
        else if (rc != WH_ERROR_OK) {
            /* TODO: forward error to secure log buffer when available. */
            wt_tasklet_block();
        }
    }
}

/* =========================================================================
 * wt_hsm_guest_init
 * ====================================================================== */
int wt_hsm_guest_init(wt_guest_id_t guest_id,
                      const whTransportServerCb *transport_cb,
                      void *transport_ctx,
                      const void *transport_cfg)
{
    int             rc;
    wt_hsm_guest_t *g;

    /* ------------------------------------------------------------------
     * 1. Bounds + duplicate check.
     * ---------------------------------------------------------------- */
    if (guest_id >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    g = &g_guests[guest_id];
    if (g->ready) {
        return WH_ERROR_BADARGS;
    }

    /* ------------------------------------------------------------------
     * 2. Zero the per-guest struct for a clean slate.
     * ---------------------------------------------------------------- */
    (void)memset(g, 0, sizeof(*g));

    /* ------------------------------------------------------------------
     * 3. Initialise the RNG that lives inside the crypto context.
     *
     * The whServerCryptoContext embeds WC_RNG rng[1].  We initialise it
     * with INVALID_DEVID so the server's RNG uses the local entropy source
     * (CUSTOM_RAND_GENERATE_BLOCK = wolftrust_rng_generate_block) rather
     * than routing back through a HSM client callback. No heap hint is used:
     * the secure wolfCrypt build has no heap allocator.
     * ---------------------------------------------------------------- */
    rc = wc_InitRng_ex(g->crypto.rng, NULL, INVALID_DEVID);
    if (rc != 0) {
        return rc;
    }

    /* ------------------------------------------------------------------
     * 4. Stash transport pointers and build comm config.
     *
     * whCommServerConfig.server_id is uint8_t; truncation from uint16_t
     * is intentional — client IDs 1..WT_MAX_GUESTS all fit in a byte.
     * ---------------------------------------------------------------- */
    g->transport_ctx = transport_ctx;
    g->transport_cb  = transport_cb;
    g->transport_cfg = transport_cfg;

    g->comm_cfg.transport_cb      = transport_cb;
    g->comm_cfg.transport_context = transport_ctx;
    g->comm_cfg.transport_config  = transport_cfg;
    g->comm_cfg.server_id         = (uint8_t)wt_hsm_guest_client_id(guest_id);

    /* ------------------------------------------------------------------
     * 5. Build server config.
     * ---------------------------------------------------------------- */
    g->server_cfg.comm_config = &g->comm_cfg;
    g->server_cfg.nvm         = &g_wt_nvm_ctx;
    g->server_cfg.crypto      = &g->crypto;
#if defined(WOLF_CRYPTO_CB)
    g->server_cfg.devId       = INVALID_DEVID;
#endif

    /* ------------------------------------------------------------------
     * 6. Initialise the wolfHSM server context.
     *
     * Note: wh_Server_Init expects NVM and crypto to be initialised before
     * it is called.  NVM was initialised in wt_hsm_init(); the RNG (crypto)
     * was initialised in step 3 above.
     * ---------------------------------------------------------------- */
    rc = wh_Server_Init(&g->server, &g->server_cfg);
    if (rc != WH_ERROR_OK) {
        wc_FreeRng(g->crypto.rng);
        return rc;
    }

    /* Mark the server connected so HandleRequestMessage does not reject
     * incoming packets immediately. */
    rc = wh_Server_SetConnected(&g->server, WH_COMM_CONNECTED);
    if (rc != WH_ERROR_OK) {
        wh_Server_Cleanup(&g->server);
        wc_FreeRng(g->crypto.rng);
        return rc;
    }

    /* ------------------------------------------------------------------
     * 7. Create tasklet.
     * ---------------------------------------------------------------- */
    g->tasklet = wt_tasklet_create_blocked(g_co_stack_slots[guest_id].stack,
                                           WT_CO_STACK_SIZE,
                                           wt_hsm_tasklet_main,
                                           (void *)(uintptr_t)guest_id);
    if (g->tasklet == NULL) {
        wh_Server_Cleanup(&g->server);
        wc_FreeRng(g->crypto.rng);
        return WH_ERROR_ABORTED;
    }

    /* ------------------------------------------------------------------
     * 8. Mark guest ready.
     * ---------------------------------------------------------------- */
    g->ready = true;
    return 0;
}

/* =========================================================================
 * SERVICE_HSM relay transport (WT-FFM-0054).
 *
 * The mediated path replaces the per-guest NS-RAM CSR window: the relay
 * partition hands one validated wolfHSM packet to wt_hsm_relay_submit, which
 * stashes it in the guest's capture buffer in monitor RAM, pumps that guest's
 * server to completion, and returns the captured response. The server's
 * transport callbacks below only ever touch secure memory.
 * ====================================================================== */
_Static_assert(sizeof(whCommHeader) + WOLFHSM_CFG_COMM_DATA_LEN <=
                   WT_HSM_RELAY_MSG_MAX,
               "wolfHSM packet exceeds the relay capture buffer");

typedef struct wt_hsm_relay_buf {
    uint8_t  req[WT_HSM_RELAY_MSG_MAX];
    uint8_t  resp[WT_HSM_RELAY_MSG_MAX];
    uint16_t req_len;
    uint16_t resp_len;
    uint8_t  req_pending;
    uint8_t  resp_ready;
} wt_hsm_relay_buf_t;

static wt_hsm_relay_buf_t g_relay_bufs[WT_MAX_GUESTS];

static int wt_hsm_relay_srv_init(void* context, const void* config,
                                 whCommSetConnectedCb connectcb,
                                 void* connectcb_arg)
{
    (void)config;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (connectcb != NULL) {
        connectcb(connectcb_arg, WH_COMM_CONNECTED);
    }
    return WH_ERROR_OK;
}

static int wt_hsm_relay_srv_recv(void* context, uint16_t* out_size,
                                 void* data)
{
    wt_hsm_relay_buf_t* buf = (wt_hsm_relay_buf_t*)context;

    if (buf == NULL || out_size == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (buf->req_pending == 0u) {
        return WH_ERROR_NOTREADY;
    }
    (void)memcpy(data, buf->req, buf->req_len);
    *out_size = buf->req_len;
    buf->req_pending = 0u;
    return WH_ERROR_OK;
}

static int wt_hsm_relay_srv_send(void* context, uint16_t size,
                                 const void* data)
{
    wt_hsm_relay_buf_t* buf = (wt_hsm_relay_buf_t*)context;

    if (buf == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (size > sizeof(buf->resp)) {
        return WH_ERROR_BADARGS;
    }
    (void)memcpy(buf->resp, data, size);
    buf->resp_len = size;
    buf->resp_ready = 1u;
    return WH_ERROR_OK;
}

static int wt_hsm_relay_srv_cleanup(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

static const whTransportServerCb g_relay_transport_cb = {
    .Init    = wt_hsm_relay_srv_init,
    .Recv    = wt_hsm_relay_srv_recv,
    .Send    = wt_hsm_relay_srv_send,
    .Cleanup = wt_hsm_relay_srv_cleanup
};

int wt_hsm_guest_init_relay(wt_guest_id_t guest_id)
{
    if (guest_id >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    return wt_hsm_guest_init(guest_id, &g_relay_transport_cb,
                             &g_relay_bufs[guest_id], NULL);
}

int wt_hsm_relay_submit(void* submit_ctx, int32_t client_id,
                        const uint8_t* req, size_t req_len,
                        uint8_t* resp, size_t resp_cap, size_t* resp_len)
{
    wt_hsm_guest_t* g;
    wt_hsm_relay_buf_t* buf;
    wt_guest_id_t gid;
    const whCommHeader* hdr;
    uint16_t kind;
    int guard = 1000;
    int rc = WH_ERROR_OK;

    (void)submit_ctx;
    if (req == NULL || resp == NULL || resp_len == NULL || client_id >= 0) {
        return WH_ERROR_BADARGS;
    }
    /* The SPM stamps NS callers as -(guest + 1); the mapping mirrors
     * wt_ffm_boot_caller_guest. */
    gid = (wt_guest_id_t)(-client_id - 1);
    if (gid >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    g = &g_guests[gid];
    buf = &g_relay_bufs[gid];
    if (!g->ready || g->transport_ctx != buf) {
        return WH_ERROR_NOTREADY;
    }
    if (req_len == 0u || req_len > sizeof(buf->req) ||
            req_len > sizeof(whCommHeader) + WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }
    if (req_len < sizeof(whCommHeader)) {
        return WH_ERROR_BADARGS;
    }

    /* The guest relay is a crypto-only door: refuse NVM-group packets so a
     * guest cannot reach the vault, rollback, or replay-counter pool. */
    hdr = (const whCommHeader*)(const void*)req;
    kind = wh_Translate16(hdr->magic, hdr->kind);
    if (WH_MESSAGE_GROUP(kind) == WH_MESSAGE_GROUP_NVM) {
        return WH_ERROR_BADARGS;
    }

    /* Bind the server to this guest's namespace so a spoofed COMM-INIT client
     * id cannot reach the attestation IAK or another guest's keys. */
    g->server.comm->client_id = (uint8_t)wt_hsm_guest_client_id(gid);

    (void)memcpy(buf->req, req, req_len);
    buf->req_len = (uint16_t)req_len;
    buf->resp_ready = 0u;
    buf->req_pending = 1u;

    while (buf->resp_ready == 0u && guard-- > 0) {
        rc = wh_Server_HandleRequestMessage(&g->server);
        if (rc != WH_ERROR_OK && rc != WH_ERROR_NOTREADY) {
            break;
        }
    }
    if (buf->resp_ready == 0u) {
        buf->req_pending = 0u;
        return (rc != WH_ERROR_OK) ? rc : WH_ERROR_ABORTED;
    }
    if (buf->resp_len > resp_cap) {
        return WH_ERROR_ABORTED;
    }
    (void)memcpy(resp, buf->resp, buf->resp_len);
    *resp_len = buf->resp_len;
    return WH_ERROR_OK;
}

/* =========================================================================
 * wt_hsm_guest_ready
 * ====================================================================== */
bool wt_hsm_guest_ready(wt_guest_id_t guest_id)
{
    if (guest_id >= WT_MAX_GUESTS) {
        return false;
    }
    return g_guests[guest_id].ready;
}

/* =========================================================================
 * wt_hsm_guest_client_id
 *
 * Client-ID 0 is reserved; guests are numbered from 1.
 * ====================================================================== */
uint16_t wt_hsm_guest_client_id(wt_guest_id_t guest_id)
{
    return (uint16_t)(guest_id + 1u);
}

/* =========================================================================
 * wt_hsm_guest_tasklet
 *
 * Returns the tasklet handle for the given guest so the monitor can wake it
 * at epoch boundaries.  Returns NULL for unknown guests or
 * guests that have not yet been initialised.
 * ====================================================================== */
struct wt_co *wt_hsm_guest_tasklet(wt_guest_id_t guest_id)
{
    if (guest_id >= WT_MAX_GUESTS) return NULL;
    return g_guests[guest_id].tasklet;
}

int wt_hsm_attest_bootstrap(void)
{
    wt_guest_id_t gid;
    wt_tasklet_t *tasklet;

    if (g_attest_ready) {
        return WH_ERROR_OK;
    }
    for (gid = 0u; gid < WT_MAX_GUESTS; gid++) {
        if (!g_guests[gid].ready || g_guests[gid].tasklet == NULL) {
            continue;
        }
        tasklet = g_guests[gid].tasklet;
        wt_tasklet_wake(tasklet);
        if (wt_tasklet_resume(tasklet) == 0u) {
            return WH_ERROR_ABORTED;
        }
        return g_attest_ready ? WH_ERROR_OK : g_attest_init_status;
    }

    return WH_ERROR_NOTREADY;
}

/* =========================================================================
 * wt_hsm_guest_for_tasklet
 *
 * Reverse lookup. Linear scan is fine: WT_MAX_GUESTS is small (currently 2)
 * and this is only called from the Secure fault dispatcher.
 * ====================================================================== */
wt_guest_id_t wt_hsm_guest_for_tasklet(const struct wt_co *tasklet)
{
    wt_guest_id_t gid;

    if (tasklet == NULL) return WT_MAX_GUESTS;

    for (gid = 0; gid < WT_MAX_GUESTS; gid++) {
        if (g_guests[gid].tasklet == tasklet) {
            return gid;
        }
    }
    return WT_MAX_GUESTS;
}

/* =========================================================================
 * wt_hsm_signal_fault
 *
 * Called from the Secure fault dispatcher after wt_tasklet_mark_faulted has
 * removed the tasklet from the scheduler. Drops any NVM lock the dying
 * tasklet still held, writes a WH_ERROR_ABORTED fatal-response into
 * the guest's transport so the NS client unblocks with a clean error,
 * and clears the ready bit so future NSC veneers reject HSM calls from
 * this guest.
 *
 * Idempotent: calling on an already-faulted guest is harmless.
 * ====================================================================== */
static int wt_hsm_fault_notify_noop(wt_guest_id_t guest_id)
{
    (void)guest_id;
    return WH_ERROR_OK;
}

static wt_hsm_fault_notify_fn g_hsm_fault_notify = wt_hsm_fault_notify_noop;

void wt_hsm_set_fault_notify(wt_hsm_fault_notify_fn fn)
{
    g_hsm_fault_notify = (fn != NULL) ? fn : wt_hsm_fault_notify_noop;
}

int wt_hsm_relay_reinit_servers(void)
{
    int             rc = WH_ERROR_OK;
    wt_hsm_guest_t *g;
    wt_guest_id_t   gid;

    for (gid = 0; gid < WT_MAX_GUESTS; gid++) {
        g = &g_guests[gid];
        if (!g->ready) {
            continue;
        }
        /* A relay fault can tear a server mid-request; rebuild the server
         * and its DRBG in place rather than trust torn state. The configs
         * and tasklet stored in g persist — only the live contexts reset. */
        (void)wh_Server_Cleanup(&g->server);
        (void)wc_FreeRng(g->crypto.rng);
        rc = wc_InitRng_ex(g->crypto.rng, NULL, INVALID_DEVID);
        if (rc == 0) {
            rc = wh_Server_Init(&g->server, &g->server_cfg);
        }
        if (rc == 0) {
            rc = wh_Server_SetConnected(&g->server, WH_COMM_CONNECTED);
        }
        if (rc != 0) {
            g->ready = false;
            break;
        }
    }
    return rc;
}

int wt_hsm_signal_fault(wt_guest_id_t guest_id)
{
    wt_hsm_guest_t *g;

    if (guest_id >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    g = &g_guests[guest_id];

    /* Force-release the NVM lock if the faulted tasklet was its holder.
     * This is the only mutex in the secure-side wolfHSM service; if more
     * are added later, this is the place to drop them all. */
    if (g->tasklet != NULL) {
        wt_hsm_release_locks(g->tasklet);
    }

    /* Tell the NS client. Failure here just means the transport was
     * never wired (guest_id outside transport range) — still safe. */
    (void)g_hsm_fault_notify(guest_id);

    g->ready = false;
    return WH_ERROR_OK;
}

typedef union wt_hsm_attest_packet {
    uint64_t align;
    uint8_t bytes[WOLFHSM_CFG_COMM_DATA_LEN];
} wt_hsm_attest_packet_t;

static void wt_hsm_force_zero(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;

    while (size > 0u) {
        *bytes++ = 0u;
        size--;
    }
}

static int wt_hsm_attest_transport_init(void* context, const void* config,
    whCommSetConnectedCb connectCb, void* connectContext)
{
    (void)context;
    (void)config;
    (void)connectCb;
    (void)connectContext;
    return WH_ERROR_OK;
}

static int wt_hsm_attest_transport_recv(void* context, uint16_t* size,
    void* data)
{
    (void)context;
    (void)size;
    (void)data;
    return WH_ERROR_NOTREADY;
}

static int wt_hsm_attest_transport_send(void* context, uint16_t size,
    const void* data)
{
    (void)context;
    (void)size;
    (void)data;
    return WH_ERROR_NOTREADY;
}

static int wt_hsm_attest_transport_cleanup(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

static const whTransportServerCb g_attest_transport_cb = {
    .Init = wt_hsm_attest_transport_init,
    .Recv = wt_hsm_attest_transport_recv,
    .Send = wt_hsm_attest_transport_send,
    .Cleanup = wt_hsm_attest_transport_cleanup
};

static int wt_hsm_attest_crypto_response(wt_hsm_attest_packet_t* response,
    uint16_t responseSize, uint32_t expectedAlgorithm, uint8_t** payload)
{
    whMessageCrypto_GenericResponseHeader* header;

    if ((response == NULL) || (payload == NULL) ||
        (responseSize < sizeof(*header))) {
        return WH_ERROR_ABORTED;
    }

    header = (whMessageCrypto_GenericResponseHeader*)response->bytes;
    if (header->algoType != expectedAlgorithm) {
        return WH_ERROR_ABORTED;
    }
    if (header->rc != WH_ERROR_OK) {
        return header->rc;
    }

    *payload = response->bytes + sizeof(*header);
    return WH_ERROR_OK;
}

static int wt_hsm_attest_export_public(void)
{
    wt_hsm_attest_packet_t response;
    whMessageKeystore_ExportPublicRequest request;
    whMessageKeystore_ExportPublicResponse* result;
    ecc_key publicKey;
    const uint8_t* der;
    word32 xSize = 32u;
    word32 ySize = 32u;
    uint16_t responseSize = 0u;
    int keyInited = 0;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    request.id = WT_HSM_ATTEST_KEY_ID;
    request.algo = WH_KEY_ALGO_ECC;

    ret = wh_Server_HandleKeyRequest(&g_attest_server,
        WH_COMM_MAGIC_NATIVE, WH_KEY_EXPORT_PUBLIC, (uint16_t)sizeof(request),
        &request, &responseSize, response.bytes);
    result = (whMessageKeystore_ExportPublicResponse*)response.bytes;
    if ((ret == WH_ERROR_OK) && (responseSize < sizeof(*result))) {
        ret = WH_ERROR_ABORTED;
    }
    if ((ret == WH_ERROR_OK) && (result->rc != WH_ERROR_OK)) {
        ret = result->rc;
    }
    if ((ret == WH_ERROR_OK) &&
        (result->len > responseSize - sizeof(*result))) {
        ret = WH_ERROR_ABORTED;
    }

    if (ret == WH_ERROR_OK) {
        der = response.bytes + sizeof(*result);
        ret = wc_ecc_init_ex(&publicKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            keyInited = 1;
            ret = wh_Crypto_EccDeserializeKeyDer(der,
                (uint16_t)result->len, &publicKey);
        }
    }
    if (ret == WH_ERROR_OK) {
        g_attest_public_key[0] = 0x04u;
        ret = wc_ecc_export_public_raw(&publicKey,
            &g_attest_public_key[1], &xSize,
            &g_attest_public_key[33], &ySize);
        if ((ret == 0) && ((xSize != 32u) || (ySize != 32u))) {
            ret = WH_ERROR_ABORTED;
        }
    }

    if (keyInited != 0) {
        wc_ecc_free(&publicKey);
        wt_hsm_force_zero(&publicKey, sizeof(publicKey));
    }
    wt_hsm_force_zero(&response, sizeof(response));
    return ret;
}

static int wt_hsm_attest_generate_key(void)
{
    static const uint8_t label[] = "wolfTrust IAK";
    wt_hsm_attest_packet_t request;
    wt_hsm_attest_packet_t response;
    whMessageCrypto_GenericRequestHeader* header;
    whMessageCrypto_EccKeyGenRequest* keygen;
    whMessageCrypto_EccKeyGenResponse* result;
    uint8_t* responsePayload = NULL;
    whKeyId serverKeyId;
    uint16_t requestSize;
    uint16_t responseSize = 0u;
    int ret;

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    header = (whMessageCrypto_GenericRequestHeader*)request.bytes;
    keygen = (whMessageCrypto_EccKeyGenRequest*)(header + 1);
    header->algoType = WC_PK_TYPE_EC_KEYGEN;
    header->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    header->affinity = WH_CRYPTO_AFFINITY_SW;
    keygen->sz = 32u;
    keygen->curveId = ECC_SECP256R1;
    keygen->keyId = WT_HSM_ATTEST_KEY_ID;
    keygen->flags = WH_NVM_FLAGS_SENSITIVE |
        WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_LOCAL |
        WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE |
        WH_NVM_FLAGS_USAGE_SIGN;
    (void)memcpy(keygen->label, label, sizeof(label) - 1u);
    requestSize = (uint16_t)(sizeof(*header) + sizeof(*keygen));

    ret = wh_Server_HandleCryptoRequest(&g_attest_server,
        WH_COMM_MAGIC_NATIVE, WC_ALGO_TYPE_PK, 0u, requestSize,
        request.bytes, &responseSize, response.bytes);
    if (ret == WH_ERROR_OK) {
        ret = wt_hsm_attest_crypto_response(&response, responseSize,
            WC_PK_TYPE_EC_KEYGEN, &responsePayload);
    }
    if (ret == WH_ERROR_OK) {
        result = (whMessageCrypto_EccKeyGenResponse*)responsePayload;
        if ((responseSize <
                sizeof(whMessageCrypto_GenericResponseHeader) +
                sizeof(*result)) ||
            (result->keyId != WT_HSM_ATTEST_KEY_ID) ||
            (result->len != responseSize -
                sizeof(whMessageCrypto_GenericResponseHeader) -
                sizeof(*result))) {
            ret = WH_ERROR_ABORTED;
        }
    }
    if (ret == WH_ERROR_OK) {
        serverKeyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_CLIENT_ID_MAX,
                                    WT_HSM_ATTEST_KEY_ID);
        ret = wh_Server_KeystoreCommitKey(&g_attest_server, serverKeyId);
    }

    wt_hsm_force_zero(&request, sizeof(request));
    wt_hsm_force_zero(&response, sizeof(response));
    return ret;
}

int wt_hsm_attest_init(void)
{
    int ret;

#if defined(WT_VAULT_FOREIGN_PROBE) && defined(WT_VAULT_PROBE_SECURED)
    wt_hsm_set_boot_lifecycle(PSA_LIFECYCLE_SECURED);
#endif
    if (g_attest_ready) {
        return WH_ERROR_OK;
    }
    if (g_attest_init_attempted) {
        return g_attest_init_status;
    }
    g_attest_init_attempted = true;

    (void)memset(&g_attest_crypto, 0, sizeof(g_attest_crypto));
    ret = wc_InitRng_ex(g_attest_crypto.rng, NULL, INVALID_DEVID);
    if (ret != 0) {
        g_attest_init_status = ret;
        return ret;
    }

    (void)memset(&g_attest_comm_cfg, 0, sizeof(g_attest_comm_cfg));
    g_attest_comm_cfg.transport_cb = &g_attest_transport_cb;
    g_attest_comm_cfg.server_id = 0u;

    (void)memset(&g_attest_server_cfg, 0, sizeof(g_attest_server_cfg));
    g_attest_server_cfg.comm_config = &g_attest_comm_cfg;
    g_attest_server_cfg.nvm = &g_wt_nvm_ctx;
    g_attest_server_cfg.crypto = &g_attest_crypto;
#if defined(WOLF_CRYPTO_CB)
    g_attest_server_cfg.devId = INVALID_DEVID;
#endif

    ret = wh_Server_Init(&g_attest_server, &g_attest_server_cfg);
    if (ret == WH_ERROR_OK) {
        g_attest_server.comm->client_id = WH_CLIENT_ID_MAX;
        ret = wh_Server_SetConnected(&g_attest_server, WH_COMM_CONNECTED);
    }
    if (ret == WH_ERROR_OK) {
        ret = wt_hsm_attest_export_public();
#if defined(WT_VAULT_FOREIGN_PROBE)
        /* Force the existing key to look unreadable so the generate path runs
         * regardless of pool state (an already-provisioned IAK would otherwise
         * export cleanly and skip the recovery under test). */
        if (!g_foreign_probe_fired) {
            ret = WH_ERROR_ACCESS;
        }
#endif
        if (ret != WH_ERROR_OK) {
            ret = wt_hsm_attest_generate_key();
#if defined(WT_VAULT_FOREIGN_PROBE)
            if (!g_foreign_probe_fired) {
                g_foreign_probe_fired = 1;
                ret = WH_ERROR_ACCESS;
            }
#endif
            /* A foreign or corrupt pool blocks provisioning: the IAK slot is
             * held by an object from an older firmware generation whose
             * NONMODIFIABLE/NONDESTROYABLE flags reject the fresh commit. In an
             * unlocked lifecycle, reformat the vault once and re-provision; a
             * SECURED device never reaches here, so its data is never wiped. */
            if (ret != WH_ERROR_OK && wt_nvm_reformat_allowed()) {
                if (wt_hsm_vault_format() == 0) {
                    /* vault_format re-inited the store under the attest server;
                     * rebind the server to the fresh store before re-provisioning
                     * so its keystore view is not stale. */
                    ret = wh_Server_Init(&g_attest_server, &g_attest_server_cfg);
                    if (ret == WH_ERROR_OK) {
                        g_attest_server.comm->client_id = WH_CLIENT_ID_MAX;
                        ret = wh_Server_SetConnected(&g_attest_server,
                                                     WH_COMM_CONNECTED);
                    }
                    if (ret == WH_ERROR_OK) {
                        ret = wt_hsm_attest_generate_key();
                    }
                }
            }
            if (ret == WH_ERROR_OK) {
                ret = wt_hsm_attest_export_public();
            }
        }
    }

    if (ret == WH_ERROR_OK) {
        g_attest_ready = true;
    }
    else {
        wt_hsm_force_zero(g_attest_public_key,
                          sizeof(g_attest_public_key));
    }
    g_attest_init_status = ret;
    return g_attest_init_status;
}

int wt_hsm_attest_sign(const uint8_t* digest, size_t digestSize,
                       uint8_t* signature, size_t signatureCapacity,
                       size_t* signatureSize)
{
    wt_hsm_attest_packet_t request;
    wt_hsm_attest_packet_t response;
    whMessageCrypto_GenericRequestHeader* header;
    whMessageCrypto_EccSignRequest* sign;
    whMessageCrypto_EccSignResponse* result;
    uint8_t* responsePayload = NULL;
    uint8_t r[32];
    uint8_t s[32];
    const uint8_t* der;
    word32 rSize = (word32)sizeof(r);
    word32 sSize = (word32)sizeof(s);
    uint16_t requestSize;
    uint16_t responseSize = 0u;
    int ret;

    if (signatureSize == NULL) {
        return WH_ERROR_BADARGS;
    }
    *signatureSize = 0u;
    if (!g_attest_ready || (digest == NULL) || (digestSize != 32u) ||
        (signature == NULL) || (signatureCapacity < 64u)) {
        return WH_ERROR_BADARGS;
    }

    (void)memset(&request, 0, sizeof(request));
    (void)memset(&response, 0, sizeof(response));
    header = (whMessageCrypto_GenericRequestHeader*)request.bytes;
    sign = (whMessageCrypto_EccSignRequest*)(header + 1);
    header->algoType = WC_PK_TYPE_ECDSA_SIGN;
    header->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    header->affinity = WH_CRYPTO_AFFINITY_SW;
    sign->keyId = WT_HSM_ATTEST_KEY_ID;
    sign->sz = (uint32_t)digestSize;
    (void)memcpy(sign + 1, digest, digestSize);
    requestSize = (uint16_t)(sizeof(*header) + sizeof(*sign) + digestSize);

    ret = wh_Server_HandleCryptoRequest(&g_attest_server,
        WH_COMM_MAGIC_NATIVE, WC_ALGO_TYPE_PK, 0u, requestSize,
        request.bytes, &responseSize, response.bytes);
    if (ret == WH_ERROR_OK) {
        ret = wt_hsm_attest_crypto_response(&response, responseSize,
            WC_PK_TYPE_ECDSA_SIGN, &responsePayload);
    }
    result = (whMessageCrypto_EccSignResponse*)responsePayload;
    if ((ret == WH_ERROR_OK) &&
        ((responseSize < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*result)) ||
         (result->sz > responseSize -
             sizeof(whMessageCrypto_GenericResponseHeader) -
             sizeof(*result)))) {
        ret = WH_ERROR_ABORTED;
    }
    if (ret == WH_ERROR_OK) {
        der = (const uint8_t*)(result + 1);
        ret = wc_ecc_sig_to_rs(der, (word32)result->sz,
                               r, &rSize, s, &sSize);
    }
    if ((ret == 0) && ((rSize > 32u) || (sSize > 32u))) {
        ret = WH_ERROR_ABORTED;
    }
    if (ret == 0) {
        (void)memset(signature, 0, 64u);
        (void)memcpy(&signature[32u - rSize], r, rSize);
        (void)memcpy(&signature[64u - sSize], s, sSize);
        *signatureSize = 64u;
    }

    wt_hsm_force_zero(&request, sizeof(request));
    wt_hsm_force_zero(&response, sizeof(response));
    wt_hsm_force_zero(r, sizeof(r));
    wt_hsm_force_zero(s, sizeof(s));
    if ((ret != 0) && (signature != NULL)) {
        (void)memset(signature, 0, signatureCapacity);
    }
    return ret;
}

int wt_hsm_attest_public_key(uint8_t* publicKey, size_t publicKeyCapacity,
                             size_t* publicKeySize)
{
    if (publicKeySize == NULL) {
        return WH_ERROR_BADARGS;
    }
    *publicKeySize = WT_HSM_ATTEST_PUBLIC_KEY_SIZE;
    if (!g_attest_ready) {
        return g_attest_init_status;
    }
    if ((publicKey == NULL) ||
        (publicKeyCapacity < WT_HSM_ATTEST_PUBLIC_KEY_SIZE)) {
        return WH_ERROR_BADARGS;
    }

    (void)memcpy(publicKey, g_attest_public_key,
                 WT_HSM_ATTEST_PUBLIC_KEY_SIZE);
    return WH_ERROR_OK;
}
