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

/* wolfCrypt's callback device table lives in this partition's private band;
 * a default device id would make every partition's one-shot hash read it. */
#if defined(WT_TARGET_BUILD) && defined(WOLF_CRYPTO_CB) && \
    !defined(WC_NO_DEFAULT_DEVID)
#error "hsm engine: build with WC_NO_DEFAULT_DEVID"
#endif

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
#include "wolftrust/arch.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/rollback.h"
#include "wolftrust/sched/tasklet.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/nvm_store.h"
#include "wolftrust/services/nvm_client.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/static_assert.h"

#include "wolftrust/port_nvm.h"
#include "psa/lifecycle.h"

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef WOLFHSM_CFG_THREADSAFE
#error "wolfTrust requires WOLFHSM_CFG_THREADSAFE for shared wolfHSM state"
#endif

WT_STATIC_ASSERT(WT_HSM_ATTEST_NOT_READY == WH_ERROR_NOTREADY,
               "attestation door not-ready code must match wolfHSM");

/* -------------------------------------------------------------------------
 * Per-tasklet secure stacks. Target builds may override WT_CO_STACK_SIZE
 * after measuring stack high-water marks for their HSM workload.
 *
 * Keep a guard area immediately below each descending stack.  Hardware PSPLIM
 * should trap a real underflow before this area is used, but the guard prevents
 * adjacent service metadata from being corrupted on emulators or during early
 * bring-up when stack-limit handling is incomplete.
 * ---------------------------------------------------------------------- */
/* Tasklet stacks live in wt_hsm_priv.c (SPM-private RAM), never this band. */

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
    bool                      ready;
} wt_hsm_guest_t;

static wt_hsm_guest_t g_guests[WT_MAX_GUESTS];
#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
static int32_t g_secure_client_id;
static wt_guest_id_t g_secure_namespace_id;
static bool g_secure_client_bound;
#endif

/* The store every server binds to: the direct vault store during the
 * privileged bootstrap (IAK provisioning, rollback floors), then the crypto
 * partition's IPC-backed view once wt_hsm_bind_nvm has run. */
static whNvmContext* g_hsm_nvm = &g_wt_nvm_ctx;

#define WT_HSM_ATTEST_KEY_ID 0xF0u
#define WT_HSM_ATTEST_PUBLIC_KEY_SIZE 65u

static whServerContext g_hsm_attest_server;
static whServerCryptoContext g_hsm_attest_crypto;
static whCommServerConfig g_hsm_attest_comm_cfg;
static whServerConfig g_hsm_attest_server_cfg;
static uint8_t g_hsm_attest_public_key[WT_HSM_ATTEST_PUBLIC_KEY_SIZE];
static int g_hsm_attest_init_status = WH_ERROR_NOTREADY;
static bool g_hsm_attest_init_attempted;
static bool g_hsm_attest_ready;

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
static void wt_hsm_server_pin(wt_guest_id_t guest_id);
static void wt_hsm_bind_server_cfg(wt_guest_id_t guest_id);
static void wt_hsm_relay_bind(wt_guest_id_t guest_id,
                              const whTransportServerCb **cb, void **ctx);
static void wt_hsm_force_zero(void* memory, size_t size);

/* =========================================================================
 * wt_hsm_init
 * ====================================================================== */
/* Erase the whole vault region and rebuild a blank store. Caller must have
 * checked wt_nvm_reformat_allowed() -- this destroys every object, including
 * WRITE_ONCE storage and the sealed device key. */
static int wt_hsm_vault_format(void)
{
    int rc;

    rc = wt_hsm_flash_format();
    if (rc == 0) {
        rc = wt_nvm_vault_bind();
    }
    if (rc == 0) {
        wt_nvm_mark_reformatted();
    }
    return rc;
}

int wt_hsm_init(void)
{
    int rc;

    rc = wolfCrypt_Init();
    if (rc != 0) {
        return rc;
    }

    /* Initialise the NVM lock once, before wh_Nvm_Init wires it in. */
    wt_mutex_init(&g_wt_nvm_lock_mutex);

    return wt_nvm_vault_bind();
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
#if defined(WT_HSM_FAULT_PROBE) && (WT_HSM_FAULT_PROBE == 1)
    static int fault_probe_fired;
#endif

#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* Key provisioning touches the persistent store and therefore must run
     * from a coroutine that can own the wolfHSM NVM mutex: the boot-time
     * bootstrap resumes this tasklet once, before the crypto partition's
     * store is rebound to its IPC view. A failed provisioning parks it. */
    if (!g_hsm_attest_ready) {
        if (wt_hsm_attest_init() != WH_ERROR_OK) {
            for (;;) {
                wt_tasklet_block();
            }
        }
    }
#endif

#if defined(WT_HSM_FAULT_PROBE) && (WT_HSM_FAULT_PROBE == 1)
    if (gid == 0U && fault_probe_fired == 0) {
        fault_probe_fired = 1;
        wt_arch_sp_fault_probe(0U);
    }
#endif

    for (;;) {
        int rc;

        if (!g->ready) {
            wt_tasklet_block();
            continue;
        }
        /* This tasklet runs only at attestation bootstrap, before any partition
         * is schedulable; the runtime pump is the relay, which pins itself in
         * wt_hsm_relay_submit (WT-FFM-0011). */
        wt_hsm_server_pin(gid);
        rc = wh_Server_HandleRequestMessage(&g->server);
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
/* Static and relay-only by design: the former public four-argument
 * wt_hsm_guest_init is gone because a caller-chosen transport left a pointer a
 * later pump could follow. Ports use wt_hsm_guest_init_relay (WT-FFM-0011). */
static int wt_hsm_guest_init(wt_guest_id_t guest_id)
{
    int                        rc;
    wt_hsm_guest_t            *g;
    wt_tasklet_t              *tasklet;
    const whTransportServerCb *transport_cb;
    void                      *transport_ctx;
    const void                *transport_cfg = NULL;

    wt_hsm_relay_bind(guest_id, &transport_cb, &transport_ctx);

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

    /* ------------------------------------------------------------------
     * 5. Build comm and server config from trusted sources.
     * ---------------------------------------------------------------- */
    wt_hsm_bind_server_cfg(guest_id);

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
    tasklet = wt_hsm_guest_tasklet(guest_id);
    if (tasklet == NULL) {
        tasklet = wt_tasklet_create_blocked(wt_hsm_priv_stack(guest_id),
                                            WT_CO_STACK_SIZE,
                                            wt_hsm_tasklet_main,
                                            (void *)(uintptr_t)guest_id);
    }
    if (tasklet == NULL) {
        wh_Server_Cleanup(&g->server);
        wc_FreeRng(g->crypto.rng);
        return WH_ERROR_ABORTED;
    }
    wt_hsm_priv_register(guest_id, tasklet);

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
WT_STATIC_ASSERT(sizeof(whCommHeader) + WOLFHSM_CFG_COMM_DATA_LEN <=
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
    uint16_t            len;

    if (buf == NULL || out_size == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (buf->req_pending == 0u) {
        return WH_ERROR_NOTREADY;
    }
    /* req_len lives in the partition-writable relay buffer; bound the copy by
     * the source buffer and the packet capacity from constants so a forged
     * length cannot overrun either side (WT-FFM-0011). */
    len = buf->req_len;
    if (len > sizeof(buf->req) ||
            len > (uint16_t)(sizeof(whCommHeader) + WOLFHSM_CFG_COMM_DATA_LEN)) {
        return WH_ERROR_BADARGS;
    }
    (void)memcpy(data, buf->req, len);
    *out_size = len;
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
    if (context != NULL) {
        wt_hsm_force_zero(context, sizeof(wt_hsm_relay_buf_t));
    }
    return WH_ERROR_OK;
}

static const whTransportServerCb g_relay_transport_cb = {
    .Init    = wt_hsm_relay_srv_init,
    .Recv    = wt_hsm_relay_srv_recv,
    .Send    = wt_hsm_relay_srv_send,
    .Cleanup = wt_hsm_relay_srv_cleanup
};

/* Only two stores exist: the direct one the boot bootstrap provisions on,
 * and the partition's door view every later pump uses. */
static whNvmContext* wt_hsm_nvm_target(void)
{
    if (g_hsm_nvm == &g_wt_nvm_ctx) {
        return &g_wt_nvm_ctx;
    }
    return wt_nvm_client_partition_nvm();
}

/* Re-assert every pointer a server pump dereferences from link-time
 * constants before the pump, so a forged value is never followed by the
 * bootstrap tasklet or the relay partition (WT-FFM-0011). */
static void wt_hsm_server_pin(wt_guest_id_t guest_id)
{
    wt_hsm_guest_t *g = &g_guests[guest_id];
    whCommServer   *comm = g->server.comm;
    uintptr_t       packet = (uintptr_t)comm->packet;
    const whTransportServerCb *transport_cb;
    void                      *transport_ctx;

    wt_hsm_relay_bind(guest_id, &transport_cb, &transport_ctx);
    comm->transport_cb      = transport_cb;
    comm->transport_context = transport_ctx;
    comm->hdr  = (whCommHeader *)packet;
    comm->data = (void *)(packet + sizeof(whCommHeader));
    g->server.crypto = &g->crypto;
    g->server.devId  = INVALID_DEVID;
    g->server.nvm = wt_hsm_nvm_target();
    if (g->server.nvm == &g_wt_nvm_ctx) {
        wt_nvm_store_pin();
    }
    else {
        wt_nvm_client_partition_pin();
    }
}

static void wt_hsm_relay_bind(wt_guest_id_t guest_id,
                              const whTransportServerCb **cb, void **ctx)
{
    *cb  = &g_relay_transport_cb;
    *ctx = &g_relay_bufs[guest_id];
}

/* Rebuild the comm and server config in the band-writable per-guest struct
 * from link-time constants, so init and fault recovery consume trusted
 * pointers even after a partition rewrote them (WT-FFM-0011). */
static void wt_hsm_bind_server_cfg(wt_guest_id_t guest_id)
{
    wt_hsm_guest_t            *g = &g_guests[guest_id];
    const whTransportServerCb *transport_cb;
    void                      *transport_ctx;

    wt_hsm_relay_bind(guest_id, &transport_cb, &transport_ctx);
    g->comm_cfg.transport_cb      = transport_cb;
    g->comm_cfg.transport_context = transport_ctx;
    g->comm_cfg.transport_config  = NULL;
    g->comm_cfg.server_id         = (uint8_t)wt_hsm_guest_client_id(guest_id);
    g->server_cfg.comm_config     = &g->comm_cfg;
    g->server_cfg.nvm             = wt_hsm_nvm_target();
    g->server_cfg.crypto          = &g->crypto;
#if defined(WOLF_CRYPTO_CB)
    g->server_cfg.devId           = INVALID_DEVID;
#endif
}

int wt_hsm_guest_init_relay(wt_guest_id_t guest_id)
{
    if (guest_id >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    return wt_hsm_guest_init(guest_id);
}

#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
int wt_hsm_relay_set_secure_client(int32_t partition_id,
                                   wt_guest_id_t namespace_id)
{
    if (partition_id <= 0 || namespace_id >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    wt_hsm_relay_set_secure_client_policy(partition_id);
    g_secure_client_id = partition_id;
    g_secure_namespace_id = namespace_id;
    g_secure_client_bound = true;
    return WH_ERROR_OK;
}
#endif

#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
/* Forge every pointer the server pump follows to an SPM-private address the
 * unprivileged relay cannot read, so wt_hsm_server_pin must restore them before
 * the pump or the relay MemManage-faults (WT-FFM-0011). */
static void wt_hsm_forge_server_ptrs(wt_guest_id_t guest_id)
{
    wt_hsm_guest_t *g = &g_guests[guest_id];
    whCommServer   *comm = g->server.comm;

    comm->transport_cb      = (const whTransportServerCb *)0x30028001u;
    comm->transport_context = (void *)0x30028001u;
    comm->hdr  = (whCommHeader *)0x30028001u;
    comm->data = (void *)0x30028001u;
    g->server.nvm    = (whNvmContext *)0x30028001u;
    g->server.crypto = (whServerCryptoContext *)0x30028001u;
    g->server.devId  = 12345;
}
#endif

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
    if (req == NULL || resp == NULL || resp_len == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (client_id < 0) {
        /* The SPM stamps NS callers as -(guest + 1); the mapping mirrors
         * wt_ffm_boot_caller_guest. */
        gid = (wt_guest_id_t)(-client_id - 1);
    }
#if defined(CONFIG_PKCS11) && defined(WT_INTERFACE_LOCAL_PROVIDER)
    else if (g_secure_client_bound && client_id == g_secure_client_id) {
        gid = g_secure_namespace_id;
    }
#endif
    else {
        return WH_ERROR_ACCESS;
    }
    if (gid >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    g = &g_guests[gid];
    buf = &g_relay_bufs[gid];
    *resp_len = 0U;
    /* Gate readiness before pinning so an unready guest returns NOTREADY
     * without the pin touching its server state. */
    if (!g->ready || g->transport_ctx != buf) {
        return WH_ERROR_NOTREADY;
    }
#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
    /* Forge in the same non-yielding window as the pin: the pump below must run
     * on repinned pointers or fault, so the guest crypto markers are proof the
     * relay pin ran on forged input every request (WT-FFM-0011). */
    wt_hsm_forge_server_ptrs(gid);
#endif
    wt_hsm_server_pin(gid);
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
        rc = (rc != WH_ERROR_OK) ? rc : WH_ERROR_ABORTED;
    }
    else if (buf->resp_len > resp_cap) {
        rc = WH_ERROR_ABORTED;
    }
    else {
        (void)memcpy(resp, buf->resp, buf->resp_len);
        *resp_len = buf->resp_len;
        rc = WH_ERROR_OK;
    }
    wt_hsm_force_zero(buf, sizeof(*buf));
    return rc;
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

/* Provisioning needs a coroutine (the NVM mutex refuses the boot context)
 * and the direct store, so it runs here, before the crypto partition's store
 * is rebound to its IPC view, on guest 0's tasklet; a port that seats its
 * guests later inherits the tasklet created here. */
int wt_hsm_attest_bootstrap(void)
{
    wt_tasklet_t *tasklet;

    if (g_hsm_attest_ready) {
        return WH_ERROR_OK;
    }
    tasklet = wt_hsm_guest_tasklet(0u);
    if (tasklet == NULL) {
        tasklet = wt_tasklet_create_blocked(wt_hsm_priv_stack(0u),
                                            WT_CO_STACK_SIZE,
                                            wt_hsm_tasklet_main,
                                            (void *)0);
        if (tasklet == NULL) {
            return WH_ERROR_ABORTED;
        }
        wt_hsm_priv_register(0u, tasklet);
    }
    wt_tasklet_wake(tasklet);
    if (wt_tasklet_resume(tasklet) == 0u) {
        return WH_ERROR_ABORTED;
    }
    return g_hsm_attest_ready ? WH_ERROR_OK : g_hsm_attest_init_status;
}

/* =========================================================================
 * wt_hsm_signal_fault
 *
 * Called from the Secure fault dispatcher for a terminal tasklet fault. Drops
 * any NVM lock the tasklet held, erases retained tasklet state, and clears
 * the ready bit so the relay rejects HSM calls from this guest.
 *
 * Idempotent: calling on an already-faulted guest is harmless.
 * ====================================================================== */
static int wt_hsm_attest_server_rebuild(void)
{
    int rc;

    (void)wh_Server_Cleanup(&g_hsm_attest_server);
    (void)wc_FreeRng(g_hsm_attest_crypto.rng);
    rc = wc_InitRng_ex(g_hsm_attest_crypto.rng, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wh_Server_Init(&g_hsm_attest_server, &g_hsm_attest_server_cfg);
    }
    if (rc == 0) {
        g_hsm_attest_server.comm->client_id = WH_CLIENT_ID_MAX;
        rc = wh_Server_SetConnected(&g_hsm_attest_server, WH_COMM_CONNECTED);
    }
    if (rc != 0) {
        /* Fail closed: a signer that could not be rebuilt reports not-ready
         * from here on, never the bootstrap's success status. */
        g_hsm_attest_ready = false;
        g_hsm_attest_init_status = WH_ERROR_NOTREADY;
    }
    return rc;
}

int wt_hsm_relay_reinit_servers(void)
{
    int             rc = WH_ERROR_OK;
    int             attest_rc = WH_ERROR_OK;
    wt_hsm_guest_t *g;
    wt_tasklet_t   *tasklet;
    wt_guest_id_t   gid;

    for (gid = 0; gid < WT_MAX_GUESTS; gid++) {
        g = &g_guests[gid];
        if (!g->ready) {
            continue;
        }
        /* Rebuild the server and DRBG in place after a fault tore them. Pin the
         * live server pointers first so wh_Server_Cleanup runs on trusted
         * transport/nvm/crypto pointers, then rebuild the config from trusted
         * constants for wh_Server_Init: a partition may have rewritten either
         * band-resident set before the fault (WT-FFM-0011). */
        wt_hsm_server_pin(gid);
        (void)wh_Server_Cleanup(&g->server);
        (void)wc_FreeRng(g->crypto.rng);
        wt_hsm_force_zero(&g_relay_bufs[gid], sizeof(g_relay_bufs[gid]));
        wt_hsm_force_zero(&g->server, sizeof(g->server));
        wt_hsm_force_zero(&g->crypto, sizeof(g->crypto));
        rc = wc_InitRng_ex(g->crypto.rng, NULL, INVALID_DEVID);
        if (rc == 0) {
            wt_hsm_bind_server_cfg(gid);
            rc = wh_Server_Init(&g->server, &g->server_cfg);
        }
        if (rc == 0) {
            rc = wh_Server_SetConnected(&g->server, WH_COMM_CONNECTED);
        }
        if (rc != 0) {
            wt_hsm_force_zero(&g->server, sizeof(g->server));
            wt_hsm_force_zero(&g->crypto, sizeof(g->crypto));
            tasklet = wt_hsm_guest_tasklet(gid);
            if (tasklet != NULL) {
                wt_hsm_release_locks(tasklet);
                wt_tasklet_mark_faulted(tasklet);
            }
            g->ready = false;
            break;
        }
    }
    /* The signer may have been torn by the same fault; rebuild it whether
     * or not a guest server failed above, so it never stays ready stale. */
    if (g_hsm_attest_ready) {
        attest_rc = wt_hsm_attest_server_rebuild();
    }
    if (rc == WH_ERROR_OK) {
        rc = attest_rc;
    }
    return rc;
}

int wt_hsm_bind_nvm(whNvmContext* nvm)
{
    wt_guest_id_t gid;

    if (nvm == NULL) {
        return WH_ERROR_BADARGS;
    }
    g_hsm_nvm = nvm;
    for (gid = 0; gid < WT_MAX_GUESTS; gid++) {
        g_guests[gid].server_cfg.nvm = nvm;
    }
    g_hsm_attest_server_cfg.nvm = nvm;
    return wt_hsm_relay_reinit_servers();
}

int wt_hsm_signal_fault(wt_guest_id_t guest_id)
{
    wt_hsm_guest_t *g;
    wt_tasklet_t   *tasklet;

    if (guest_id >= WT_MAX_GUESTS) {
        return WH_ERROR_BADARGS;
    }
    g = &g_guests[guest_id];
    tasklet = wt_hsm_guest_tasklet(guest_id);

    /* Force-release the NVM lock if the faulted tasklet was its holder.
     * This is the only mutex in the secure-side wolfHSM service; if more
     * are added later, this is the place to drop them all. */
    if (tasklet != NULL) {
        wt_hsm_release_locks(tasklet);
    }

    wt_hsm_force_zero(&g_relay_bufs[guest_id],
                      sizeof(g_relay_bufs[guest_id]));
    wt_hsm_force_zero(&g->server, sizeof(g->server));
    wt_hsm_force_zero(&g->crypto, sizeof(g->crypto));
    wt_hsm_priv_wipe_stack(guest_id);
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

static const whTransportServerCb g_hsm_attest_transport_cb = {
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

    ret = wh_Server_HandleKeyRequest(&g_hsm_attest_server,
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
        g_hsm_attest_public_key[0] = 0x04u;
        ret = wc_ecc_export_public_raw(&publicKey,
            &g_hsm_attest_public_key[1], &xSize,
            &g_hsm_attest_public_key[33], &ySize);
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

    ret = wh_Server_HandleCryptoRequest(&g_hsm_attest_server,
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
        ret = wh_Server_KeystoreCommitKey(&g_hsm_attest_server, serverKeyId);
    }

    wt_hsm_force_zero(&request, sizeof(request));
    wt_hsm_force_zero(&response, sizeof(response));
    return ret;
}

/* Bring up the signer's own server on the bound store. */
static int wt_hsm_attest_server_open(void)
{
    int ret;

    (void)memset(&g_hsm_attest_crypto, 0, sizeof(g_hsm_attest_crypto));
    ret = wc_InitRng_ex(g_hsm_attest_crypto.rng, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    (void)memset(&g_hsm_attest_comm_cfg, 0, sizeof(g_hsm_attest_comm_cfg));
    g_hsm_attest_comm_cfg.transport_cb = &g_hsm_attest_transport_cb;
    g_hsm_attest_comm_cfg.server_id = 0u;

    (void)memset(&g_hsm_attest_server_cfg, 0, sizeof(g_hsm_attest_server_cfg));
    g_hsm_attest_server_cfg.comm_config = &g_hsm_attest_comm_cfg;
    g_hsm_attest_server_cfg.nvm = g_hsm_nvm;
    g_hsm_attest_server_cfg.crypto = &g_hsm_attest_crypto;
#if defined(WOLF_CRYPTO_CB)
    g_hsm_attest_server_cfg.devId = INVALID_DEVID;
#endif

    ret = wh_Server_Init(&g_hsm_attest_server, &g_hsm_attest_server_cfg);
    if (ret == WH_ERROR_OK) {
        g_hsm_attest_server.comm->client_id = WH_CLIENT_ID_MAX;
        ret = wh_Server_SetConnected(&g_hsm_attest_server, WH_COMM_CONNECTED);
    }
    return ret;
}

int wt_hsm_attest_restore(const uint8_t* publicKey, size_t publicKeySize)
{
    int ret;

    /* Boot provisioned no signer: it stays not ready (fail closed). */
    if (publicKey == NULL ||
            publicKeySize != WT_HSM_ATTEST_PUBLIC_KEY_SIZE) {
        return WH_ERROR_OK;
    }
    g_hsm_attest_init_attempted = true;
    ret = wt_hsm_attest_server_open();
    if (ret == WH_ERROR_OK) {
        (void)memcpy(g_hsm_attest_public_key, publicKey, publicKeySize);
        g_hsm_attest_ready = true;
    }
    g_hsm_attest_init_status = ret;
    return ret;
}

int wt_hsm_attest_init(void)
{
    int ret;

#if defined(WT_VAULT_FOREIGN_PROBE) && defined(WT_VAULT_PROBE_SECURED)
    wt_hsm_set_boot_lifecycle(PSA_LIFECYCLE_SECURED);
#endif
    if (g_hsm_attest_ready) {
        return WH_ERROR_OK;
    }
    if (g_hsm_attest_init_attempted) {
        return g_hsm_attest_init_status;
    }
    g_hsm_attest_init_attempted = true;

    ret = wt_hsm_attest_server_open();
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
                    ret = wh_Server_Init(&g_hsm_attest_server,
                                         &g_hsm_attest_server_cfg);
                    if (ret == WH_ERROR_OK) {
                        g_hsm_attest_server.comm->client_id = WH_CLIENT_ID_MAX;
                        ret = wh_Server_SetConnected(&g_hsm_attest_server,
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
        g_hsm_attest_ready = true;
    }
    else {
        wt_hsm_force_zero(g_hsm_attest_public_key,
                          sizeof(g_hsm_attest_public_key));
    }
    g_hsm_attest_init_status = ret;
    return g_hsm_attest_init_status;
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
    if (!g_hsm_attest_ready) {
        return (g_hsm_attest_init_status != WH_ERROR_OK) ?
               g_hsm_attest_init_status : WH_ERROR_NOTREADY;
    }
    if ((digest == NULL) || (digestSize != 32u) ||
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

    ret = wh_Server_HandleCryptoRequest(&g_hsm_attest_server,
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
    if (!g_hsm_attest_ready) {
        return (g_hsm_attest_init_status != WH_ERROR_OK) ?
               g_hsm_attest_init_status : WH_ERROR_NOTREADY;
    }
    if ((publicKey == NULL) ||
        (publicKeyCapacity < WT_HSM_ATTEST_PUBLIC_KEY_SIZE)) {
        return WH_ERROR_BADARGS;
    }

    (void)memcpy(publicKey, g_hsm_attest_public_key,
                 WT_HSM_ATTEST_PUBLIC_KEY_SIZE);
    return WH_ERROR_OK;
}

#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
/* used + noinline so the hsmpinneg runner can confirm through nm that the
 * probe is present rather than inlined away under LTO. */
__attribute__((used, noinline))
int wt_platform_hsm_pin_probe(void)
{
    /* The relay forges and re-pins the per-guest pointers on every pump; here
     * verify the door view's chain. The vault checks the direct store's. */
    return wt_nvm_client_partition_pin_probe();
}
#endif
