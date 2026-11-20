/* psa_crypto_service.c
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

/* Secure PSA Crypto (WT_SECURE_PSA=1): wolfPSA runs in the crypto
 * partition and Non-secure clients reach it through the native wire. Keys
 * and operation state never leave this band; every key id and operation
 * token is checked against the SPM-stamped client. */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "psa/crypto.h"
#include "wolfpsa/psa_store.h"

#include "wolftrust/zeroize.h"
#include "wolftrust/services/crypto_native.h"
#include "wolftrust/services/psa_crypto_service.h"

#include <string.h>

#ifndef WT_PSA_KEY_SLOTS
#define WT_PSA_KEY_SLOTS 16U
#endif
#ifndef WT_PSA_OP_SLOTS
#define WT_PSA_OP_SLOTS 8U
#endif
#ifndef WT_PSA_CLIENTS
#if defined(WT_MAX_GUESTS) && WT_MAX_GUESTS > 0
#define WT_PSA_CLIENTS (WT_MAX_GUESTS)
#else
#define WT_PSA_CLIENTS 2U
#endif
#endif
#define WT_PSA_KEY_QUOTA (WT_PSA_KEY_SLOTS / WT_PSA_CLIENTS)
#define WT_PSA_OP_QUOTA  (WT_PSA_OP_SLOTS / WT_PSA_CLIENTS)
#if WT_PSA_KEY_QUOTA < 1 || WT_PSA_OP_QUOTA < 1 || WT_PSA_OP_SLOTS > 256
#error "WT_PSA_KEY_SLOTS and WT_PSA_OP_SLOTS need one slot per client, ops at most 256"
#endif
/* One arena per client: a call's keys and operation state, and what it holds. */
#ifndef WT_PSA_POOL_BYTES
#define WT_PSA_POOL_BYTES (WT_PSA_CLIENTS * 2048U)
#endif
#if WT_PSA_POOL_BYTES / WT_PSA_CLIENTS < 1536
#error "WT_PSA_POOL_BYTES needs at least 1536 bytes per client"
#endif

/* An operation slot's 24-bit generation: a slot that has used them all is
 * retired until the service restarts, so a token never repeats. */
#ifndef WT_PSA_GEN_MAX
#define WT_PSA_GEN_MAX 0xFFFFFFU
#endif

#define WT_PSA_KIND_HASH   1U
#define WT_PSA_KIND_MAC    2U
#define WT_PSA_KIND_CIPHER 3U
#define WT_PSA_KIND_AEAD   4U
#define WT_PSA_KIND_KDF    5U

#define WT_PSA_CAP_UNLIMITED 0xFFFFFFFFU

/* -------------------------------------------------------------------------
 * Partition-private allocator for wolfPSA's XMALLOC: one first-fit arena per
 * client in the crypto partition's band, scrubbed on free. A call allocates
 * only from its caller's arena, so one guest cannot starve another.
 * ---------------------------------------------------------------------- */
/* ALIGN16 contexts in wolfCrypt need 16-byte blocks under WOLFSSL_USE_ALIGN. */
#ifdef WOLFSSL_USE_ALIGN
#define WT_PSA_POOL_ALIGN 16U
#else
#define WT_PSA_POOL_ALIGN 8U
#endif

typedef union {
    struct {
        uint32_t size;
        uint32_t used;
    } h;
    uint64_t align;
    uint8_t pad[WT_PSA_POOL_ALIGN];
} wt_psa_blk_t;

#define WT_PSA_ARENA_BLKS \
    (WT_PSA_POOL_BYTES / WT_PSA_CLIENTS / sizeof(wt_psa_blk_t))
#define WT_PSA_ARENA_BYTES (WT_PSA_ARENA_BLKS * sizeof(wt_psa_blk_t))

static ALIGN16 wt_psa_blk_t g_wt_psa_pool[WT_PSA_CLIENTS][WT_PSA_ARENA_BLKS];
static uint8_t g_wt_psa_pool_ready[WT_PSA_CLIENTS];
/* The calling client's arena plus one, 0 outside a call. */
static size_t g_wt_psa_arena;
#ifdef WT_PSA_POOL_STATS
static size_t g_wt_psa_pool_in_use[WT_PSA_CLIENTS];
static size_t g_wt_psa_pool_peak;
static size_t g_wt_psa_pool_hwm;

void wt_psa_pool_stats(size_t* in_use, size_t* peak, size_t* hwm)
{
    size_t i;

    *in_use = 0U;
    for (i = 0U; i < WT_PSA_CLIENTS; i++) {
        *in_use += g_wt_psa_pool_in_use[i];
    }
    *peak = g_wt_psa_pool_peak;
    *hwm = g_wt_psa_pool_hwm;
}

void wt_psa_pool_stats_mark(void)
{
    g_wt_psa_pool_peak = 0U;
}

size_t wt_psa_pool_arena_in_use(size_t arena)
{
    return (arena < WT_PSA_CLIENTS) ? g_wt_psa_pool_in_use[arena] : 0U;
}
#endif

void* wt_psa_pool_alloc(unsigned int sz)
{
    uint8_t* p;
    uint8_t* end;
    wt_psa_blk_t* b;
    wt_psa_blk_t* n;
    uint32_t need;
    size_t a;

    if (g_wt_psa_arena == 0U || g_wt_psa_arena > WT_PSA_CLIENTS ||
            sz == 0U || sz > WT_PSA_ARENA_BYTES) {
        return NULL;
    }
    a = g_wt_psa_arena - 1U;
    p = (uint8_t*)g_wt_psa_pool[a];
    end = p + WT_PSA_ARENA_BYTES;
    need = ((uint32_t)sz + (uint32_t)sizeof(*b) - 1U) &
           ~((uint32_t)sizeof(*b) - 1U);
    if (g_wt_psa_pool_ready[a] == 0U) {
        b = (wt_psa_blk_t*)p;
        b->h.size = (uint32_t)WT_PSA_ARENA_BYTES - (uint32_t)sizeof(*b);
        b->h.used = 0U;
        g_wt_psa_pool_ready[a] = 1U;
    }
    while (p < end) {
        b = (wt_psa_blk_t*)p;
        if (b->h.used == 0U && b->h.size >= need) {
            if (b->h.size >= need + 2U * (uint32_t)sizeof(*b)) {
                n = (wt_psa_blk_t*)(p + sizeof(*b) + need);
                n->h.size = b->h.size - need - (uint32_t)sizeof(*b);
                n->h.used = 0U;
                b->h.size = need;
            }
            b->h.used = 1U;
#ifdef WT_PSA_POOL_STATS
            g_wt_psa_pool_in_use[a] += sizeof(*b) + b->h.size;
            if (g_wt_psa_pool_in_use[a] > g_wt_psa_pool_peak) {
                g_wt_psa_pool_peak = g_wt_psa_pool_in_use[a];
            }
            if ((size_t)(p - (uint8_t*)g_wt_psa_pool[a]) + sizeof(*b) +
                    b->h.size > g_wt_psa_pool_hwm) {
                g_wt_psa_pool_hwm = (size_t)(p - (uint8_t*)g_wt_psa_pool[a]) +
                                    sizeof(*b) + b->h.size;
            }
#endif
            return p + sizeof(*b);
        }
        p += sizeof(*b) + b->h.size;
    }
    return NULL;
}

void wt_psa_pool_free(void* ptr)
{
    uint8_t* base = (uint8_t*)g_wt_psa_pool;
    uint8_t* p;
    uint8_t* end;
    wt_psa_blk_t* b;
    wt_psa_blk_t* n;
    size_t a;

    if (ptr == NULL || (uint8_t*)ptr < base + sizeof(*b) ||
            (uint8_t*)ptr >= base + sizeof(g_wt_psa_pool)) {
        return;
    }
    a = (size_t)((uint8_t*)ptr - base) / WT_PSA_ARENA_BYTES;
    p = (uint8_t*)g_wt_psa_pool[a];
    end = p + WT_PSA_ARENA_BYTES;
    b = (wt_psa_blk_t*)((uint8_t*)ptr - sizeof(*b));
    wt_forceZero(ptr, b->h.size);
    b->h.used = 0U;
#ifdef WT_PSA_POOL_STATS
    g_wt_psa_pool_in_use[a] -= sizeof(*b) + b->h.size;
#endif
    while (p < end) {
        b = (wt_psa_blk_t*)p;
        n = (wt_psa_blk_t*)(p + sizeof(*b) + b->h.size);
        if (b->h.used == 0U && (uint8_t*)n < end && n->h.used == 0U) {
            b->h.size += (uint32_t)sizeof(*b) + n->h.size;
        }
        else {
            p = (uint8_t*)n;
        }
    }
}

void* wt_psa_pool_realloc(void* ptr, unsigned int sz)
{
    wt_psa_blk_t* b;
    void* q;

    if (ptr == NULL) {
        return wt_psa_pool_alloc(sz);
    }
    b = (wt_psa_blk_t*)((uint8_t*)ptr - sizeof(*b));
    if (b->h.size >= sz) {
        return ptr;
    }
    q = wt_psa_pool_alloc(sz);
    if (q != NULL) {
        (void)memcpy(q, ptr, b->h.size);
        wt_psa_pool_free(ptr);
    }
    return q;
}

/* -------------------------------------------------------------------------
 * Per-client state: volatile key owners and operation slots.
 * ---------------------------------------------------------------------- */
typedef struct {
    psa_key_id_t id;
    int32_t owner;
} wt_psa_key_t;

typedef struct {
    union {
        psa_hash_operation_t hash;
        psa_mac_operation_t mac;
        psa_cipher_operation_t cipher;
        psa_aead_operation_t aead;
        psa_key_derivation_operation_t kdf;
    } u;
    int32_t owner;
    uint32_t gen;
    uint8_t kind;
    uint8_t used;
} wt_psa_op_t;

/* A client's index here picks its operation slot range and pool arena. */
typedef struct {
    int32_t owner;
} wt_psa_client_t;

typedef struct {
    uint64_t uid;
    uint32_t off;
    uint8_t open;
    uint8_t read;
    uint8_t written;
} wt_psa_store_t;

static wt_psa_key_t g_psa_keys[WT_PSA_KEY_SLOTS];
static wt_psa_op_t g_psa_ops[WT_PSA_OP_SLOTS];
static wt_psa_op_t g_psa_idle_op;
static wt_psa_client_t g_psa_clients[WT_PSA_CLIENTS];
static wt_psa_store_t g_psa_store;
static uint32_t g_psa_nonce;
static int32_t g_psa_owner;
static int32_t g_psa_client;

static wt_psa_client_t* wt_psa_client_of(int32_t client);

/* -------------------------------------------------------------------------
 * wolfPSA store backend: persistent keys are opaque keyvault records in the
 * calling client's namespace, so equal key ids of two clients never meet.
 * ---------------------------------------------------------------------- */
int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2,
                         int read, int variableSz, void** store)
{
    psa_status_t status;

    (void)id2;
    (void)variableSz;
    if (type != WOLFPSA_STORE_KEY || store == NULL || g_psa_store.open != 0U) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if (id1 < PSA_KEY_ID_USER_MIN || id1 > PSA_KEY_ID_USER_MAX) {
        return (read != 0) ? WOLFPSA_STORE_NOT_AVAILABLE :
               WOLFPSA_STORE_IO_ERROR;
    }
    if (read != 0) {
        status = wt_hsm_keyvault_rec_get(g_psa_owner, g_psa_client,
                                         WT_PSA_UID(id1), 0U, NULL, 0U, NULL);
        if (status == PSA_ERROR_DOES_NOT_EXIST) {
            return WOLFPSA_STORE_NOT_AVAILABLE;
        }
        if (status != PSA_SUCCESS) {
            return WOLFPSA_STORE_IO_ERROR;
        }
    }
    g_psa_store.uid = WT_PSA_UID(id1);
    g_psa_store.off = 0U;
    g_psa_store.read = (read != 0) ? 1U : 0U;
    g_psa_store.written = 0U;
    g_psa_store.open = 1U;
    *store = &g_psa_store;
    return WOLFPSA_STORE_OK;
}

int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2,
                       int read, void** store)
{
    return wolfPSA_Store_OpenSz(type, id1, id2, read, 0, store);
}

int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    psa_status_t status;

    (void)id2;
    if (type != WOLFPSA_STORE_KEY) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if (id1 < PSA_KEY_ID_USER_MIN || id1 > PSA_KEY_ID_USER_MAX) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }
    status = wt_hsm_keyvault_rec_remove(g_psa_owner, g_psa_client,
                                        WT_PSA_UID(id1));
    if (status == PSA_ERROR_DOES_NOT_EXIST) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }
    return (status == PSA_SUCCESS) ? WOLFPSA_STORE_OK : WOLFPSA_STORE_IO_ERROR;
}

int wolfPSA_Store_Close(void* store)
{
    if (store != &g_psa_store) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    (void)memset(&g_psa_store, 0, sizeof(g_psa_store));
    return WOLFPSA_STORE_OK;
}

int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len)
{
    if (store != &g_psa_store || g_psa_store.open == 0U ||
            g_psa_store.read == 0U || buffer == NULL || len <= 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if (wt_hsm_keyvault_rec_get(g_psa_owner, g_psa_client, g_psa_store.uid,
                                g_psa_store.off, buffer, (size_t)len,
                                NULL) != PSA_SUCCESS) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    g_psa_store.off += (uint32_t)len;
    return len;
}

/* wolfPSA writes a record in one piece, so it is committed here. */
int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len)
{
    if (store != &g_psa_store || g_psa_store.open == 0U ||
            g_psa_store.read != 0U || g_psa_store.written != 0U ||
            buffer == NULL || len <= 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if (wt_hsm_keyvault_rec_put(g_psa_owner, g_psa_client, g_psa_store.uid,
                                buffer, (size_t)len) != PSA_SUCCESS) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    g_psa_store.written = 1U;
    return len;
}

/* -------------------------------------------------------------------------
 * Ownership checks.
 * ---------------------------------------------------------------------- */
static int wt_psa_is_user_id(psa_key_id_t id)
{
    return (id >= PSA_KEY_ID_USER_MIN && id <= PSA_KEY_ID_USER_MAX) ? 1 : 0;
}

/* Persistent ids are namespaced by the store; volatile ids must be the
 * caller's own. Id 0 names no key, so wolfPSA reports it. */
static psa_status_t wt_psa_key_ok(psa_key_id_t id)
{
    size_t i;

    if (id == PSA_KEY_ID_NULL || wt_psa_is_user_id(id) != 0) {
        return PSA_SUCCESS;
    }
    for (i = 0U; i < WT_PSA_KEY_SLOTS; i++) {
        if (g_psa_keys[i].id == id && g_psa_keys[i].owner == g_psa_client) {
            return PSA_SUCCESS;
        }
    }
    return PSA_ERROR_INVALID_HANDLE;
}

/* A new key: persistent ids stay in the user range, and a volatile key
 * needs a free owner slot within the caller's quota. */
static psa_status_t wt_psa_key_room(const psa_key_attributes_t* attr)
{
    size_t i;
    size_t mine = 0U;
    size_t free_slots = 0U;

    if (PSA_KEY_LIFETIME_GET_PERSISTENCE(attr->lifetime) !=
            PSA_KEY_PERSISTENCE_VOLATILE) {
        return (wt_psa_is_user_id(attr->id) != 0) ? PSA_SUCCESS :
               PSA_ERROR_INVALID_ARGUMENT;
    }
    for (i = 0U; i < WT_PSA_KEY_SLOTS; i++) {
        if (g_psa_keys[i].id == PSA_KEY_ID_NULL) {
            free_slots++;
        }
        else if (g_psa_keys[i].owner == g_psa_client) {
            mine++;
        }
    }
    return (free_slots != 0U && mine < WT_PSA_KEY_QUOTA) ? PSA_SUCCESS :
           PSA_ERROR_INSUFFICIENT_MEMORY;
}

static psa_status_t wt_psa_key_add(psa_status_t status, psa_key_id_t id)
{
    size_t i;

    if (status != PSA_SUCCESS || wt_psa_is_user_id(id) != 0) {
        return status;
    }
    for (i = 0U; i < WT_PSA_KEY_SLOTS; i++) {
        if (g_psa_keys[i].id == PSA_KEY_ID_NULL) {
            g_psa_keys[i].id = id;
            g_psa_keys[i].owner = g_psa_client;
            return PSA_SUCCESS;
        }
    }
    (void)psa_destroy_key(id);
    return PSA_ERROR_INSUFFICIENT_MEMORY;
}

static void wt_psa_key_drop(psa_key_id_t id)
{
    size_t i;

    for (i = 0U; i < WT_PSA_KEY_SLOTS; i++) {
        if (g_psa_keys[i].id == id && g_psa_keys[i].owner == g_psa_client) {
            g_psa_keys[i].id = PSA_KEY_ID_NULL;
            g_psa_keys[i].owner = 0;
        }
    }
}

static uint32_t wt_psa_op_token(const wt_psa_op_t* op)
{
    uint32_t idx = (uint32_t)(op - g_psa_ops);

    return ((op->gen << 8) | idx) ^ g_psa_nonce;
}

/* Resolve a client token. Token 0 is an inactive operation: setup claims a
 * slot, anything else runs on a zeroed operation so wolfPSA reports the
 * state error. A token that does not validate is a bad state. */
static wt_psa_op_t* wt_psa_op_for(uint32_t token, uint8_t kind, int setup,
                                  psa_status_t* status)
{
    wt_psa_op_t* op = NULL;
    wt_psa_client_t* cl;
    uint32_t x = token ^ g_psa_nonce;
    size_t i;
    size_t end;

    *status = PSA_SUCCESS;
    if (token != 0U) {
        i = (size_t)(x & 0xFFU);
        if (i < WT_PSA_OP_SLOTS && g_psa_ops[i].used != 0U &&
                g_psa_ops[i].owner == g_psa_client &&
                g_psa_ops[i].kind == kind &&
                g_psa_ops[i].gen == (x >> 8)) {
            op = &g_psa_ops[i];
        }
        else {
            *status = PSA_ERROR_BAD_STATE;
        }
    }
    else if (setup == 0) {
        (void)memset(&g_psa_idle_op, 0, sizeof(g_psa_idle_op));
        op = &g_psa_idle_op;
    }
    else {
        /* Each client draws from its own slot range, its quota. */
        cl = wt_psa_client_of(g_psa_client);
        i = (cl != NULL) ? (size_t)(cl - g_psa_clients) * WT_PSA_OP_QUOTA :
            WT_PSA_OP_SLOTS;
        end = i + WT_PSA_OP_QUOTA;
        for (; op == NULL && i < end && i < WT_PSA_OP_SLOTS; i++) {
            if (g_psa_ops[i].used == 0U &&
                    g_psa_ops[i].gen + 2U <= WT_PSA_GEN_MAX) {
                op = &g_psa_ops[i];
            }
        }
        if (op == NULL) {
            *status = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        else {
            (void)memset(&op->u, 0, sizeof(op->u));
            op->owner = g_psa_client;
            op->kind = kind;
            op->used = 1U;
            op->gen++;
            if (wt_psa_op_token(op) == 0U) {
                op->gen++;
            }
        }
    }
    return op;
}

/* An operation wolfPSA has released frees its slot; the client sees 0. */
static uint32_t wt_psa_op_sync(wt_psa_op_t* op)
{
    if (op == NULL || op == &g_psa_idle_op) {
        return 0U;
    }
    if (op->u.hash.opaque == 0U) {
        op->used = 0U;
        op->owner = 0;
        return 0U;
    }
    return wt_psa_op_token(op);
}

static void wt_psa_op_abort(wt_psa_op_t* op)
{
    uint32_t gen;

    switch (op->kind) {
    case WT_PSA_KIND_HASH:
        (void)psa_hash_abort(&op->u.hash);
        break;
    case WT_PSA_KIND_MAC:
        (void)psa_mac_abort(&op->u.mac);
        break;
    case WT_PSA_KIND_CIPHER:
        (void)psa_cipher_abort(&op->u.cipher);
        break;
    case WT_PSA_KIND_AEAD:
        (void)psa_aead_abort(&op->u.aead);
        break;
    default:
        (void)psa_key_derivation_abort(&op->u.kdf);
        break;
    }
    gen = op->gen;
    (void)memset(op, 0, sizeof(*op));
    op->gen = gen;
}

static wt_psa_client_t* wt_psa_client_of(int32_t client)
{
    wt_psa_client_t* free_entry = NULL;
    size_t i;

    for (i = 0U; i < WT_PSA_CLIENTS; i++) {
        if (g_psa_clients[i].owner == client) {
            return &g_psa_clients[i];
        }
        if (g_psa_clients[i].owner == 0 && free_entry == NULL) {
            free_entry = &g_psa_clients[i];
        }
    }
    if (free_entry != NULL) {
        free_entry->owner = client;
    }
    return free_entry;
}

/* A client (re)starting PSA Crypto drops everything it held before. */
static void wt_psa_client_reset(int32_t client)
{
    size_t i;

    for (i = 0U; i < WT_PSA_KEY_SLOTS; i++) {
        if (g_psa_keys[i].id != PSA_KEY_ID_NULL &&
                g_psa_keys[i].owner == client) {
            (void)psa_destroy_key(g_psa_keys[i].id);
            g_psa_keys[i].id = PSA_KEY_ID_NULL;
            g_psa_keys[i].owner = 0;
        }
    }
    for (i = 0U; i < WT_PSA_OP_SLOTS; i++) {
        if (g_psa_ops[i].used != 0U && g_psa_ops[i].owner == client) {
            wt_psa_op_abort(&g_psa_ops[i]);
        }
    }
}

/* -------------------------------------------------------------------------
 * Attributes wire form.
 * ---------------------------------------------------------------------- */
static uint32_t wt_psa_rd32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void wt_psa_wr32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static psa_status_t wt_psa_attr_get(const uint8_t* p, size_t len,
                                    psa_key_attributes_t* attr)
{
    uint32_t tb;

    if (p == NULL || len != WT_PSA_WIRE_ATTR_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *attr = psa_key_attributes_init();
    tb = wt_psa_rd32(p);
    attr->type = (psa_key_type_t)(tb & 0xFFFFU);
    attr->bits = (psa_key_bits_t)(tb >> 16);
    attr->lifetime = (psa_key_lifetime_t)wt_psa_rd32(p + 4);
    attr->policy.usage = (psa_key_usage_t)wt_psa_rd32(p + 8);
    attr->policy.alg = (psa_algorithm_t)wt_psa_rd32(p + 12);
    attr->policy.alg2 = (psa_algorithm_t)wt_psa_rd32(p + 16);
    attr->id = (psa_key_id_t)wt_psa_rd32(p + 20);
#ifdef WT_SECURE_PSA_symmetric
    /* wolfCrypt keeps ECC for the native engine; the profile serves none. */
    if (PSA_KEY_TYPE_IS_ECC(attr->type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
    return wt_psa_key_room(attr);
}

static psa_status_t wt_psa_attr_put(const psa_key_attributes_t* attr,
                                    uint8_t* p, size_t cap, size_t* len)
{
    if (cap < WT_PSA_WIRE_ATTR_LEN) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    wt_psa_wr32(p, (uint32_t)attr->type | ((uint32_t)attr->bits << 16));
    wt_psa_wr32(p + 4, (uint32_t)attr->lifetime);
    wt_psa_wr32(p + 8, (uint32_t)attr->policy.usage);
    wt_psa_wr32(p + 12, (uint32_t)attr->policy.alg);
    wt_psa_wr32(p + 16, (uint32_t)attr->policy.alg2);
    wt_psa_wr32(p + 20, (uint32_t)attr->id);
    *len = WT_PSA_WIRE_ATTR_LEN;
    return PSA_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Dispatch.
 * ---------------------------------------------------------------------- */
typedef struct {
    const wt_psa_wire_args_t* args;
    wt_psa_op_t* op;
    const uint8_t* in[WT_PSA_WIRE_IN_MAX];
    size_t in_len[WT_PSA_WIRE_IN_MAX];
    uint8_t* out[WT_PSA_WIRE_OUT_MAX];
    size_t out_cap[WT_PSA_WIRE_OUT_MAX];
    size_t out_len[WT_PSA_WIRE_OUT_MAX];
    uint32_t val;
} wt_psa_call_t;

#define A(i)   (c->args->a[(i)])
#define IN(i)  (c->in[(i)])
#define INL(i) (c->in_len[(i)])
#define OUT(i) (c->out[(i)])
#define CAP(i) (c->out_cap[(i)])
#define OL(i)  (&c->out_len[(i)])

/* Operation kind of fn (0 for one-shot calls); setup marks the calls that
 * may claim a slot. */
static uint8_t wt_psa_fn_kind(uint32_t fn, int* setup)
{
    uint8_t kind = 0U;

    *setup = (fn == WT_PSA_FN_HASH_SETUP || fn == WT_PSA_FN_HASH_CLONE ||
              fn == WT_PSA_FN_MAC_SIGN_SETUP ||
              fn == WT_PSA_FN_MAC_VERIFY_SETUP ||
              fn == WT_PSA_FN_CIPHER_ENCRYPT_SETUP ||
              fn == WT_PSA_FN_CIPHER_DECRYPT_SETUP ||
              fn == WT_PSA_FN_AEAD_ENCRYPT_SETUP ||
              fn == WT_PSA_FN_AEAD_DECRYPT_SETUP ||
              fn == WT_PSA_FN_KDF_SETUP) ? 1 : 0;
    if (fn >= WT_PSA_FN_HASH_SETUP && fn <= WT_PSA_FN_HASH_CLONE) {
        kind = WT_PSA_KIND_HASH;
    }
    else if (fn >= WT_PSA_FN_MAC_SIGN_SETUP && fn <= WT_PSA_FN_MAC_ABORT) {
        kind = WT_PSA_KIND_MAC;
    }
    else if (fn >= WT_PSA_FN_CIPHER_ENCRYPT_SETUP &&
             fn <= WT_PSA_FN_CIPHER_ABORT) {
        kind = WT_PSA_KIND_CIPHER;
    }
    else if (fn >= WT_PSA_FN_AEAD_ENCRYPT_SETUP &&
             fn <= WT_PSA_FN_AEAD_ABORT) {
        kind = WT_PSA_KIND_AEAD;
    }
    else if (fn >= WT_PSA_FN_KDF_SETUP && fn <= WT_PSA_FN_KDF_ABORT) {
        kind = WT_PSA_KIND_KDF;
    }
    return kind;
}

static size_t wt_psa_cap_in(uint32_t cap)
{
    return (cap == WT_PSA_CAP_UNLIMITED) ?
           PSA_KEY_DERIVATION_UNLIMITED_CAPACITY : (size_t)cap;
}

static psa_status_t wt_psa_keys_fn(uint32_t fn, wt_psa_call_t* c)
{
    psa_key_attributes_t attr;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t status;

    switch (fn) {
    case WT_PSA_FN_GENERATE_RANDOM:
        status = psa_generate_random(OUT(0), CAP(0));
        if (status == PSA_SUCCESS) {
            c->out_len[0] = CAP(0);
        }
        break;
    case WT_PSA_FN_GET_KEY_ATTRIBUTES:
        attr = psa_key_attributes_init();
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = psa_get_key_attributes(A(0), &attr);
        }
        if (status == PSA_SUCCESS) {
            status = wt_psa_attr_put(&attr, OUT(0), CAP(0), OL(0));
        }
        psa_reset_key_attributes(&attr);
        break;
    case WT_PSA_FN_IMPORT_KEY:
        status = wt_psa_attr_get(IN(0), INL(0), &attr);
        if (status == PSA_SUCCESS) {
            status = psa_import_key(&attr, IN(1), INL(1), &id);
            status = wt_psa_key_add(status, id);
        }
        c->val = (status == PSA_SUCCESS) ? id : 0U;
        break;
    case WT_PSA_FN_GENERATE_KEY:
        status = wt_psa_attr_get(IN(0), INL(0), &attr);
        if (status == PSA_SUCCESS) {
            status = psa_generate_key(&attr, &id);
            status = wt_psa_key_add(status, id);
        }
        c->val = (status == PSA_SUCCESS) ? id : 0U;
        break;
    case WT_PSA_FN_COPY_KEY:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = wt_psa_attr_get(IN(0), INL(0), &attr);
        }
        if (status == PSA_SUCCESS) {
            status = psa_copy_key(A(0), &attr, &id);
            status = wt_psa_key_add(status, id);
        }
        c->val = (status == PSA_SUCCESS) ? id : 0U;
        break;
    case WT_PSA_FN_EXPORT_KEY:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = psa_export_key(A(0), OUT(0), CAP(0), OL(0));
        }
        break;
    case WT_PSA_FN_EXPORT_PUBLIC_KEY:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = psa_export_public_key(A(0), OUT(0), CAP(0), OL(0));
        }
        break;
    case WT_PSA_FN_DESTROY_KEY:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = psa_destroy_key(A(0));
        }
        if (status == PSA_SUCCESS) {
            wt_psa_key_drop(A(0));
        }
        break;
    case WT_PSA_FN_PURGE_KEY:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = psa_purge_key(A(0));
        }
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }
    return status;
}

static psa_status_t wt_psa_hash_mac_fn(uint32_t fn, wt_psa_call_t* c)
{
    psa_hash_operation_t* h = &c->op->u.hash;
    psa_mac_operation_t* m = &c->op->u.mac;
    wt_psa_op_t* tgt;
    psa_status_t status = PSA_SUCCESS;

    switch (fn) {
    case WT_PSA_FN_HASH_COMPUTE:
        status = psa_hash_compute(A(0), IN(0), INL(0), OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_HASH_COMPARE:
        status = psa_hash_compare(A(0), IN(0), INL(0), IN(1), INL(1));
        break;
    case WT_PSA_FN_HASH_SETUP:
        status = psa_hash_setup(h, A(1));
        break;
    case WT_PSA_FN_HASH_UPDATE:
        status = psa_hash_update(h, IN(0), INL(0));
        break;
    case WT_PSA_FN_HASH_FINISH:
        status = psa_hash_finish(h, OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_HASH_VERIFY:
        status = psa_hash_verify(h, IN(0), INL(0));
        break;
    case WT_PSA_FN_HASH_ABORT:
        status = psa_hash_abort(h);
        break;
    case WT_PSA_FN_HASH_CLONE:
        /* a0 is the target; a1 the source, which must already be live. */
        tgt = c->op;
        c->op = wt_psa_op_for(A(1), WT_PSA_KIND_HASH, 0, &status);
        if (c->op != NULL) {
            status = psa_hash_clone(&c->op->u.hash, &tgt->u.hash);
        }
        c->op = tgt;
        break;
    case WT_PSA_FN_MAC_COMPUTE:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = psa_mac_compute(A(0), A(1), IN(0), INL(0), OUT(0), CAP(0),
                                     OL(0));
        }
        break;
    case WT_PSA_FN_MAC_VERIFY:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = psa_mac_verify(A(0), A(1), IN(0), INL(0), IN(1), INL(1));
        }
        break;
    case WT_PSA_FN_MAC_SIGN_SETUP:
    case WT_PSA_FN_MAC_VERIFY_SETUP:
        status = wt_psa_key_ok(A(1));
        if (status == PSA_SUCCESS) {
            status = (fn == WT_PSA_FN_MAC_SIGN_SETUP) ?
                     psa_mac_sign_setup(m, A(1), A(2)) :
                     psa_mac_verify_setup(m, A(1), A(2));
        }
        break;
    case WT_PSA_FN_MAC_UPDATE:
        status = psa_mac_update(m, IN(0), INL(0));
        break;
    case WT_PSA_FN_MAC_SIGN_FINISH:
        status = psa_mac_sign_finish(m, OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_MAC_VERIFY_FINISH:
        status = psa_mac_verify_finish(m, IN(0), INL(0));
        break;
    default:
        status = psa_mac_abort(m);
        break;
    }
    return status;
}

static psa_status_t wt_psa_cipher_fn(uint32_t fn, wt_psa_call_t* c)
{
    psa_cipher_operation_t* o = &c->op->u.cipher;
    psa_status_t status;

    switch (fn) {
    case WT_PSA_FN_CIPHER_ENCRYPT:
    case WT_PSA_FN_CIPHER_DECRYPT:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = (fn == WT_PSA_FN_CIPHER_ENCRYPT) ?
                     psa_cipher_encrypt(A(0), A(1), IN(0), INL(0), OUT(0),
                                        CAP(0), OL(0)) :
                     psa_cipher_decrypt(A(0), A(1), IN(0), INL(0), OUT(0),
                                        CAP(0), OL(0));
        }
        break;
    case WT_PSA_FN_CIPHER_ENCRYPT_SETUP:
    case WT_PSA_FN_CIPHER_DECRYPT_SETUP:
        status = wt_psa_key_ok(A(1));
        if (status == PSA_SUCCESS) {
            status = (fn == WT_PSA_FN_CIPHER_ENCRYPT_SETUP) ?
                     psa_cipher_encrypt_setup(o, A(1), A(2)) :
                     psa_cipher_decrypt_setup(o, A(1), A(2));
        }
        break;
    case WT_PSA_FN_CIPHER_GENERATE_IV:
        status = psa_cipher_generate_iv(o, OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_CIPHER_SET_IV:
        status = psa_cipher_set_iv(o, IN(0), INL(0));
        break;
    case WT_PSA_FN_CIPHER_UPDATE:
        status = psa_cipher_update(o, IN(0), INL(0), OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_CIPHER_FINISH:
        status = psa_cipher_finish(o, OUT(0), CAP(0), OL(0));
        break;
    default:
        status = psa_cipher_abort(o);
        break;
    }
    return status;
}

static psa_status_t wt_psa_aead_fn(uint32_t fn, wt_psa_call_t* c)
{
    psa_aead_operation_t* o = &c->op->u.aead;
    psa_status_t status;

    switch (fn) {
    case WT_PSA_FN_AEAD_ENCRYPT:
    case WT_PSA_FN_AEAD_DECRYPT:
        status = wt_psa_key_ok(A(0));
        if (status == PSA_SUCCESS) {
            status = (fn == WT_PSA_FN_AEAD_ENCRYPT) ?
                     psa_aead_encrypt(A(0), A(1), IN(0), INL(0), IN(1), INL(1),
                                      IN(2), INL(2), OUT(0), CAP(0), OL(0)) :
                     psa_aead_decrypt(A(0), A(1), IN(0), INL(0), IN(1), INL(1),
                                      IN(2), INL(2), OUT(0), CAP(0), OL(0));
        }
        break;
    case WT_PSA_FN_AEAD_ENCRYPT_SETUP:
    case WT_PSA_FN_AEAD_DECRYPT_SETUP:
        status = wt_psa_key_ok(A(1));
        if (status == PSA_SUCCESS) {
            status = (fn == WT_PSA_FN_AEAD_ENCRYPT_SETUP) ?
                     psa_aead_encrypt_setup(o, A(1), A(2)) :
                     psa_aead_decrypt_setup(o, A(1), A(2));
        }
        break;
    case WT_PSA_FN_AEAD_GENERATE_NONCE:
        status = psa_aead_generate_nonce(o, OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_AEAD_SET_NONCE:
        status = psa_aead_set_nonce(o, IN(0), INL(0));
        break;
    case WT_PSA_FN_AEAD_SET_LENGTHS:
        status = psa_aead_set_lengths(o, A(1), A(2));
        break;
    case WT_PSA_FN_AEAD_UPDATE_AD:
        status = psa_aead_update_ad(o, IN(0), INL(0));
        break;
    case WT_PSA_FN_AEAD_UPDATE:
        status = psa_aead_update(o, IN(0), INL(0), OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_AEAD_FINISH:
        status = psa_aead_finish(o, OUT(0), CAP(0), OL(0), OUT(1), CAP(1),
                                 OL(1));
        break;
    case WT_PSA_FN_AEAD_VERIFY:
        status = psa_aead_verify(o, OUT(0), CAP(0), OL(0), IN(0), INL(0));
        break;
    default:
        status = psa_aead_abort(o);
        break;
    }
    return status;
}

static psa_status_t wt_psa_kdf_fn(uint32_t fn, wt_psa_call_t* c)
{
    psa_key_derivation_operation_t* o = &c->op->u.kdf;
    psa_key_attributes_t attr;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    size_t cap = 0U;
    psa_status_t status;

    switch (fn) {
    case WT_PSA_FN_KDF_SETUP:
        status = psa_key_derivation_setup(o, A(1));
        break;
    case WT_PSA_FN_KDF_GET_CAPACITY:
        status = psa_key_derivation_get_capacity(o, &cap);
        c->val = (cap >= (size_t)WT_PSA_CAP_UNLIMITED) ?
                 WT_PSA_CAP_UNLIMITED : (uint32_t)cap;
        break;
    case WT_PSA_FN_KDF_SET_CAPACITY:
        status = psa_key_derivation_set_capacity(o, wt_psa_cap_in(A(1)));
        break;
    case WT_PSA_FN_KDF_INPUT_BYTES:
        status = psa_key_derivation_input_bytes(o, A(1), IN(0), INL(0));
        break;
    case WT_PSA_FN_KDF_INPUT_KEY:
        status = wt_psa_key_ok(A(2));
        if (status == PSA_SUCCESS) {
            status = psa_key_derivation_input_key(o, A(1), A(2));
        }
        break;
#ifndef WT_SECURE_PSA_symmetric
    case WT_PSA_FN_KDF_KEY_AGREEMENT:
        status = wt_psa_key_ok(A(2));
        if (status == PSA_SUCCESS) {
            status = psa_key_derivation_key_agreement(o, A(1), A(2), IN(0),
                                                      INL(0));
        }
        break;
#endif
    case WT_PSA_FN_KDF_OUTPUT_BYTES:
        status = psa_key_derivation_output_bytes(o, OUT(0), CAP(0));
        if (status == PSA_SUCCESS) {
            c->out_len[0] = CAP(0);
        }
        break;
    case WT_PSA_FN_KDF_OUTPUT_KEY:
        status = wt_psa_attr_get(IN(0), INL(0), &attr);
        if (status == PSA_SUCCESS) {
            status = psa_key_derivation_output_key(&attr, o, &id);
            status = wt_psa_key_add(status, id);
        }
        c->val = (status == PSA_SUCCESS) ? id : 0U;
        break;
    case WT_PSA_FN_KDF_INPUT_INTEGER:
        status = psa_key_derivation_input_integer(o, A(1),
                                                  ((uint64_t)A(3) << 32) |
                                                  A(2));
        break;
    case WT_PSA_FN_KDF_VERIFY_BYTES:
        status = psa_key_derivation_verify_bytes(o, IN(0), INL(0));
        break;
    case WT_PSA_FN_KDF_VERIFY_KEY:
        status = wt_psa_key_ok(A(1));
        if (status == PSA_SUCCESS) {
            status = psa_key_derivation_verify_key(o, A(1));
        }
        break;
    case WT_PSA_FN_KDF_ABORT:
        status = psa_key_derivation_abort(o);
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }
    return status;
}

#ifndef WT_SECURE_PSA_symmetric
static psa_status_t wt_psa_asym_fn(uint32_t fn, wt_psa_call_t* c)
{
    psa_key_attributes_t attr;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t status;

    status = wt_psa_key_ok((fn == WT_PSA_FN_RAW_KEY_AGREEMENT ||
                            fn == WT_PSA_FN_KEY_AGREEMENT) ? A(1) : A(0));
    if (status != PSA_SUCCESS) {
        return status;
    }
    switch (fn) {
    case WT_PSA_FN_KEY_AGREEMENT:
        status = wt_psa_attr_get(IN(1), INL(1), &attr);
        if (status == PSA_SUCCESS) {
            status = psa_key_agreement(A(1), IN(0), INL(0), A(0), &attr,
                                       &id);
            status = wt_psa_key_add(status, id);
        }
        c->val = (status == PSA_SUCCESS) ? id : 0U;
        break;
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT) || defined(PSA_WANT_ALG_RSA_OAEP)
    case WT_PSA_FN_ASYMMETRIC_ENCRYPT:
        status = psa_asymmetric_encrypt(A(0), A(1), IN(0), INL(0), IN(1),
                                        INL(1), OUT(0), CAP(0), OL(0));
        break;
    case WT_PSA_FN_ASYMMETRIC_DECRYPT:
        status = psa_asymmetric_decrypt(A(0), A(1), IN(0), INL(0), IN(1),
                                        INL(1), OUT(0), CAP(0), OL(0));
        break;
#endif
    case WT_PSA_FN_SIGN_HASH:
        status = psa_sign_hash(A(0), A(1), IN(0), INL(0), OUT(0), CAP(0),
                               OL(0));
        break;
    case WT_PSA_FN_VERIFY_HASH:
        status = psa_verify_hash(A(0), A(1), IN(0), INL(0), IN(1), INL(1));
        break;
    case WT_PSA_FN_SIGN_MESSAGE:
        status = psa_sign_message(A(0), A(1), IN(0), INL(0), OUT(0), CAP(0),
                                  OL(0));
        break;
    case WT_PSA_FN_VERIFY_MESSAGE:
        status = psa_verify_message(A(0), A(1), IN(0), INL(0), IN(1), INL(1));
        break;
    case WT_PSA_FN_RAW_KEY_AGREEMENT:
        status = psa_raw_key_agreement(A(0), A(1), IN(0), INL(0), OUT(0),
                                       CAP(0), OL(0));
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }
    return status;
}
#endif

static psa_status_t wt_psa_fn(uint32_t fn, wt_psa_call_t* c)
{
    psa_status_t status;

    if (fn == WT_PSA_FN_CRYPTO_INIT) {
        wt_psa_client_reset(g_psa_client);
        status = PSA_SUCCESS;
    }
    else if (fn >= WT_PSA_FN_GENERATE_RANDOM &&
             fn <= WT_PSA_FN_GENERATE_KEY) {
        status = wt_psa_keys_fn(fn, c);
    }
    else if (fn >= WT_PSA_FN_HASH_COMPUTE && fn <= WT_PSA_FN_MAC_ABORT) {
        status = wt_psa_hash_mac_fn(fn, c);
    }
    else if (fn >= WT_PSA_FN_CIPHER_ENCRYPT && fn <= WT_PSA_FN_CIPHER_ABORT) {
        status = wt_psa_cipher_fn(fn, c);
    }
    else if (fn >= WT_PSA_FN_AEAD_ENCRYPT && fn <= WT_PSA_FN_AEAD_ABORT) {
        status = wt_psa_aead_fn(fn, c);
    }
    else if (fn >= WT_PSA_FN_KDF_SETUP && fn <= WT_PSA_FN_KDF_ABORT) {
        status = wt_psa_kdf_fn(fn, c);
    }
#ifndef WT_SECURE_PSA_symmetric
    else if (fn >= WT_PSA_FN_SIGN_HASH &&
             fn <= WT_PSA_FN_ASYMMETRIC_DECRYPT) {
        status = wt_psa_asym_fn(fn, c);
    }
#endif
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }
    return status;
}

/* Lay the inputs and outputs out over the message. */
static psa_status_t wt_psa_layout(wt_psa_call_t* c, const uint8_t* inl,
                                  size_t inl_len, uint8_t* outl,
                                  size_t outl_cap)
{
    const uint8_t* base = inl;
    uint8_t* obase = outl;
    size_t total = 0U;
    size_t i;

    for (i = 0U; i < WT_PSA_WIRE_IN_MAX; i++) {
        if (c->args->in_len[i] > inl_len) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        c->in_len[i] = c->args->in_len[i];
        total += c->in_len[i];
    }
    if (total != inl_len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    for (i = 0U; i < WT_PSA_WIRE_IN_MAX; i++) {
        c->in[i] = base;
        base += c->in_len[i];
    }
    total = 0U;
    for (i = 0U; i < WT_PSA_WIRE_OUT_MAX; i++) {
        if (c->args->out_cap[i] > outl_cap) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        c->out_cap[i] = c->args->out_cap[i];
        total += c->out_cap[i];
    }
    if (total > outl_cap) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    for (i = 0U; i < WT_PSA_WIRE_OUT_MAX; i++) {
        c->out[i] = obase;
        obase += c->out_cap[i];
    }
    return PSA_SUCCESS;
}

/* A restart reloads the RESTART_CLEAR crypto band, so every volatile key,
 * operation and pool block is already gone; only the nonce is new. */
int wt_psa_service_init(void)
{
    uint8_t nonce[sizeof(uint32_t)];

    if (psa_crypto_init() != PSA_SUCCESS) {
        return -1;
    }
    if (wt_hsm_keyvault_random(nonce, sizeof(nonce)) != PSA_SUCCESS) {
        return -1;
    }
    g_psa_nonce = wt_psa_rd32(nonce);
    return 0;
}

psa_status_t wt_psa_service_call(int32_t owner, int32_t client,
                                 const wt_crypto_wire_req_t* hdr,
                                 const uint8_t* payload, size_t payload_len,
                                 uint8_t* out, size_t out_cap,
                                 size_t* out_len)
{
    wt_psa_wire_args_t args;
    wt_psa_wire_ret_t ret;
    wt_psa_call_t call;
    wt_psa_call_t* c = &call;
    wt_psa_client_t* cl;
    uint32_t fn = hdr->usage;
    uint8_t kind;
    int setup = 0;
    psa_status_t status = PSA_SUCCESS;

    *out_len = 0U;
    if ((hdr->key_type >> WT_PSA_WIRE_VER_SHIFT) != WT_PSA_WIRE_VERSION ||
            (hdr->key_type & 0xFFFFU) != 0U ||
            hdr->uid != 0U || payload_len < sizeof(args) ||
            out_cap < sizeof(ret) || client >= 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memcpy(&args, payload, sizeof(args));
    (void)memset(&call, 0, sizeof(call));
    (void)memset(&ret, 0, sizeof(ret));
    call.args = &args;
    g_psa_owner = owner;
    g_psa_client = client;

    cl = wt_psa_client_of(client);
    if (cl == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    else {
        g_wt_psa_arena = (size_t)(cl - g_psa_clients) + 1U;
        status = wt_psa_layout(c, payload + sizeof(args),
                               payload_len - sizeof(args), out + sizeof(ret),
                               out_cap - sizeof(ret));
    }
    kind = wt_psa_fn_kind(fn, &setup);
    if (status == PSA_SUCCESS) {
        c->op = wt_psa_op_for((kind != 0U) ? A(0) : 0U, kind, setup, &status);
    }
    if (status == PSA_SUCCESS) {
        status = wt_psa_fn(fn, c);
    }
    if (c->op != NULL) {
        ret.op = wt_psa_op_sync(c->op);
    }
    ret.val = c->val;
    if (status != PSA_SUCCESS) {
        c->out_len[0] = 0U;
        c->out_len[1] = 0U;
        if (c->out[0] != NULL) {
            wt_forceZero(c->out[0], c->out_cap[0] + c->out_cap[1]);
        }
    }
    ret.out_len[0] = (uint32_t)c->out_len[0];
    ret.out_len[1] = (uint32_t)c->out_len[1];
    *out_len = sizeof(ret);
    if (c->out_len[1] != 0U) {
        (void)memmove(out + sizeof(ret) + c->out_len[0], c->out[1],
                      c->out_len[1]);
    }
    *out_len += c->out_len[0] + c->out_len[1];
    (void)memcpy(out, &ret, sizeof(ret));
    g_wt_psa_arena = 0U;
    return status;
}
