/* crypto_native.h
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

#ifndef WOLFTRUST_SERVICES_CRYPTO_NATIVE_H
#define WOLFTRUST_SERVICES_CRYPTO_NATIVE_H

#include "wolftrust/services/vault_service.h"

#include <stdint.h>
#include <stddef.h>

/* Native crypto engine (WT_ENGINE=native): wolfCrypt dispatch behind the
 * unchanged SERVICE_HSM door. The relay hands one opaque packet to
 * wt_native_submit; key ops and the keyvault DRBG run in SERVICE_HSM, and key
 * objects persist in the vault through its keystore IPC door — the wolfHSM
 * server, comm, and message layers are not linked. */

/* Native wire ops carried in wt_crypto_wire_req_t.op. Key ops address vault
 * key objects namespaced (owner = SERVICE_HSM partition, sub = SPM-stamped
 * NS client), so a client only ever reaches its own keys. */
#define WT_CRYPTO_OP_KEY_GENERATE      1U
#define WT_CRYPTO_OP_KEY_IMPORT        2U
#define WT_CRYPTO_OP_KEY_EXPORT_PUBLIC 3U
#define WT_CRYPTO_OP_KEY_SIGN          4U
#define WT_CRYPTO_OP_KEY_VERIFY        5U
#define WT_CRYPTO_OP_KEY_ENCRYPT       6U
#define WT_CRYPTO_OP_KEY_DECRYPT       7U
#define WT_CRYPTO_OP_KEY_DESTROY       8U
#define WT_CRYPTO_OP_RANDOM            9U
#define WT_CRYPTO_OP_HASH             10U
#define WT_CRYPTO_OP_PSA              11U

#define WT_CRYPTO_RANDOM_MAX 256U

/* One request packet: [wt_crypto_wire_req_t][payload], bounded by the relay
 * copy buffer (WT_HSM_RELAY_MSG_MAX). usage carries the WT_VAULT_KEY_USAGE_*
 * bits on generate/import and the requested byte count on RANDOM; key_type
 * uses the WT_VAULT_KEY_* encodings. The response packet is
 * [int32_t psa_status][payload]. */
typedef struct wt_crypto_wire_req {
    uint64_t uid;
    uint32_t op;
    uint32_t usage;
    uint32_t key_type;
    uint32_t reserved;
} wt_crypto_wire_req_t;

/* Boot bring-up for the native engine: wolfCrypt, the port flash, the shared
 * NVM store, the vault storage/seal bindings and its own RANDOM-face DRBG, and
 * the keyvault. The native peer of wt_hsm_init; failure is fatal. */
int wt_native_init(void);

/* SERVICE_HSM submit hook (matches wt_hsm_relay_submit_fn): service one
 * native wire packet. submit_ctx carries the owning partition id. */
int wt_native_submit(void* submit_ctx, int32_t client_id, const uint8_t* req,
                     size_t req_len, uint8_t* resp, size_t resp_cap,
                     size_t* resp_len);

/* wolfCrypt key-op backend over vault NVM objects (WT-FFM-0046): private
 * material is stored SENSITIVE + NONEXPORTABLE in the vault and is copied
 * through the keystore door only into the crypto partition, which computes
 * on it and never exports it. */
struct whNvmContext_t;
int wt_hsm_keyvault_init(struct whNvmContext_t* nvm);

/* Rebind the keyvault to nvm (the crypto partition's IPC-backed store view)
 * after boot provisioning on the direct store. Privileged bootstrap only. */
int wt_native_bind_nvm(struct whNvmContext_t* nvm);
extern const wt_vault_key_backend_t wt_hsm_key_backend;

/* Destroy one key object in the caller's namespace. Refuses anything that
 * is not a key, so the key wire can never delete a storage object. */
psa_status_t wt_hsm_keyvault_destroy(int32_t owner, int32_t sub, uint64_t uid);

/* The crypto partition's keyvault DRBG for key generation and signing; the
 * vault's RANDOM face draws from its own DRBG. */
psa_status_t wt_hsm_keyvault_random(uint8_t* out, size_t len);

/* Vault uids of PSA persistent keys: a "PSK" tag over the key id. The key
 * wire refuses this range, so native keys cannot collide with or remove them. */
#define WT_PSA_UID_TAG 0x50534BU
#define WT_PSA_UID(id) (((uint64_t)WT_PSA_UID_TAG << 32) | (uint64_t)(id))
#define WT_PSA_UID_RESERVED(uid) ((uint32_t)((uid) >> 32) == WT_PSA_UID_TAG)

#ifdef WT_SECURE_PSA
/* Opaque PSA key records (Secure PSA Crypto persistent keys), stored as key
 * objects of their own type so neither the key wire nor storage can use them. */
#define WT_HSM_KEY_TYPE_PSA_RECORD 0xFFU
psa_status_t wt_hsm_keyvault_rec_put(int32_t owner, int32_t sub, uint64_t uid,
                                     const uint8_t* data, size_t len);
psa_status_t wt_hsm_keyvault_rec_get(int32_t owner, int32_t sub, uint64_t uid,
                                     uint32_t offset, uint8_t* data,
                                     size_t len, size_t* total);
psa_status_t wt_hsm_keyvault_rec_remove(int32_t owner, int32_t sub,
                                        uint64_t uid);
#endif

#endif /* WOLFTRUST_SERVICES_CRYPTO_NATIVE_H */
