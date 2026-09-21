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
 * wt_native_submit; keys are vault NVM objects served by the wolfCrypt key
 * backend inside the privileged vault domain — the wolfHSM server, comm,
 * and message layers are not linked. */

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
 * NVM store, and the vault storage/seal/key/RNG bindings. The native peer of
 * wt_hsm_init; failure is fatal — the caller should panic. */
int wt_native_init(void);

/* Fault-recovery entry for the native engine: invalidate operation-scoped
 * crypto state (the shared vault DRBG) so a restarted relay partition serves
 * from clean state instead of a generator torn mid-draw. */
void wt_native_reinit(void);

/* SERVICE_HSM submit hook (matches wt_hsm_relay_submit_fn): service one
 * native wire packet. submit_ctx carries the owning partition id. */
int wt_native_submit(void* submit_ctx, int32_t client_id, const uint8_t* req,
                     size_t req_len, uint8_t* resp, size_t resp_cap,
                     size_t* resp_len);

/* wolfCrypt key-op backend over vault NVM objects (WT-FFM-0046): private
 * material is stored SENSITIVE + NONEXPORTABLE and never leaves the
 * privileged vault domain. */
struct whNvmContext_t;
int wt_hsm_keyvault_init(struct whNvmContext_t* nvm);
extern const wt_vault_key_backend_t wt_hsm_key_backend;

/* Destroy one key object in the caller's namespace. Refuses anything that
 * is not a key, so the key wire can never delete a storage object. */
psa_status_t wt_hsm_keyvault_destroy(int32_t owner, int32_t sub, uint64_t uid);

/* Vault-domain DRBG for the RANDOM face and key generation. */
psa_status_t wt_hsm_keyvault_random(uint8_t* out, size_t len);

/* Invalidate the vault DRBG so it re-seeds on next use (fault recovery). */
void wt_hsm_keyvault_reset(void);

#endif /* WOLFTRUST_SERVICES_CRYPTO_NATIVE_H */
