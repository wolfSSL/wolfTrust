/* hsm.h
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

#ifndef WOLFTRUST_SERVICES_HSM_H
#define WOLFTRUST_SERVICES_HSM_H

#include "wolftrust/types.h"
#include "psa/error.h"

/* Pull in the wolfHSM comm header for the whTransportServerCb type.
 * This is the minimal wolfHSM dependency; the wolfCrypt settings header
 * must be visible on the include path before this file is processed. */
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_common.h"

/* Initialise the wolfHSM service: wolfCrypt static memory pool,
 * target-backed NVM, shared lock, the per-guest crypto contexts, but NOT
 * the per-guest transport (that is wired by wt_hsm_guest_init for each
 * guest). Call once at boot, before wt_hsm_guest_init. Returns 0 on
 * success, negative on failure. Failure is fatal — the caller should panic. */
int wt_hsm_init(void);

/* Record the PSA lifecycle wolfBoot handed off, before wt_hsm_init. It gates
 * whether a foreign/corrupt vault may be auto-reformatted: only the unlocked
 * development states (ASSEMBLY_AND_TEST, PSA_ROT_PROVISIONING) permit it, so a
 * SECURED device never auto-wipes WRITE_ONCE storage or the sealed key. A
 * value never set (0/unknown) is treated as locked. */
void wt_hsm_set_boot_lifecycle(uint32_t lifecycle);

/* WT-FFM-0050 firmware anti-rollback, run after wt_hsm_init and before the
 * first guest dispatch: the wolfTrust image version and every pinned guest
 * version must meet the monotonic floors persisted in the vault NVM. A
 * below-floor image quarantines the affected guests (all of them when the
 * wolfTrust image itself is rolled back) before any domain is entered; an
 * accepted boot advances the floors. Returns 0 or WT_ROLLBACK_REFUSED. */
int wt_hsm_rollback_enforce(uint32_t image_version);

/* Effective image staging floor for SERVICE_FWU: the persisted monotonic
 * floor, or zero in the unlocked provisioning lifecycles. Nonzero on an
 * unreadable table so the caller can fail closed. */
int wt_hsm_rollback_image_floor(uint32_t* floor);

/* Running image version recorded at boot enforcement; SERVICE_FWU reports
 * it as the public active version. */
uint32_t wt_hsm_active_image_version(void);

/* 1 if a foreign/corrupt vault was reformatted this boot (observability). */
int wt_hsm_vault_was_reformatted(void);

/* Initialise the per-guest wolfHSM server context, transport, and
 * tasklet. `transport_cb` and `transport_ctx` come from the CMSE transport
 * module. The tasklet starts blocked and is later scheduled by the monitor as
 * the guest's runnable representative while that guest is waiting on HSM
 * work. Safe to call only from monitor init (before scheduler starts).
 * Returns 0 on success, negative on failure. */
int wt_hsm_guest_init(wt_guest_id_t guest_id,
                      const whTransportServerCb *transport_cb,
                      void *transport_ctx,
                      const void *transport_cfg);

/* Bind a guest's wolfHSM server to the secure relay capture transport
 * (WT-FFM-0054): the request/response buffers live in monitor RAM, filled by
 * wt_hsm_relay_submit from SERVICE_HSM's mediated psa_call path — no NS-RAM
 * window and no CSR handshake. Same call rules as wt_hsm_guest_init. */
int wt_hsm_guest_init_relay(wt_guest_id_t guest_id);

/* SERVICE_HSM's platform submit hook (matches wt_hsm_relay_submit_fn): map
 * the SPM-stamped caller to its guest server, pump one relayed wolfHSM
 * packet through wh_Server_HandleRequestMessage in monitor RAM, and return
 * the response packet. May block on the shared NVM mutex, so it must run
 * from a scheduled coroutine, never the bootstrap context. */
int wt_hsm_relay_submit(void* submit_ctx, int32_t client_id,
                        const uint8_t* req, size_t req_len,
                        uint8_t* resp, size_t resp_cap, size_t* resp_len);

/* Returns true if guest_id has been successfully initialised. Used
 * by the NSC veneers to reject HSM calls from guests that don't
 * have HSM provisioned. */
bool wt_hsm_guest_ready(wt_guest_id_t guest_id);

/* For audit / instrumentation. Returns the wolfHSM client_id value
 * (key namespace) we use for guest_id. Currently this is just
 * guest_id + 1 (0 is reserved). */
uint16_t wt_hsm_guest_client_id(wt_guest_id_t guest_id);

/* Return the tasklet handle for guest_id, or NULL if guest_id is out of
 * range or the guest has not yet been initialised via wt_hsm_guest_init.
 * Used by the monitor to wake per-guest wolfHSM service work. */
struct wt_co;
struct wt_co *wt_hsm_guest_tasklet(wt_guest_id_t guest_id);

/* Reverse lookup: which guest owns `tasklet`? Returns WT_MAX_GUESTS if it
 * does not match any per-guest server tasklet. Used by the Secure fault
 * dispatcher to map a faulted tasklet back to its NS client. */
wt_guest_id_t wt_hsm_guest_for_tasklet(const struct wt_co *tasklet);

/* Signal a terminal Secure-side fault for guest_id: drops the NVM lock
 * if the dying tasklet was holding it, writes a WH_ERROR_ABORTED
 * fatal-response into the guest's transport, and clears the ready bit
 * so subsequent NSC veneers reject HSM calls from this guest. Safe to
 * call from handler mode. Returns WH_ERROR_OK on success. */
int wt_hsm_signal_fault(wt_guest_id_t guest_id);

/* Drop every secure-side wolfHSM lock held by a faulted coroutine. Used by the
 * graceful SP fault-recovery path to release a dead partition's NVM lock
 * without the guest-keyed teardown wt_hsm_signal_fault performs. Safe from
 * handler mode; a NULL coroutine or a non-holder is a no-op. */
void wt_hsm_release_locks(struct wt_co *co);

/* The shared NVM serialisation mutex, exposed so the SVC gate can run gated
 * acquire/release on behalf of the confined keystore partitions. */
struct wt_mutex;
struct wt_mutex *wt_hsm_nvm_lock_mutex(void);

/* Rebuild every ready per-guest server after a relay-partition fault: a
 * request may have been torn mid-flight, leaving the server DRBG or handler
 * state unusable. Fails closed — a guest whose re-init fails stays down. */
int wt_hsm_relay_reinit_servers(void);

/* Terminal-fault NS-client notifier. wt_hsm_signal_fault calls the installed
 * callback; the arch transport installs its concrete notifier at boot. The
 * default is a no-op so engine-less/host builds link. */
typedef int (*wt_hsm_fault_notify_fn)(wt_guest_id_t guest_id);
void wt_hsm_set_fault_notify(wt_hsm_fault_notify_fn fn);

/* Provision or reopen the Initial Attestation Key in the wolfHSM keystore.
 * The private key is non-exportable and restricted to signing. */
int wt_hsm_attest_init(void);

/* Run one secure HSM tasklet during bootstrap so the Initial Attestation Key
 * is provisioned before any Non-secure guest can request attestation. */
int wt_hsm_attest_bootstrap(void);

/* Sign a SHA-256 digest with the protected Initial Attestation Key. Output is
 * the 64-byte COSE ECDSA form, r followed by s. */
int wt_hsm_attest_sign(const uint8_t* digest, size_t digestSize,
                       uint8_t* signature, size_t signatureCapacity,
                       size_t* signatureSize);

/* Return the IAK public point in X9.63 form, 0x04 followed by X and Y. */
int wt_hsm_attest_public_key(uint8_t* publicKey, size_t publicKeyCapacity,
                             size_t* publicKeySize);

/* Gated vault backing (WT-FFM-0047): bind the shared NVM context, then
 * install wt_hsm_vault_backend into SERVICE_VAULT. wt_hsm_init does both;
 * requires wh_NvmFlash capacity/compaction callbacks. Host tests may use
 * that backend over ramsim. Other NVM backends are rejected with -1. */
struct whNvmContext_t;
int wt_hsm_vault_init(struct whNvmContext_t* nvm);
struct wt_vault_backend;
extern const struct wt_vault_backend wt_hsm_vault_backend;

/* Vault sealer (WT-FFM-0048): AES-GCM confidentiality + rollback binding for
 * WT_VAULT_FLAG_SEALED objects, running entirely inside the privileged vault
 * domain — the device-unique key never reaches any Secure Partition. seal
 * writes pt_len + WT_VAULT_SEAL_TAG_LEN bytes ([ciphertext][tag]); unseal
 * takes ct_len >= tag length and writes ct_len - tag plaintext bytes. The
 * monotonic rollback counter is the GCM nonce, so a replayed (rolled-back)
 * ciphertext fails tag authentication. */
#define WT_VAULT_SEAL_TAG_LEN 16U

/* Device-unique seal key + rollback counter table ids: directly above the
 * vault object window (0x0100..0x011F), never matched by vault lookups. */
#define WT_HSM_SEAL_KEY_ID        0x0120U
#define WT_HSM_VAULT_TABLE_ID     0x0121U
#define WT_HSM_ROLLBACK_TABLE_ID  0x0122U

typedef struct wt_vault_sealer {
    psa_status_t (*seal)(const uint8_t* aad, size_t aad_len, uint64_t counter,
                         const uint8_t* pt, size_t pt_len, uint8_t* ct);
    psa_status_t (*unseal)(const uint8_t* aad, size_t aad_len,
                           uint64_t counter, const uint8_t* ct, size_t ct_len,
                           uint8_t* pt);
} wt_vault_sealer_t;

/* Install the sealer. NULL restores the fail-closed default: SEALED requests
 * are refused with PSA_ERROR_NOT_SUPPORTED. */
void wt_hsm_vault_set_sealer(const wt_vault_sealer_t* sealer);

/* wolfCrypt AES-256-GCM sealer over the device-unique key at
 * WT_HSM_SEAL_KEY_ID (generated on first boot, NONEXPORTABLE and immutable).
 * Only linked into builds that carry wolfCrypt. */
int wt_hsm_seal_init(struct whNvmContext_t* nvm);
extern const wt_vault_sealer_t wt_hsm_sealer;

/* Shared vault directory helpers (wt_hsm_vault.c) for privileged backends:
 * label-addressed lookup over the vault NVM id window, and the label
 * make/flags codec. whNvmMetadata is an untagged typedef, so wh_common.h
 * must be included for the real type. */
psa_status_t wt_hsm_vault_lookup(int32_t owner, int32_t sub, uint64_t uid,
                                 whNvmId* out_id, whNvmMetadata* out_meta,
                                 whNvmId* out_free_id);
void wt_hsm_vault_make_label(uint8_t* label, int32_t owner, int32_t sub,
                             uint64_t uid, uint32_t flags);
uint32_t wt_hsm_vault_flags_of(const uint8_t* label);

/* Reserve pool space for a shared-store object add of len bytes, holding back
 * the counter-table headroom and compacting reclaimable entries first. A
 * writer must call this before wh_Nvm_AddObject so a doomed add on a full pool
 * cannot fail mid-write and poison later adds, and so key churn cannot starve
 * the seal-counter table or the rollback floor. Returns INSUFFICIENT_STORAGE
 * when even reclaim cannot make room. */
psa_status_t wt_hsm_vault_reserve_object(whNvmSize len);

/* Vault-domain RNG (WT-FFM-0054): entropy for SERVICE_VAULT's RANDOM face,
 * produced by a wolfCrypt DRBG owned by the privileged vault domain. Installed
 * via wt_vault_service_set_rng at boot. Only linked into builds that carry
 * wolfCrypt. */
psa_status_t wt_hsm_vault_random(uint8_t* out, size_t len);

#endif /* WOLFTRUST_SERVICES_HSM_H */
