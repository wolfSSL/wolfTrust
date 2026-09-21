/* crypto_native.c
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
 * Native crypto engine (WT_ENGINE=native): direct wolfCrypt dispatch behind
 * the unchanged SERVICE_HSM door. wt_native_init is the boot bring-up peer
 * of wt_hsm_init; wt_native_submit services the native wire at the relay
 * seam; the attestation signer runs wc_ecc against a vault-stored IAK.
 */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"

#include "wolftrust/types.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/nvm_store.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/crypto_native.h"

#include "wolftrust/port_nvm.h"
#include "psa/lifecycle.h"

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* The IAK vault home: owner/sub 0 is reachable by no SPM-stamped caller
 * (partitions are positive, NS clients negative), so only the boot and
 * attestation paths below can address it. */
#define WT_NATIVE_IAK_OWNER 0
#define WT_NATIVE_IAK_SUB   0
#define WT_NATIVE_IAK_UID   0xF0u

static bool g_native_attest_ready;

int wt_native_init(void)
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
            wt_hsm_vault_set_sealer(NULL);
        }
        if (wt_hsm_keyvault_init(&g_wt_nvm_ctx) == 0) {
            wt_vault_service_set_key_backend(&wt_hsm_key_backend);
        }
        wt_vault_service_set_rng(wt_hsm_keyvault_random);
    }

    return 0;
}

/* Native-engine fault-recovery hook (WT-SYS-0008): invalidate the shared vault
 * DRBG a torn request may have left mid-draw so the restart re-seeds from clean
 * state. Per-operation wolfCrypt contexts are stack-local and die with the
 * scrubbed coroutine, so the DRBG is the only mutable crypto state to reset. */
void wt_native_reinit(void)
{
    wt_hsm_keyvault_reset();
}

/* =========================================================================
 * Attestation (native): the IAK is a vault key object, provisioned at boot
 * and exercised through the key backend so private material never leaves
 * the privileged vault domain. Same wire forms as the hsm engine: 64-byte
 * r||s signatures, 65-byte X9.63 public point.
 * ====================================================================== */
static psa_status_t wt_native_iak_generate(void)
{
    return wt_hsm_key_backend.generate(WT_NATIVE_IAK_OWNER,
                                       WT_NATIVE_IAK_SUB, WT_NATIVE_IAK_UID,
                                       WT_VAULT_KEY_P256,
                                       WT_VAULT_KEY_USAGE_SIGN |
                                           WT_VAULT_KEY_USAGE_VERIFY);
}

static psa_status_t wt_native_iak_export(void)
{
    uint8_t publicKey[WT_VAULT_KEY_PUB_LEN];
    size_t publicKeySize = 0U;

    return wt_hsm_key_backend.export_public(WT_NATIVE_IAK_OWNER,
                                            WT_NATIVE_IAK_SUB,
                                            WT_NATIVE_IAK_UID, publicKey,
                                            sizeof(publicKey),
                                            &publicKeySize);
}

#if defined(WT_VAULT_FOREIGN_PROBE)
/* Negative test, same contract as the hsm engine: make the first provisioning
 * look blocked so the real recovery path runs exactly once (self-heal when
 * unlocked, fail closed when WT_VAULT_PROBE_SECURED forces a locked
 * lifecycle). */
static int g_native_foreign_probe_fired;
#endif

int wt_hsm_attest_init(void)
{
    psa_status_t status;

#if defined(WT_VAULT_FOREIGN_PROBE) && defined(WT_VAULT_PROBE_SECURED)
    wt_hsm_set_boot_lifecycle(PSA_LIFECYCLE_SECURED);
#endif
    if (g_native_attest_ready) {
        return WH_ERROR_OK;
    }
    status = wt_native_iak_export();
#if defined(WT_VAULT_FOREIGN_PROBE)
    if (g_native_foreign_probe_fired == 0) {
        status = PSA_ERROR_NOT_PERMITTED;
    }
#endif
    if (status != PSA_SUCCESS && wt_nvm_reformat_allowed() != 0) {
        /* An unreadable IAK (absent, foreign, or corrupt) is (re)provisioned
         * here, but only while the lifecycle still permits it. A SECURED
         * device must never silently mint a fresh attestation identity for an
         * absent IAK (e.g. across an hsm-to-native engine migration): it falls
         * through and fails closed, so attestation degrades rather than the
         * device adopting a new key that pinned verifiers would reject. */
        status = wt_native_iak_generate();
#if defined(WT_VAULT_FOREIGN_PROBE)
        if (g_native_foreign_probe_fired == 0) {
            g_native_foreign_probe_fired = 1;
            status = PSA_ERROR_NOT_PERMITTED;
        }
#endif
        if (status != PSA_SUCCESS) {
            if (wt_hsm_flash_format() == 0 && wt_native_init() == 0) {
                wt_nvm_mark_reformatted();
                status = wt_native_iak_generate();
            }
        }
        if (status == PSA_SUCCESS) {
            status = wt_native_iak_export();
        }
    }
    if (status != PSA_SUCCESS) {
        return WH_ERROR_ABORTED;
    }
    g_native_attest_ready = true;
    return WH_ERROR_OK;
}

int wt_hsm_attest_bootstrap(void)
{
    /* No server tasklet to pump in the native engine: provisioning runs on
     * the boot stack against the vault directly. */
    return wt_hsm_attest_init();
}

int wt_hsm_attest_sign(const uint8_t* digest, size_t digestSize,
                       uint8_t* signature, size_t signatureCapacity,
                       size_t* signatureSize)
{
    psa_status_t status;

    /* Same argument contract as the hsm engine: reject NULL/undersized
     * buffers here so a bad caller cannot fault the key backend. */
    if (signatureSize == NULL) {
        return WH_ERROR_BADARGS;
    }
    *signatureSize = 0u;
    if (!g_native_attest_ready) {
        return WH_ERROR_NOTREADY;
    }
    if (digest == NULL || digestSize != 32u || signature == NULL ||
            signatureCapacity < 64u) {
        return WH_ERROR_BADARGS;
    }
    status = wt_hsm_key_backend.sign(WT_NATIVE_IAK_OWNER, WT_NATIVE_IAK_SUB,
                                     WT_NATIVE_IAK_UID, digest, digestSize,
                                     signature, signatureCapacity,
                                     signatureSize);
    return (status == PSA_SUCCESS) ? WH_ERROR_OK : WH_ERROR_ABORTED;
}

int wt_hsm_attest_public_key(uint8_t* publicKey, size_t publicKeyCapacity,
                             size_t* publicKeySize)
{
    psa_status_t status;

    /* Report the required size and reject NULL/undersized buffers as the hsm
     * engine does, before forwarding to the key backend. */
    if (publicKeySize == NULL) {
        return WH_ERROR_BADARGS;
    }
    *publicKeySize = WT_VAULT_KEY_PUB_LEN;
    if (!g_native_attest_ready) {
        return WH_ERROR_NOTREADY;
    }
    if (publicKey == NULL || publicKeyCapacity < WT_VAULT_KEY_PUB_LEN) {
        return WH_ERROR_BADARGS;
    }
    status = wt_hsm_key_backend.export_public(WT_NATIVE_IAK_OWNER,
                                              WT_NATIVE_IAK_SUB,
                                              WT_NATIVE_IAK_UID, publicKey,
                                              publicKeyCapacity,
                                              publicKeySize);
    return (status == PSA_SUCCESS) ? WH_ERROR_OK : WH_ERROR_ABORTED;
}
