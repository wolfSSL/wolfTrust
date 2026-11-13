/* initial_attestation.c
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

#include "wolftrust/services/initial_attestation.h"

#include "wolftrust/guest_verify.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/arch.h"

#include "wolftrust/services/hsm.h"
#include "wolftrust/services/hsm_relay.h"

#include "psa/lifecycle.h"

#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hash.h"

#include "wolfhsm/wh_error.h"

#include <wolfcose/wolfcose.h>
#include <wolfcose/eat_psa.h>

#include <stdbool.h>
#include <string.h>

#define WT_UEID_TYPE_RANDOM 0x01u
/* Sized for the standard claim set plus one lean measurement+signer component
 * per verified guest (WT-FFM-0049); the signed token stays under the 640-byte
 * WT_ATTEST_MAX_TOKEN_SIZE / PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE ceiling the
 * conformance suite compiles with. */
#define WT_ATTEST_PAYLOAD_SIZE 512u
#define WT_ATTEST_SCRATCH_SIZE 768u

static const uint8_t g_measurement_type[] = "sha-256";
static const uint8_t g_measurement_description[] = "wolftrust";
#ifdef WT_ATTEST_CERT_REFERENCE
static const uint8_t g_cert_reference[] = WT_ATTEST_CERT_REFERENCE;
#endif
#ifdef WT_ATTEST_VERIFICATION_SERVICE
static const uint8_t g_verification_service[] = WT_ATTEST_VERIFICATION_SERVICE;
#endif
static const uint8_t g_implementation_name[] = "wolfTrust Cortex-M runtime";
/* Identifies the wolfBoot signing authority that measured the component; the
 * signing key itself is not carried in the handoff, so hash its name. */
static const uint8_t g_signer_name[] = "wolfBoot";

static wt_boot_handoff_t g_boot_handoff;
static uint8_t g_ueid[33];
static uint8_t g_boot_seed[WC_SHA256_DIGEST_SIZE];
static uint8_t g_implementation_id[WC_SHA256_DIGEST_SIZE];
static uint8_t g_signer_id[WC_SHA256_DIGEST_SIZE];
static bool g_handoff_ready;
static bool g_attest_ready;

/* SERVICE_HSM signer binding: transport, the attestation partition's own id
 * (stamped by the SVC on target), the crypto service's SID, and the cached
 * connection. A NULL transport selects the engine's local signer. */
static wt_spm_transport_fn g_attest_hsm_transport;
static wt_ffm_runtime_t* g_attest_hsm_runtime;
static int32_t g_attest_hsm_partition;
static uint32_t g_attest_hsm_sid;
static psa_handle_t g_attest_hsm_handle;
static uint8_t g_attest_hsm_restarted;

static void wt_attest_force_zero(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;

    while (size > 0u) {
        *bytes++ = 0u;
        size--;
    }
}

int wt_initial_attest_bind_hsm(wt_spm_transport_fn transport,
                               wt_ffm_runtime_t* runtime,
                               int32_t partition_id, uint32_t hsm_sid)
{
    if (transport == NULL || partition_id <= 0) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    g_attest_hsm_transport = transport;
    g_attest_hsm_runtime = runtime;
    g_attest_hsm_partition = partition_id;
    g_attest_hsm_sid = hsm_sid;
    g_attest_hsm_handle = 0;
    g_attest_hsm_restarted = 0U;
    return WT_ATTEST_SUCCESS;
}

void wt_initial_attest_hsm_restarted(void)
{
    g_attest_hsm_restarted = 1U;
}

static int wt_attest_hsm_xfer(wt_spm_call_t* call)
{
    if (g_attest_hsm_transport(g_attest_hsm_runtime, call) !=
            WT_FFM_SUCCESS || call->ret_int == WT_FFM_ERROR_NOT_READY) {
        return WH_ERROR_ABORTED;
    }
    return 0;
}

/* Release a connection the crypto partition's fault dropped to the error
 * state: FF-M lets the client close such a handle, never call it again. */
static void wt_attest_hsm_close(void)
{
    wt_spm_call_t call;

    if (g_attest_hsm_handle > 0) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_CLOSE;
        call.partition_id = g_attest_hsm_partition;
        call.msg_handle = g_attest_hsm_handle;
        (void)wt_attest_hsm_xfer(&call);
    }
    g_attest_hsm_handle = 0;
    g_attest_hsm_restarted = 0U;
}

/* One attestation-door call on SERVICE_HSM: in is the digest (SIGN) or
 * absent (PUBLIC_KEY); out receives exactly out_len bytes. Maps the door's
 * BAD_STATE (no IAK yet) onto WH_ERROR_NOTREADY like the local signer. */
static int wt_attest_hsm_call(int32_t type, const uint8_t* in, size_t in_len,
                              uint8_t* out, size_t out_len)
{
    wt_spm_call_t call;
    int ret = 0;

    if (g_attest_hsm_restarted != 0U) {
        wt_attest_hsm_close();
    }
    if (g_attest_hsm_handle <= 0) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_CONNECT;
        call.partition_id = g_attest_hsm_partition;
        call.sid = g_attest_hsm_sid;
        call.version = 1U;
        ret = wt_attest_hsm_xfer(&call);
        if (ret == 0 &&
                (call.ret_int != WT_FFM_SUCCESS || call.ret_handle <= 0)) {
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            g_attest_hsm_handle = call.ret_handle;
        }
    }
    if (ret == 0) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_CALL;
        call.partition_id = g_attest_hsm_partition;
        call.msg_handle = g_attest_hsm_handle;
        call.call_type = type;
        if (in != NULL) {
            call.sp_in[0].base = in;
            call.sp_in[0].len = in_len;
            call.sp_in_len = 1U;
        }
        call.sp_out[0].base = out;
        call.sp_out[0].len = out_len;
        call.sp_out_len = 1U;
        ret = wt_attest_hsm_xfer(&call);
        if (ret == 0 && call.ret_int != WT_FFM_SUCCESS) {
            ret = WH_ERROR_ABORTED;
        }
    }
    if (ret == 0) {
        if (call.ret_status == PSA_ERROR_COMMUNICATION_FAILURE) {
            /* The crypto partition faulted under this request
             * (WT-FFM-0017): close the dropped connection now. */
            wt_attest_hsm_close();
            ret = WH_ERROR_ABORTED;
        }
        else if (call.ret_status == PSA_ERROR_BAD_STATE) {
            ret = WH_ERROR_NOTREADY;
        }
        else if (call.ret_status != PSA_SUCCESS ||
                 call.sp_out[0].len != out_len) {
            ret = WH_ERROR_ABORTED;
        }
    }
    return ret;
}

static int wt_attest_signer_sign(const uint8_t* digest, size_t digestSize,
    uint8_t* signature, size_t signatureCapacity, size_t* signatureSize)
{
    int ret;

    if (g_attest_hsm_transport == NULL) {
        return wt_hsm_attest_sign(digest, digestSize, signature,
                                  signatureCapacity, signatureSize);
    }
    if (signatureSize == NULL) {
        return WH_ERROR_BADARGS;
    }
    *signatureSize = 0u;
    if (digest == NULL || digestSize != WT_HSM_ATTEST_DIGEST_LEN ||
            signature == NULL ||
            signatureCapacity < WT_HSM_ATTEST_SIGNATURE_LEN) {
        return WH_ERROR_BADARGS;
    }
    ret = wt_attest_hsm_call(WT_HSM_OP_ATTEST_SIGN, digest, digestSize,
                             signature, WT_HSM_ATTEST_SIGNATURE_LEN);
    if (ret == 0) {
        *signatureSize = WT_HSM_ATTEST_SIGNATURE_LEN;
    }
    else {
        (void)memset(signature, 0, signatureCapacity);
    }
    return ret;
}

static int wt_attest_signer_public_key(uint8_t* publicKey,
    size_t publicKeyCapacity, size_t* publicKeySize)
{
    int ret;

    if (g_attest_hsm_transport == NULL) {
        return wt_hsm_attest_public_key(publicKey, publicKeyCapacity,
                                        publicKeySize);
    }
    if (publicKeySize == NULL) {
        return WH_ERROR_BADARGS;
    }
    *publicKeySize = WT_HSM_ATTEST_PUBLIC_KEY_LEN;
    if (publicKey == NULL || publicKeyCapacity < WT_HSM_ATTEST_PUBLIC_KEY_LEN) {
        return WH_ERROR_BADARGS;
    }
    ret = wt_attest_hsm_call(WT_HSM_OP_ATTEST_PUBLIC_KEY, NULL, 0u,
                             publicKey, WT_HSM_ATTEST_PUBLIC_KEY_LEN);
    if (ret != 0) {
        (void)memset(publicKey, 0, publicKeyCapacity);
    }
    return ret;
}

static int wt_attest_prepare(void)
{
    uint8_t publicKey[WT_ATTEST_IAK_PUBLIC_KEY_SIZE];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    size_t publicKeySize = sizeof(publicKey);
    wc_Sha256 sha;
    int ret;

    if (g_attest_ready) {
        return WT_ATTEST_SUCCESS;
    }
    if (!g_handoff_ready) {
        return WT_ATTEST_ERROR_NOT_READY;
    }

    ret = wt_attest_signer_public_key(publicKey, sizeof(publicKey),
                                      &publicKeySize);
    if (ret == WH_ERROR_NOTREADY) {
        ret = WT_ATTEST_ERROR_NOT_READY;
    }
    else if (ret != 0) {
        ret = WT_ATTEST_ERROR_CRYPTO;
    }
    if ((ret == 0) && (publicKeySize != sizeof(publicKey))) {
        ret = WT_ATTEST_ERROR_CRYPTO;
    }
    if (ret == 0) {
        ret = wc_Sha256Hash(publicKey, (word32)publicKeySize, digest);
        if (ret != 0) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }
    if (ret == 0) {
        g_ueid[0] = WT_UEID_TYPE_RANDOM;
        (void)memcpy(&g_ueid[1], digest, sizeof(digest));
    }
    /* Boot-seed binds the token to this measured boot of this device: it hashes
     * the boot measurement with the device instance id, so it is stable across
     * a boot cycle and reproducible for the golden conformance vector. */
    if (ret == 0) {
        ret = wc_InitSha256(&sha);
    }
    if (ret == 0) {
        ret = wc_Sha256Update(&sha, g_boot_handoff.measurement,
                              (word32)g_boot_handoff.measurement_size);
        if (ret == 0) {
            ret = wc_Sha256Update(&sha, g_ueid, sizeof(g_ueid));
        }
        if (ret == 0) {
            ret = wc_Sha256Final(&sha, g_boot_seed);
        }
        wc_Sha256Free(&sha);
        if (ret != 0) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }
    if (ret == 0) {
        g_attest_ready = true;
    }

    wt_attest_force_zero(publicKey, sizeof(publicKey));
    wt_attest_force_zero(digest, sizeof(digest));
    return ret;
}

/* Measurement access seam: the confined attest partition cannot reach the
 * monitor's table, so it snapshots records through the read-only SVC gate;
 * privileged and host callers read the table directly. */
static size_t wt_attest_measurement_count(void)
{
#if defined(WT_TARGET_BUILD)
    if (wt_arch_thread_unprivileged()) {
        unsigned int count = 0u;

        if (wt_spm_measure_read_call(0u, NULL, 0u, &count) != 0) {
            return 0u;
        }
        return (size_t)count;
    }
#endif
    return wt_guest_measurement_count();
}

static int wt_attest_measurement_get(size_t index,
                                     wt_guest_measurement_t* record)
{
    const wt_guest_measurement_t* rec;

#if defined(WT_TARGET_BUILD)
    if (wt_arch_thread_unprivileged()) {
        return wt_spm_measure_read_call((unsigned int)index, record,
                                        (unsigned int)sizeof(*record), NULL);
    }
#endif
    rec = wt_guest_measurement_get(index, NULL);
    if (rec == NULL) {
        return -1;
    }
    (void)memcpy(record, rec, sizeof(*record));
    return 0;
}

/* COSE external-signer callback: wolfCOSE hands us the digest of the
 * Sig_structure; forward it to the IAK held in the secure HSM. */
static int wt_attest_eat_sign(void* context, int32_t algorithm,
    const uint8_t* digest, size_t digestSize, uint8_t* signature,
    size_t signatureSize, size_t* signatureLength)
{
    (void)context;
    if (algorithm != WOLFCOSE_ALG_ES256) {
        return WOLFCOSE_E_INVALID_ARG;
    }
    return wt_attest_signer_sign(digest, digestSize, signature,
                                 signatureSize, signatureLength);
}

static int wt_attest_build_claims(wt_guest_id_t guestId,
    const uint8_t* challenge, size_t challengeSize,
    WOLFCOSE_EAT_PSA_CLAIMS* claims, WOLFCOSE_EAT_PSA_COMPONENT* components,
    size_t componentCap, wt_guest_measurement_t* records, size_t recordCap)
{
    size_t count;
    size_t index;
    int ret = WT_ATTEST_SUCCESS;

    if ((challenge == NULL) || (claims == NULL) || (components == NULL) ||
        (records == NULL)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    /* Reject out-of-range guest ids so the negative client-id map below cannot
     * overflow int32 or turn positive. */
    if (guestId >= WT_MAX_GUESTS) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    count = wt_attest_measurement_count();
    if ((count > recordCap) || ((count + 1u) > componentCap)) {
        return WT_ATTEST_ERROR_BUFFER_TOO_SMALL;
    }

    (void)memset(claims, 0, sizeof(*claims));
    (void)memset(components, 0, sizeof(*components) * componentCap);

    /* Descriptor component: the wolfBoot measurement and its signer. */
    components[0].measurementType.data = g_measurement_type;
    components[0].measurementType.len = sizeof(g_measurement_type) - 1u;
    components[0].measurementValue.data = g_boot_handoff.measurement;
    components[0].measurementValue.len = g_boot_handoff.measurement_size;
    components[0].signerId.data = g_signer_id;
    components[0].signerId.len = sizeof(g_signer_id);
    components[0].measurementDesc.data = g_measurement_description;
    components[0].measurementDesc.len = sizeof(g_measurement_description) - 1u;

    /* One lean component per launch-verified guest (WT-FFM-0049): the pinned
     * digest and the boot-chain signer that authenticated the pin. */
    for (index = 0u; (ret == WT_ATTEST_SUCCESS) && (index < count); index++) {
        if (wt_attest_measurement_get(index, &records[index]) != 0) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
        else {
            components[index + 1u].measurementValue.data =
                records[index].digest;
            components[index + 1u].measurementValue.len =
                sizeof(records[index].digest);
            components[index + 1u].signerId.data = g_signer_id;
            components[index + 1u].signerId.len = sizeof(g_signer_id);
        }
    }

    if (ret == WT_ATTEST_SUCCESS) {
        claims->nonce.data = challenge;
        claims->nonce.len = challengeSize;
        claims->ueid.data = g_ueid;
        claims->ueid.len = sizeof(g_ueid);
        claims->implementationId.data = g_implementation_id;
        claims->implementationId.len = sizeof(g_implementation_id);
        claims->bootSeed.data = g_boot_seed;
        claims->bootSeed.len = sizeof(g_boot_seed);
#ifdef WT_ATTEST_CERT_REFERENCE
        claims->certificationReference.data = g_cert_reference;
        claims->certificationReference.len = sizeof(g_cert_reference) - 1u;
#endif
#ifdef WT_ATTEST_VERIFICATION_SERVICE
        claims->verificationServiceIndicator.data = g_verification_service;
        claims->verificationServiceIndicator.len =
            sizeof(g_verification_service) - 1u;
#endif
        /* NSPE callers map guest N to PSA client id -(N + 1); never positive. */
        claims->clientId = -((int32_t)guestId + 1);
        claims->lifecycle = (uint16_t)g_boot_handoff.lifecycle;
        claims->components = components;
        claims->componentCount = count + 1u;
    }

    return ret;
}

/* Accept only the PSA lifecycle major states the wolfCOSE EAT encoder allows
 * (RFC 9783), so init fails closed instead of arming a path that can never
 * issue a token. */
static int wt_attest_lifecycle_valid(uint32_t lifecycle)
{
    uint16_t major;

    if (lifecycle > 0xFFFFu) {
        return 0;
    }
    major = (uint16_t)(lifecycle & PSA_LIFECYCLE_PSA_STATE_MASK);
    return ((major == PSA_LIFECYCLE_UNKNOWN) ||
            (major == PSA_LIFECYCLE_ASSEMBLY_AND_TEST) ||
            (major == PSA_LIFECYCLE_PSA_ROT_PROVISIONING) ||
            (major == PSA_LIFECYCLE_SECURED) ||
            (major == PSA_LIFECYCLE_NON_PSA_ROT_DEBUG) ||
            (major == PSA_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG) ||
            (major == PSA_LIFECYCLE_DECOMMISSIONED)) ? 1 : 0;
}

int wt_initial_attest_init(const wt_boot_handoff_t* handoff)
{
    int ret;

    if (handoff == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    if ((handoff->hash_algorithm != WT_BOOT_HANDOFF_HASH_SHA256) ||
        (handoff->measurement_size != WT_BOOT_HANDOFF_DIGEST_SIZE)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    /* Reject a handoff whose lifecycle is not a PSA state the EAT encoder
     * accepts, so a doomed handoff is refused here rather than at token time. */
    if (wt_attest_lifecycle_valid(handoff->lifecycle) == 0) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    ret = wc_Sha256Hash(g_implementation_name,
        (word32)(sizeof(g_implementation_name) - 1u),
        g_implementation_id);
    if (ret == 0) {
        ret = wc_Sha256Hash(g_signer_name,
            (word32)(sizeof(g_signer_name) - 1u), g_signer_id);
    }
    if (ret == 0) {
        (void)memcpy(&g_boot_handoff, handoff, sizeof(g_boot_handoff));
        g_handoff_ready = true;
        /* Drop the cached UEID and boot-seed so a new handoff re-derives them;
         * a stale boot-binding must never be carried into a signed token. */
        g_attest_ready = false;
    }

    return ret == 0 ? WT_ATTEST_SUCCESS : WT_ATTEST_ERROR_CRYPTO;
}

int wt_initial_attest_get_token_size(size_t challengeSize,
    size_t* tokenSize)
{
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_64];
    uint8_t payload[WT_ATTEST_PAYLOAD_SIZE];
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT components[1u + WT_MAX_GUESTS];
    wt_guest_measurement_t records[WT_MAX_GUESTS];
    size_t payloadSize = 0u;
    int ret;

    if (tokenSize == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    *tokenSize = 0u;
    if ((challengeSize != WT_ATTEST_CHALLENGE_SIZE_32) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_48) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_64)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    ret = wt_attest_prepare();
    if (ret == WT_ATTEST_SUCCESS) {
        (void)memset(challenge, 0, sizeof(challenge));
        ret = wt_attest_build_claims(0u, challenge, challengeSize, &claims,
            components, sizeof(components) / sizeof(components[0]),
            records, sizeof(records) / sizeof(records[0]));
    }
    if (ret == WT_ATTEST_SUCCESS) {
        ret = wc_CoseEatPsaToken_EncodeClaims(&claims, payload,
                                              sizeof(payload), &payloadSize);
        if (ret == WOLFCOSE_E_BUFFER_TOO_SMALL) {
            ret = WT_ATTEST_ERROR_BUFFER_TOO_SMALL;
        }
        else if (ret != WOLFCOSE_SUCCESS) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }
    if (ret == WT_ATTEST_SUCCESS) {
        if (wc_CoseSign1_SignSize_ex(NULL, WOLFCOSE_ALG_ES256, 0u,
                payloadSize, 0u, 0u, tokenSize) != WOLFCOSE_SUCCESS) {
            *tokenSize = 0u;
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }

    wt_attest_force_zero(challenge, sizeof(challenge));
    wt_attest_force_zero(payload, sizeof(payload));
    return ret;
}

int wt_initial_attest_get_token(wt_guest_id_t guestId,
    const uint8_t* challenge, size_t challengeSize, uint8_t* token,
    size_t tokenCapacity, size_t* tokenSize)
{
    uint8_t claimsBuf[WT_ATTEST_PAYLOAD_SIZE];
    uint8_t scratch[WT_ATTEST_SCRATCH_SIZE];
    WOLFCOSE_EAT_PSA_CLAIMS claims;
    WOLFCOSE_EAT_PSA_COMPONENT components[1u + WT_MAX_GUESTS];
    wt_guest_measurement_t records[WT_MAX_GUESTS];
    WOLFCOSE_KEY key;
    int keyReady = 0;
    int ret;

    if ((challenge == NULL) || (token == NULL) || (tokenSize == NULL) ||
        (tokenCapacity == 0u)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    *tokenSize = 0u;
    if ((challengeSize != WT_ATTEST_CHALLENGE_SIZE_32) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_48) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_64)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    ret = wt_attest_prepare();
    if (ret == WT_ATTEST_SUCCESS) {
        ret = wt_attest_build_claims(guestId, challenge, challengeSize, &claims,
            components, sizeof(components) / sizeof(components[0]),
            records, sizeof(records) / sizeof(records[0]));
    }
    if (ret == WT_ATTEST_SUCCESS) {
        if (wc_CoseKey_Init(&key) != WOLFCOSE_SUCCESS) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
        else {
            keyReady = 1;
            key.kty = WOLFCOSE_KTY_EC2;
            key.crv = WOLFCOSE_CRV_P256;
            key.alg = WOLFCOSE_ALG_ES256;
            if (wc_CoseKey_SetExtSigner(&key, wt_attest_eat_sign, NULL) !=
                WOLFCOSE_SUCCESS) {
                ret = WT_ATTEST_ERROR_CRYPTO;
            }
        }
    }
    if (ret == WT_ATTEST_SUCCESS) {
        ret = wc_CoseEatPsaToken_CreateSign1(&key, WOLFCOSE_ALG_ES256, &claims,
            claimsBuf, sizeof(claimsBuf), scratch, sizeof(scratch), token,
            tokenCapacity, tokenSize, NULL);
        if (ret == WOLFCOSE_E_BUFFER_TOO_SMALL) {
            ret = WT_ATTEST_ERROR_BUFFER_TOO_SMALL;
        }
        else if (ret != WOLFCOSE_SUCCESS) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }

    if (keyReady != 0) {
        wc_CoseKey_Free(&key);
    }
    wt_attest_force_zero(claimsBuf, sizeof(claimsBuf));
    wt_attest_force_zero(scratch, sizeof(scratch));
    return ret;
}

int wt_initial_attest_get_iak_public_key(uint8_t* publicKey,
    size_t publicKeyCapacity, size_t* publicKeySize)
{
    int ret;

    if (publicKeySize == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    ret = wt_attest_prepare();
    if (ret == WT_ATTEST_SUCCESS) {
        ret = wt_attest_signer_public_key(publicKey, publicKeyCapacity,
                                          publicKeySize);
        if (ret != 0) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }
    return ret;
}
