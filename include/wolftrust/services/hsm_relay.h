/* hsm_relay.h
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

#ifndef WOLFTRUST_SERVICES_HSM_RELAY_H
#define WOLFTRUST_SERVICES_HSM_RELAY_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"

/* SERVICE_HSM: the single mediated door to the wolfHSM server (WT-FFM-0054).
 * A non-secure client's wolfHSM wire packet arrives as invec[0] of one
 * psa_call, is handed opaquely to the platform's submit hook (on target, the
 * monitor's per-guest server tasklet), and the server's response packet is
 * written back as outvec[0]. The relay never parses packet contents — the
 * wolfHSM comm layer owns the protocol; the SPM owns caller identity and the
 * copied-transfer bounds (WT-FFM-0041/0047). A Secure Partition caller's
 * PSA_IPC_CALL is refused with PSA_ERROR_NOT_PERMITTED unless the platform
 * explicitly binds that one caller as the local interface provider. */

/* One wolfHSM wire packet: whCommHeader (8) + WOLFHSM_CFG_COMM_DATA_LEN (368)
 * = 376 bytes on this platform; bound with headroom, under the FF-M copied
 * transfer limit so a packet always fits one psa_call. */
#define WT_HSM_RELAY_MSG_MAX 384U

/* Platform submit hook: process one request packet and produce the response.
 * client_id is the SPM-stamped caller identity, never caller-supplied. A
 * negative return maps to a generic error on the client's psa_call. */
typedef int (*wt_hsm_relay_submit_fn)(void* submit_ctx, int32_t client_id,
                                      const uint8_t* req, size_t req_len,
                                      uint8_t* resp, size_t resp_cap,
                                      size_t* resp_len);

/* Install the submit hook. NULL restores the fail-closed default, which
 * refuses every packet with PSA_ERROR_NOT_SUPPORTED. */
void wt_hsm_relay_set_submit(wt_hsm_relay_submit_fn fn, void* submit_ctx);

/* Allow one positive Secure-partition identity onto the ordinary HSM wire.
 * Zero clears the binding. The default refuses every Secure caller, and
 * Non-secure callers remain governed by their SPM-stamped negative identity. */
#if (defined(CONFIG_PKCS11) || defined(CONFIG_TPM)) && \
    defined(WT_INTERFACE_LOCAL_PROVIDER)
void wt_hsm_relay_set_secure_client_policy(int32_t partition_id);
#endif

/* Attestation signing door (isolation level 3): the attestation partition
 * holds no key material and reaches the Initial Attestation Key only through
 * these psa_call types on SERVICE_HSM, served for the one partition
 * registered here and refused for every other client (Non-secure clients
 * included). SIGN takes the 32-byte digest in invec[0] and returns the
 * 64-byte r||s signature in outvec[0]; PUBLIC_KEY returns the 65-byte X9.63
 * point in outvec[0]. The engine's local signer pair is installed by the
 * platform start hook; NULL (the default) refuses both. */
#define WT_HSM_OP_ATTEST_SIGN       1
#define WT_HSM_OP_ATTEST_PUBLIC_KEY 2
#if defined(WT_PKCS11_HSM_RESTART_PROBE) && \
    (WT_PKCS11_HSM_RESTART_PROBE == 1)
#define WT_HSM_OP_TEST_RESTART      0x7f01
#endif

/* Signer result for "no Initial Attestation Key yet"; equals the engines'
 * WH_ERROR_NOTREADY (asserted where they are linked) so the relay stays free
 * of wolfHSM headers. */
#define WT_HSM_ATTEST_NOT_READY      (-2001)

#define WT_HSM_ATTEST_DIGEST_LEN     32U
#define WT_HSM_ATTEST_SIGNATURE_LEN  64U
#define WT_HSM_ATTEST_PUBLIC_KEY_LEN 65U

typedef int (*wt_hsm_attest_sign_fn)(const uint8_t* digest, size_t digest_len,
                                     uint8_t* signature,
                                     size_t signature_capacity,
                                     size_t* signature_len);
typedef int (*wt_hsm_attest_public_key_fn)(uint8_t* public_key,
                                           size_t public_key_capacity,
                                           size_t* public_key_len);
void wt_hsm_relay_set_attest_ops(int32_t attest_partition_id,
                                 wt_hsm_attest_sign_fn sign,
                                 wt_hsm_attest_public_key_fn public_key);

/* Transport seam, mirroring the other services: direct gate calls on the
 * host, the SVC transport when scheduled on target. NULL restores default. */
void wt_hsm_relay_set_transport(wt_spm_transport_fn fn);

/* SERVICE_HSM's dispatch loop: wait, get, relay one packet, reply.
 * Architecture-neutral so the same code is host-tested through a real
 * psa_connect/psa_call round trip and scheduled on target. */
int wt_hsm_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                          int32_t partition_id);

#endif /* WOLFTRUST_SERVICES_HSM_RELAY_H */
