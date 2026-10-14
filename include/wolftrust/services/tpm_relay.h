/* tpm_relay.h
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

#ifndef WOLFTRUST_SERVICES_TPM_RELAY_H
#define WOLFTRUST_SERVICES_TPM_RELAY_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/tpm/tpm_abi.h"

typedef int (*wt_tpm_local_provider_fn)(const uint8_t* command,
                                        size_t command_len,
                                        uint8_t* response,
                                        size_t response_cap,
                                        size_t* response_len,
                                        void* context);

/* SERVICE_TPM: the single mediated door between the application guest and
 * the isolated fwTPM guest. The relay never parses a frame; it owns the one
 * in-flight command/response slot in its own band and enforces which
 * SPM-stamped caller may play which role, so the crossing is the same FF-M
 * level-3 door every other service rides. Secure Partition callers and any
 * Non-secure caller outside the two bound roles are refused. */

/* Bind the roles to SPM-stamped Non-secure client ids (guest N is -(N+1)).
 * Until both are bound the relay fails closed on every op. */
void wt_tpm_relay_set_roles(int32_t app_client_id, int32_t ftpm_client_id);

/* AArch64 hosts fwTPM inside this S-EL0 partition because the port has one
 * Normal-world endpoint. NULL selects the two-client relay used on M33. */
void wt_tpm_relay_set_local_provider(wt_tpm_local_provider_fn provider,
                                     void* context);

/* Transport seam, mirroring the other services: direct gate calls on the
 * host, the SVC transport when scheduled on target. NULL restores default. */
void wt_tpm_relay_set_transport(wt_spm_transport_fn fn);

/* SERVICE_TPM's dispatch loop: wait, get, serve one op, reply.
 * Architecture-neutral so the same code is host-tested through a real
 * psa_connect/psa_call round trip and scheduled on target. */
int wt_tpm_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                          int32_t partition_id);

#if defined(WT_TPM_NEG_PROBE) && (WT_TPM_NEG_PROBE == 1)
/* Test-only witness that cold boot and restart restore this partition's
 * initialized data and clear its BSS. */
int wt_tpm_relay_restart_probe(int restarted);
#endif

#endif /* WOLFTRUST_SERVICES_TPM_RELAY_H */
