/* tpm_abi.h
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

#ifndef WOLFTRUST_TPM_TPM_ABI_H
#define WOLFTRUST_TPM_TPM_ABI_H

/* SERVICE_TPM over FF-M: the mediated door between a Non-secure application
 * and the isolated firmware-TPM (fwTPM) Non-secure partition. Both sides
 * include this header; keep it free of secure-side internals.
 *
 * The relay holds one in-flight TPM 2.0 command/response slot in its own
 * Secure band. The application submits a command frame and polls for the
 * response; the fwTPM partition fetches the pending command and posts the
 * response. The SPM-stamped caller identity selects the role, so neither
 * side can play the other. Every op moves one frame in one direction. */

#define WT_TPM_SERVICE_SID      4104U
#define WT_TPM_SERVICE_VERSION  1U

/* One command or response frame. A single psa_call carries one frame in one
 * direction, so this sits well inside the FF-M copied-transfer budget. The
 * ECC core profile fits; RSA-2048/PQC frames need the TIS burst model. */
#define WT_TPM_FRAME_MAX        512U

/* Application ops: SUBMIT invec[0]=command; POLL outvec[0]=response.
 * SUBMIT begins a new transaction and the application owns the exchange, so it
 * reclaims a slot the application left behind (it restarted after SUBMIT, or
 * its poll limit expired on an uncollected response): the stale command or
 * response is scrubbed and replaced. A command the fwTPM has already taken
 * into service is never discarded; SUBMIT returns WT_TPM_E_BUSY until that
 * command completes. The application therefore runs one SUBMIT then POLL at a
 * time and must not treat a duplicate SUBMIT as harmless. If the fwTPM loses
 * a command it has taken (it restarts and fetches again), the relay never
 * replays it: the next POLL returns WT_TPM_E_ABORTED, the command ran at most
 * once, and its outcome is unknown. */
#define WT_TPM_OP_SUBMIT        1
#define WT_TPM_OP_POLL          2
/* fwTPM partition ops: FETCH outvec[0]=command; RESPOND invec[0]=response. */
#define WT_TPM_OP_FETCH         3
#define WT_TPM_OP_RESPOND       4

/* Relay statuses carried as the psa_call result, outside the PSA ranges. */
#define WT_TPM_E_EMPTY          (-2100) /* nothing pending for this role */
#define WT_TPM_E_BUSY           (-2101) /* the in-service command is not done */
#define WT_TPM_E_ABORTED        (-2102) /* fwTPM lost it; outcome unknown */

#endif /* WOLFTRUST_TPM_TPM_ABI_H */
