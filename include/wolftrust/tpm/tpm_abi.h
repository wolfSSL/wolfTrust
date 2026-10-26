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

/* SERVICE_TPM copies a command into its private domain, runs fwTPM, and
 * returns the response in the same call. No external responder is needed. */
#define WT_TPM_SERVICE_SID      4104U
#define WT_TPM_SERVICE_VERSION  1U

/* Command plus response fits the 1024-byte FF-M copied-transfer budget. */
#define WT_TPM_FRAME_MAX        512U

/* invec[0]=command, outvec[0]=response. Never replay a failed call. */
#define WT_TPM_OP_TRANSACT      5

#endif /* WOLFTRUST_TPM_TPM_ABI_H */
