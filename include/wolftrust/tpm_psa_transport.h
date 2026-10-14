/* tpm_psa_transport.h
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

#ifndef WOLFTRUST_TPM_PSA_TRANSPORT_H
#define WOLFTRUST_TPM_PSA_TRANSPORT_H

#include "wolftrust/tpm/tpm_abi.h"

#include <stddef.h>
#include <stdint.h>

/* Non-secure client helpers for SERVICE_TPM. Each call is one psa_call on a
 * cached connection; a lost connection is reopened on the next call. The
 * application side moves whole TPM 2.0 command/response frames; the fwTPM
 * partition side serves them. Return 0, or the negative relay/PSA status. */

/* Application: submit one command frame (non-blocking). */
int wt_tpm_psa_submit(const uint8_t* cmd, size_t cmd_len);
/* Application: collect the response; WT_TPM_E_BUSY while still in service. */
int wt_tpm_psa_poll(uint8_t* resp, size_t resp_cap, size_t* resp_len);

/* fwTPM partition: take the pending command; WT_TPM_E_EMPTY when none. */
int wt_tpm_psa_fetch(uint8_t* cmd, size_t cmd_cap, size_t* cmd_len);
/* fwTPM partition: post the response to the command last fetched. */
int wt_tpm_psa_respond(const uint8_t* resp, size_t resp_len);

/* Drop the cached connection (after a transport error or for teardown). */
void wt_tpm_psa_close(void);

#endif /* WOLFTRUST_TPM_PSA_TRANSPORT_H */
