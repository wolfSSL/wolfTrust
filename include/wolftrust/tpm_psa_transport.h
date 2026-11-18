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
 * application moves whole TPM 2.0 frames to the Secure service, which runs
 * fwTPM directly. Return 0, or the negative service/PSA status. */

/* Execute one command synchronously; transport errors never replay it. */
int wt_tpm_psa_transact(const uint8_t* command, size_t command_len,
                        uint8_t* response, size_t response_cap,
                        size_t* response_len);

/* Drop the cached connection (after a transport error or for teardown). */
void wt_tpm_psa_close(void);

#endif /* WOLFTRUST_TPM_PSA_TRANSPORT_H */
