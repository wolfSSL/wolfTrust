/* tpm_local_provider.h
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

#ifndef WOLFTRUST_SERVICES_TPM_LOCAL_PROVIDER_H
#define WOLFTRUST_SERVICES_TPM_LOCAL_PROVIDER_H

#include "wolftrust/services/tpm_relay.h"

int wt_tpm_local_provider_init(void** context);
int wt_tpm_local_provider_process(const uint8_t* command,
                                  size_t command_len,
                                  uint8_t* response,
                                  size_t response_cap,
                                  size_t* response_len,
                                  void* context);

#endif /* WOLFTRUST_SERVICES_TPM_LOCAL_PROVIDER_H */
