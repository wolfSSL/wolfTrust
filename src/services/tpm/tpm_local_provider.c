/* tpm_local_provider.c
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

#include "wolftrust/services/tpm_local_provider.h"

#include <limits.h>
#include <string.h>

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_command.h>

static FWTPM_CTX g_tpm;

int wt_tpm_local_provider_init(void** context)
{
    int rc;

    if (context == NULL) {
        return -1;
    }
    *context = NULL;
    (void)memset(&g_tpm, 0, sizeof(g_tpm));
    rc = FWTPM_Init(&g_tpm);
    if (rc == 0) {
        *context = &g_tpm;
    }
    return rc;
}

int wt_tpm_local_provider_process(const uint8_t* command,
                                  size_t command_len,
                                  uint8_t* response,
                                  size_t response_cap,
                                  size_t* response_len,
                                  void* context)
{
    FWTPM_CTX* tpm = (FWTPM_CTX*)context;
    int length;
    int rc;

    if (tpm == NULL || command == NULL || command_len == 0U ||
            command_len > (size_t)INT_MAX || response == NULL ||
            response_cap == 0U || response_cap > (size_t)INT_MAX ||
            response_len == NULL) {
        return -1;
    }
    *response_len = 0U;
    length = (int)response_cap;
    rc = FWTPM_ProcessCommand(tpm, command, (int)command_len, response,
                              &length, 0);
    if (rc != 0 || length <= 0 || (size_t)length > response_cap) {
        return -1;
    }
    *response_len = (size_t)length;
    return 0;
}
