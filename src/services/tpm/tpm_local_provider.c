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
#include "wolftrust/services/interface_client.h"
#include "wolftrust/provider_crypto.h"

#include <limits.h>
#include <string.h>

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_command.h>

static FWTPM_CTX g_tpm;
static uint32_t g_tpm_client_epoch;
volatile uint32_t g_wt_interface_client_epoch;

/* A departed client gets a TPM Reset: Startup(CLEAR) flushes objects, sessions
 * and PCRs, and the new client's own Startup gets TPM_RC_INITIALIZE. The DA
 * count and the lockoutAuth lock, which clockless Startup clears, carry over. */
static int wt_tpm_client_reset(FWTPM_CTX* tpm, uint8_t* response)
{
    static const uint8_t startup[12] = {
        0x80U, 0x01U, 0x00U, 0x00U, 0x00U, 0x0CU,
        0x00U, 0x00U, 0x01U, 0x44U, 0x00U, 0x00U
    };
    uint8_t command[sizeof(startup)];
    int length = 0;
    int rc;
#ifndef FWTPM_NO_DA
    int lockout_failed = tpm->lockoutAuthFailed;
#endif

    (void)memcpy(command, startup, sizeof(command));
    tpm->wasStarted = 0;
    rc = FWTPM_ProcessCommand(tpm, command, (int)sizeof(command), response,
                              &length, 0);
#ifndef FWTPM_NO_DA
    tpm->lockoutAuthFailed = lockout_failed;
#endif
    if (rc == 0 && (length != 10 || response[6] != 0U || response[7] != 0U ||
            response[8] != 0U || response[9] != 0U)) {
        rc = -1;
    }
    return rc;
}

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

int wt_tpm_local_provider_process(uint8_t* command,
                                  size_t command_len,
                                  uint8_t* response,
                                  size_t response_cap,
                                  size_t* response_len,
                                  void* context)
{
    FWTPM_CTX* tpm = (FWTPM_CTX*)context;
    uint32_t epoch;
    int length;
    int rc;

    /* fwTPM writes up to FWTPM_MAX_COMMAND_SIZE whatever rspSize says. */
    if (tpm == NULL || command == NULL || command_len == 0U ||
            command_len > (size_t)INT_MAX || response == NULL ||
            response_cap < (size_t)FWTPM_MAX_COMMAND_SIZE ||
            response_cap > (size_t)INT_MAX || response_len == NULL) {
        return -1;
    }
    *response_len = 0U;
    if (wt_provider_crypto_prepare() != 0) {
        return -1;
    }
    epoch = g_wt_interface_client_epoch;
    if (epoch != g_tpm_client_epoch) {
        if (wt_tpm_client_reset(tpm, response) != 0) {
            return -1;
        }
        g_tpm_client_epoch = epoch;
    }
    length = (int)response_cap;
    rc = FWTPM_ProcessCommand(tpm, command, (int)command_len, response,
                              &length, 0);
    if (rc != 0 || length <= 0 || (size_t)length > response_cap) {
        return -1;
    }
    *response_len = (size_t)length;
    return 0;
}
