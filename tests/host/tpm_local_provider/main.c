/* main.c
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

#include <wolftpm/fwtpm/fwtpm_command.h>

#include <stdio.h>
#include <string.h>

static const uint8_t g_startup[12] = {
    0x80U, 0x01U, 0x00U, 0x00U, 0x00U, 0x0CU,
    0x00U, 0x00U, 0x01U, 0x44U, 0x00U, 0x00U
};
static const uint8_t g_client_cmd[12] = {
    0x80U, 0x01U, 0x00U, 0x00U, 0x00U, 0x0CU,
    0x00U, 0x00U, 0x01U, 0x7BU, 0x00U, 0x08U
};

enum startup_mode {
    STARTUP_OK,
    STARTUP_RC_FAIL,
    STARTUP_SHORT,
    STARTUP_TPM_ERROR
};

static int g_failures;
static unsigned int g_calls;
static unsigned int g_startups;
static unsigned int g_client_cmds;
static int g_started_at_startup;
static enum startup_mode g_mode;

static void check(int ok, const char* what)
{
    if (ok != 0) {
        (void)printf("PASS: %s\n", what);
    }
    else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

int wt_provider_crypto_prepare(void)
{
    return 0;
}

int FWTPM_Init(FWTPM_CTX* ctx)
{
    ctx->wasStarted = 0;
    return 0;
}

int FWTPM_ProcessCommand(FWTPM_CTX* ctx, const byte* cmdBuf, int cmdSize,
                         byte* rspBuf, int* rspSize, int locality)
{
    static const uint8_t ok[10] = {
        0x80U, 0x01U, 0x00U, 0x00U, 0x00U, 0x0AU, 0x00U, 0x00U, 0x00U, 0x00U
    };

    (void)locality;
    g_calls++;
    /* Like fwTPM: rspSize is output-only and rspBuf holds a full frame. */
    (void)memset(rspBuf, 0xEE, FWTPM_MAX_COMMAND_SIZE);
    (void)memcpy(rspBuf, ok, sizeof(ok));
    *rspSize = (int)sizeof(ok);
    if (cmdSize == (int)sizeof(g_startup) &&
            memcmp(cmdBuf, g_startup, sizeof(g_startup)) == 0) {
        g_startups++;
        g_started_at_startup = ctx->wasStarted;
        ctx->lockoutAuthFailed = 0;
        if (g_mode == STARTUP_RC_FAIL) {
            return -1;
        }
        if (g_mode == STARTUP_SHORT) {
            *rspSize = 9;
        }
        else if (g_mode == STARTUP_TPM_ERROR) {
            rspBuf[9] = 0x01U;
        }
        else {
            ctx->wasStarted = 1;
        }
        return 0;
    }
    if (cmdSize == (int)sizeof(g_client_cmd) &&
            memcmp(cmdBuf, g_client_cmd, sizeof(g_client_cmd)) == 0) {
        g_client_cmds++;
    }
    return 0;
}

static int process_cap(void* context, size_t response_cap)
{
    uint8_t command[sizeof(g_client_cmd)];
    uint8_t response[FWTPM_MAX_COMMAND_SIZE];
    size_t response_len = 99U;
    int rc;

    (void)memcpy(command, g_client_cmd, sizeof(command));
    g_calls = 0U;
    g_startups = 0U;
    g_client_cmds = 0U;
    rc = wt_tpm_local_provider_process(command, sizeof(command), response,
                                       response_cap, &response_len,
                                       context);
    if (rc != 0 && response_len != 0U) {
        return -2;
    }
    return rc;
}

static int process(void* context)
{
    return process_cap(context, FWTPM_MAX_COMMAND_SIZE);
}

static void test_failed_reset(void* context, enum startup_mode mode,
                              const char* what)
{
    g_wt_interface_client_epoch++;
    g_mode = mode;
    check(process(context) == -1 && g_startups == 1U && g_client_cmds == 0U,
          what);
}

int main(void)
{
    void* context = NULL;
    FWTPM_CTX* tpm;

    check(wt_tpm_local_provider_init(&context) == 0 && context != NULL,
          "provider init");
    tpm = (FWTPM_CTX*)context;
    tpm->wasStarted = 1;
    g_mode = STARTUP_OK;
    check(process(context) == 0 && g_calls == 1U && g_client_cmds == 1U,
          "a request from the same client runs without a reset");
    check(process_cap(context, FWTPM_MAX_COMMAND_SIZE - 1U) != 0 &&
              g_calls == 0U,
          "a response buffer below a full fwTPM frame is refused");

    g_wt_interface_client_epoch++;
    tpm->lockoutAuthFailed = 1;
    check(process(context) == 0 && g_calls == 2U && g_startups == 1U &&
              g_started_at_startup == 0 && g_client_cmds == 1U &&
              tpm->wasStarted == 1,
          "a departed client gets Startup(CLEAR) before the next command");
    check(tpm->lockoutAuthFailed == 1,
          "the reset keeps the lockoutAuth lock that clockless Startup clears");
    tpm->lockoutAuthFailed = 0;
    check(process(context) == 0 && g_calls == 1U && g_startups == 0U,
          "the reset runs once per departure");

    test_failed_reset(context, STARTUP_RC_FAIL,
                      "a failed Startup refuses the client command");
    test_failed_reset(context, STARTUP_SHORT,
                      "a short Startup response refuses the client command");
    test_failed_reset(context, STARTUP_TPM_ERROR,
                      "a Startup error code refuses the client command");
    g_mode = STARTUP_OK;
    check(process(context) == 0 && g_startups == 1U && g_client_cmds == 1U,
          "a failed reset is retried on the next request");
    check(process(context) == 0 && g_startups == 0U,
          "a retried reset completes the departure");

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: TPM provider client reset\n");
    return 0;
}
