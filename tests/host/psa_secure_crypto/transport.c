/* transport.c
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

/* SERVICE_HSM door stand-in: psa_call frames go to the server process,
 * stamped with the client id the test selects, as the SPM would. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "psa/client.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/psa_crypto_wire.h"
#include "transport.h"

/* The Makefile names the server it built, so no input picks what runs. */
#ifndef WT_PSA_SERVER_BIN
#error "build with -DWT_PSA_SERVER_BIN naming the psa_server binary"
#endif

static pid_t g_srv_pid;
static int g_to_srv = -1;
static int g_from_srv = -1;
static int32_t g_client = -1;

static void srv_stop(void)
{
    int st;

    if (g_srv_pid > 0) {
        (void)close(g_to_srv);
        (void)close(g_from_srv);
        /* EOF on its stdin ends the service the way a restart would. */
        (void)waitpid(g_srv_pid, &st, 0);
        g_srv_pid = 0;
        g_to_srv = -1;
        g_from_srv = -1;
    }
}

static int srv_start(void)
{
    int to[2];
    int from[2];

    if (g_srv_pid > 0) {
        return 0;
    }
    if (pipe(to) != 0 || pipe(from) != 0) {
        return -1;
    }
    g_srv_pid = fork();
    if (g_srv_pid == 0) {
        (void)dup2(to[0], STDIN_FILENO);
        (void)dup2(from[1], STDOUT_FILENO);
        (void)close(to[1]);
        (void)close(from[0]);
        (void)execl(WT_PSA_SERVER_BIN, WT_PSA_SERVER_BIN, (char*)NULL);
        _exit(127);
    }
    (void)close(to[0]);
    (void)close(from[1]);
    g_to_srv = to[1];
    g_from_srv = from[0];
    if (atexit(srv_stop) != 0) {
        return -1;
    }
    return (g_srv_pid > 0) ? 0 : -1;
}

void wt_test_set_client(int32_t client)
{
    g_client = client;
}

int wt_test_service_restart(void)
{
    srv_stop();
    return srv_start();
}

static int g_fail_in;

void wt_test_fail_call(int nth)
{
    g_fail_in = nth;
}

static int g_mangle_in;
static int g_mangle_mode;

void wt_test_mangle_reply(int nth, int mode)
{
    g_mangle_in = nth;
    g_mangle_mode = mode;
}

static void mangle(psa_outvec* out, size_t len)
{
    uint32_t big = 0xFFFFU;

    if (g_mangle_mode == WT_TEST_REPLY_SHORT && len > sizeof(int32_t) + 4U) {
        out->len = sizeof(int32_t) + 4U;
    }
    else if (g_mangle_mode == WT_TEST_REPLY_OVERSIZE &&
             len >= sizeof(int32_t) + sizeof(wt_psa_wire_ret_t)) {
        (void)memcpy((uint8_t*)out->base + sizeof(int32_t) +
                     offsetof(wt_psa_wire_ret_t, out_len), &big, sizeof(big));
    }
}

static int xfer(int fd, void* buf, size_t len, int out)
{
    uint8_t* p = (uint8_t*)buf;
    ssize_t n;

    while (len != 0U) {
        n = (out != 0) ? write(fd, p, len) : read(fd, p, len);
        if (n <= 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

uint32_t psa_framework_version(void)
{
    return 0x0101U;
}

uint32_t psa_version(uint32_t sid)
{
    (void)sid;
    return 1U;
}

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    (void)sid;
    (void)version;
    return (srv_start() == 0) ? (psa_handle_t)1 : PSA_ERROR_CONNECTION_REFUSED;
}

void psa_close(psa_handle_t handle)
{
    (void)handle;
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    uint32_t frame[3];
    uint32_t reply[2];

    (void)handle;
    if (type != PSA_IPC_CALL || in_len != 1U || out_len != 1U ||
            in_vec[0].len == 0U || in_vec[0].len > WT_HSM_RELAY_MSG_MAX ||
            srv_start() != 0) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (g_fail_in > 0 && --g_fail_in == 0) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    frame[0] = (uint32_t)g_client;
    frame[1] = (uint32_t)out_vec[0].len;
    frame[2] = (uint32_t)in_vec[0].len;
    if (xfer(g_to_srv, frame, sizeof(frame), 1) != 0 ||
            xfer(g_to_srv, (void*)(uintptr_t)in_vec[0].base, in_vec[0].len,
                 1) != 0 ||
            xfer(g_from_srv, reply, sizeof(reply), 0) != 0 ||
            reply[1] > out_vec[0].len ||
            xfer(g_from_srv, out_vec[0].base, reply[1], 0) != 0) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    out_vec[0].len = reply[1];
    if (g_mangle_in > 0 && --g_mangle_in == 0) {
        mangle(&out_vec[0], reply[1]);
    }
    return (reply[0] == 0U) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}
