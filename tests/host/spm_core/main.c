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

#include <stdio.h>
#include <string.h>

#include "wolftrust/manifest.h"
#include "wolftrust/spm_core.h"

#define NS1 (-1)
#define NS2 (-2)
#define SP_A 1
#define SP_B 2

const wt_spm_service_t g_wt_spm_services[] = {
    { 0x100U, 1U, 0x10U, 0U, (uint8_t)WT_SERVICE_VERSION_STRICT, 1U, 1U },
    { 0x200U, 2U, 0x20U, 1U, (uint8_t)WT_SERVICE_VERSION_RELAXED, 0U, 1U },
    { 0x300U, 1U, 0x40U, 1U, (uint8_t)WT_SERVICE_VERSION_UNSPECIFIED, 1U, 0U }
};
const uint8_t g_wt_spm_service_count = 3U;
const wt_spm_sp_ipc_t g_wt_spm_sps[] = {
    { SP_A, 0x2U, 0x10U | PSA_DOORBELL | 0x100U },
    { SP_B, 0x0U, 0x20U | 0x40U | PSA_DOORBELL }
};
const uint8_t g_wt_spm_sp_count = 2U;
const wt_spm_irq_t g_wt_spm_irqs[] = { { 5U, 0x100U, 0U } };
const uint8_t g_wt_spm_irq_count = 1U;

static int g_write_ok = 1;
static int g_failures;

int wt_spm_caller_can_write(psa_client_id_t caller, void* base, size_t len)
{
    (void)caller;
    (void)base;
    (void)len;
    return g_write_ok;
}

#define CHECK(cond) check((cond) != 0, #cond, __LINE__)

static void check(int ok, const char* what, int line)
{
    if (!ok) {
        printf("FAIL line %d: %s\n", line, what);
        g_failures++;
    }
}

static psa_handle_t serve_connect(uint8_t sp, psa_signal_t signal,
                                  uint8_t slot, psa_status_t status)
{
    psa_msg_t msg;

    CHECK(wt_spm_get(sp, signal, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_CONNECT);
    CHECK(wt_spm_reply(sp, msg.handle, status) == WT_SPM_OK);
    CHECK(wt_spm_done(slot));
    return wt_spm_connect_finish(slot);
}

static psa_handle_t connect_ns(psa_client_id_t caller)
{
    uint8_t slot = WT_SPM_NO_SLOT;

    CHECK(wt_spm_connect_begin(caller, 0x100U, 1U, &slot) == PSA_SUCCESS);
    return serve_connect(0U, 0x10U, slot, PSA_SUCCESS);
}

static void close_handle(psa_client_id_t caller, psa_handle_t handle,
                         uint8_t sp, psa_signal_t signal)
{
    uint8_t slot = WT_SPM_NO_SLOT;
    psa_msg_t msg;

    CHECK(wt_spm_close_begin(caller, handle, &slot) == PSA_SUCCESS);
    CHECK(slot != WT_SPM_NO_SLOT);
    CHECK(wt_spm_get(sp, signal, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_DISCONNECT);
    CHECK(wt_spm_reply(sp, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    wt_spm_close_finish(slot);
}

static void test_connect_policy(void)
{
    uint8_t slot = 0U;
    psa_handle_t handle;

    wt_spm_core_init();
    CHECK(wt_spm_connect_begin(NS1, 0x100U, 0U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_connect_begin(NS1, 0x100U, 2U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_connect_begin(NS1, 0x999U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_connect_begin(NS1, 0x200U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_connect_begin(SP_B, 0x200U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_connect_begin(SP_A, 0x200U, 3U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_connect_begin(NS1, 0x300U, 1U, &slot) ==
          PSA_ERROR_NOT_SUPPORTED);
    CHECK(wt_spm_service_version(NS1, 0x100U) == 1U);
    CHECK(wt_spm_service_version(NS1, 0x200U) == PSA_VERSION_NONE);
    CHECK(wt_spm_service_version(SP_A, 0x200U) == 2U);

    CHECK(wt_spm_connect_begin(SP_A, 0x200U, 1U, &slot) == PSA_SUCCESS);
    CHECK(!wt_spm_done(slot));
    CHECK((wt_spm_pending(1U) & 0x20U) != 0U);
    handle = serve_connect(1U, 0x20U, slot, PSA_ERROR_CONNECTION_REFUSED);
    CHECK(handle == PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_pending(1U) == 0U);

    handle = connect_ns(NS1);
    CHECK(handle > 0);
    close_handle(NS1, handle, 0U, 0x10U);
    CHECK(wt_spm_close_begin(NS1, handle, &slot) == WT_SPM_E_HANDLE);
}

static void test_call_io(void)
{
    char in[] = "abc";
    char out[8] = { 0 };
    char got[8] = { 0 };
    wt_spm_vec_t vec[2] = { { in, 3U }, { out, sizeof(out) } };
    size_t out_len[PSA_MAX_IOVEC];
    size_t done = 0U;
    psa_handle_t handle;
    psa_msg_t msg;
    uint8_t slot = 0U;

    wt_spm_core_init();
    handle = connect_ns(NS1);
    CHECK(wt_spm_call_begin(NS1, handle, 7, vec, 1U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == 7 && msg.client_id == NS1);
    CHECK(msg.in_size[0] == 3U && msg.out_size[0] == sizeof(out));
    CHECK(msg.in_size[1] == 0U && msg.out_size[1] == 0U);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, got, 2U, 0, &done) == WT_SPM_OK);
    CHECK(done == 2U && memcmp(got, "ab", 2U) == 0);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, got, 5U, 0, &done) == WT_SPM_OK);
    CHECK(done == 1U && got[0] == 'c');
    CHECK(wt_spm_copy(0U, msg.handle, 1U, got, 5U, 0, &done) == WT_SPM_OK);
    CHECK(done == 0U);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "wxyz", 4U, 1, &done) ==
          WT_SPM_OK);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "12345", 5U, 1, &done) ==
          WT_SPM_E_BUFFER);
    CHECK(wt_spm_copy(0U, msg.handle, 2U, NULL, 0U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_copy(0U, msg.handle, 2U, "x", 1U, 1, &done) ==
          WT_SPM_E_BUFFER);
    CHECK(wt_spm_copy(0U, msg.handle, 4U, got, 1U, 0, &done) ==
          WT_SPM_E_ARGUMENT);
    CHECK(wt_spm_copy(1U, msg.handle, 0U, got, 1U, 0, &done) ==
          WT_SPM_E_HANDLE);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_ERROR_CONNECTION_BUSY) ==
          WT_SPM_E_ARGUMENT);
    CHECK(wt_spm_reply(0U, msg.handle, 42) == WT_SPM_OK);
    CHECK(wt_spm_reply(0U, msg.handle, 42) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_done(slot));
    CHECK(wt_spm_call_finish(slot, out_len) == 42);
    CHECK(out_len[0] == 4U && memcmp(out, "wxyz", 4U) == 0);
    CHECK(out_len[1] == 0U);

    vec[0].len = 1000U;
    vec[1].len = 100U;
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 1U, 1U, &slot) ==
          PSA_ERROR_INVALID_ARGUMENT);
    vec[0].len = 3U;
    vec[1].len = sizeof(out);
    CHECK(wt_spm_call_begin(NS2, handle, 0, vec, 1U, 1U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(wt_spm_call_begin(NS1, handle + 0x80, 0, vec, 1U, 1U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(wt_spm_close_begin(NS2, handle, &slot) == WT_SPM_E_POLICY);

    g_write_ok = 0;
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 1U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "zz", 2U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(wt_spm_call_finish(slot, out_len) == PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(out_len[0] == 0U && out[0] == 'w');
    g_write_ok = 1;
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 1U, 1U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    close_handle(NS1, handle, 0U, 0x10U);
}

static void test_error_latch(void)
{
    wt_spm_vec_t vec[1] = { { NULL, 0U } };
    size_t out_len[PSA_MAX_IOVEC];
    psa_handle_t handle;
    psa_msg_t msg;
    uint8_t slot = 0U;
    uint8_t other = 0U;

    wt_spm_core_init();
    handle = connect_ns(NS1);
    CHECK(wt_spm_call_begin(NS1, handle, -1, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    close_handle(NS1, handle, 0U, 0x10U);

    handle = connect_ns(NS1);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 0U, &other) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(wt_spm_close_begin(NS1, handle, &other) == WT_SPM_E_STATE);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(wt_spm_call_finish(slot, out_len) == PSA_SUCCESS);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);

    wt_spm_call_refuse(NS1, handle);
    close_handle(NS1, handle, 0U, 0x10U);
    CHECK(wt_spm_close_begin(NS1, PSA_NULL_HANDLE, &slot) == PSA_SUCCESS);
    CHECK(slot == WT_SPM_NO_SLOT);
}

static void test_quotas(void)
{
    psa_handle_t handle[WT_SPM_SLOTS];
    wt_spm_vec_t vec[1] = { { NULL, 0U } };
    uint8_t slot = 0U;
    uint32_t i;

    wt_spm_core_init();
    for (i = 0U; i < WT_SPM_SLOTS_PER_CLIENT; i++) {
        handle[i] = connect_ns(NS1);
        CHECK(handle[i] > 0);
    }
    CHECK(wt_spm_connect_begin(NS1, 0x100U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_BUSY);
    for (; i < WT_SPM_NS_SLOTS; i++) {
        handle[i] = connect_ns(NS2);
    }
    CHECK(wt_spm_connect_begin(NS2, 0x100U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_BUSY);
    CHECK(wt_spm_connect_begin(SP_A, 0x200U, 1U, &slot) == PSA_SUCCESS);
    wt_spm_abandon(slot);

    for (i = 0U; i < WT_SPM_TRANSFERS; i++) {
        CHECK(wt_spm_call_begin(NS1, handle[i], 0, vec, 0U, 0U, &slot) ==
              PSA_SUCCESS);
    }
    CHECK(wt_spm_call_begin(NS1, handle[i], 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_INSUFFICIENT_MEMORY);
    wt_spm_client_gone(NS1);
    wt_spm_client_gone(NS2);
    for (i = 0U; i < WT_SPM_SLOTS; i++) {
        CHECK(g_wt_spm.slot[i].state == 0U);
    }
    for (i = 0U; i < WT_SPM_TRANSFERS; i++) {
        CHECK(g_wt_spm.xfer[i].used == 0U);
    }
}

static void test_detach(void)
{
    char out[4] = { 0 };
    wt_spm_vec_t vec[1] = { { out, sizeof(out) } };
    psa_handle_t handle;
    psa_msg_t msg;
    size_t done = 0U;
    uint8_t slot = 0U;
    uint8_t closing = 0U;

    wt_spm_core_init();
    handle = connect_ns(NS1);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    wt_spm_abandon(slot);
    CHECK(wt_spm_close_begin(NS1, handle, &closing) == PSA_SUCCESS);
    CHECK(closing == WT_SPM_NO_SLOT);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "ab", 2U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(out[0] == 0);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_DISCONNECT);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(g_wt_spm.slot[slot].state == 0U);
    CHECK(g_wt_spm.xfer[0].used == 0U);

    handle = connect_ns(NS1);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    wt_spm_client_gone(NS1);
    CHECK(wt_spm_close_begin(NS1, handle, &closing) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_DISCONNECT);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(g_wt_spm.slot[slot].state == 0U);

    CHECK(wt_spm_connect_begin(NS1, 0x100U, 1U, &slot) == PSA_SUCCESS);
    wt_spm_abandon(slot);
    CHECK(g_wt_spm.slot[slot].state == 0U);
    CHECK(wt_spm_pending(0U) == 0U);
}

static void test_signals(void)
{
    psa_signal_t asserted = 0U;
    uint32_t irq = 0U;

    wt_spm_core_init();
    CHECK(wt_spm_wait(0U, 0x20U, &asserted) == WT_SPM_E_ARGUMENT);
    CHECK(wt_spm_wait(0U, 0x10U | 0x20U, &asserted) == WT_SPM_E_NOT_READY);
    CHECK(wt_spm_clear(0U) == WT_SPM_E_STATE);
    CHECK(wt_spm_notify(SP_A) == WT_SPM_OK);
    CHECK(wt_spm_notify(9) == WT_SPM_E_POLICY);
    CHECK(wt_spm_wait(0U, PSA_WAIT_ANY, &asserted) == WT_SPM_OK);
    CHECK(asserted == PSA_DOORBELL);
    CHECK(wt_spm_clear(0U) == WT_SPM_OK);

    CHECK(wt_spm_irq_assert(6U) == WT_SPM_E_POLICY);
    CHECK(wt_spm_irq_assert(5U) == 0);
    CHECK(wt_spm_irq_of(0U, 0x100U, &irq) == WT_SPM_OK && irq == 5U);
    CHECK(wt_spm_eoi(0U, 0x180U) == WT_SPM_E_ARGUMENT);
    CHECK(wt_spm_eoi(0U, 0x10U) == WT_SPM_E_POLICY);
    CHECK(wt_spm_eoi(1U, 0x100U) == WT_SPM_E_POLICY);
    CHECK(wt_spm_eoi(0U, 0x100U) == WT_SPM_OK);
    CHECK(wt_spm_eoi(0U, 0x100U) == WT_SPM_E_STATE);
}

#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
static void test_restart(void)
{
    char out[4] = { 0 };
    wt_spm_vec_t vec[1] = { { out, sizeof(out) } };
    size_t out_len[PSA_MAX_IOVEC];
    psa_handle_t handle;
    psa_handle_t own;
    psa_msg_t msg;
    size_t done = 0U;
    uint8_t slot = 0U;
    uint8_t own_slot = 0U;

    wt_spm_core_init();
    handle = connect_ns(NS1);
    CHECK(wt_spm_connect_begin(SP_A, 0x200U, 1U, &own_slot) == PSA_SUCCESS);
    own = serve_connect(1U, 0x20U, own_slot, PSA_SUCCESS);
    CHECK(own > 0);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "ab", 2U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_notify(SP_A) == WT_SPM_OK);
    CHECK(wt_spm_sp_restarted(0U, PSA_ERROR_CONNECTION_REFUSED) == 1);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_done(slot));
    CHECK(wt_spm_call_finish(slot, out_len) == PSA_ERROR_CONNECTION_REFUSED);
    CHECK(out_len[0] == 0U && out[0] == 0);
    CHECK(wt_spm_pending(0U) == 0U);
    CHECK(wt_spm_call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(wt_spm_close_begin(SP_A, own, &slot) == WT_SPM_E_HANDLE);
    close_handle(NS1, handle, 0U, 0x10U);
}
#endif

int main(void)
{
    test_connect_policy();
    test_call_io();
    test_error_latch();
    test_quotas();
    test_detach();
    test_signals();
#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
    test_restart();
#endif
    if (g_failures != 0) {
        printf("spm_core: %d failure(s)\n", g_failures);
        return 1;
    }
    printf("PASS: spm_core\n");
    return 0;
}
