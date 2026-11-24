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

/* Split a begin result into the status and slot the checks below read. */
static int32_t begin(int32_t ret, uint8_t* slot)
{
    if (ret >= 0) {
        *slot = (uint8_t)ret;
        ret = PSA_SUCCESS;
    }
    return ret;
}

static int32_t connect_begin(psa_client_id_t caller, uint32_t sid,
                             uint32_t version, uint8_t* slot)
{
    return begin(wt_spm_connect_begin(caller, sid, version), slot);
}

/* The checks pass inputs then outputs; the core takes one half for each. */
static int32_t call_begin(psa_client_id_t caller, psa_handle_t handle,
                          int32_t type, const wt_spm_vec_t* vec,
                          size_t in_len, size_t out_len, uint8_t* slot)
{
    wt_spm_vec_t fixed[WT_SPM_VECS];
    size_t i;

    (void)memset(fixed, 0, sizeof(fixed));
    for (i = 0U; i < in_len && i < PSA_MAX_IOVEC; i++) {
        fixed[i] = vec[i];
    }
    for (i = 0U; i < out_len && i < PSA_MAX_IOVEC; i++) {
        fixed[PSA_MAX_IOVEC + i] = vec[in_len + i];
    }
    return begin(wt_spm_call_begin(caller, handle, type, fixed, in_len,
                                   out_len), slot);
}

static psa_status_t call_finish(uint8_t slot, size_t out_len[PSA_MAX_IOVEC])
{
    wt_spm_vec_t fixed[WT_SPM_VECS];
    psa_status_t status;
    size_t i;

    (void)memset(fixed, 0xA5, sizeof(fixed));
    status = wt_spm_call_finish(slot, fixed);
    for (i = 0U; i < PSA_MAX_IOVEC; i++) {
        out_len[i] = fixed[PSA_MAX_IOVEC + i].len;
    }
    return status;
}

static int32_t close_begin(psa_client_id_t caller, psa_handle_t handle,
                           uint8_t* slot)
{
    return begin(wt_spm_close_begin(caller, handle), slot);
}

static psa_handle_t serve_connect(uint8_t sp, psa_signal_t signal,
                                  uint8_t slot, psa_status_t status)
{
    psa_msg_t msg;

    CHECK(wt_spm_get(sp, signal, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_CONNECT);
    CHECK(wt_spm_reply(sp, msg.handle, status) == WT_SPM_OK);
    CHECK(wt_spm_done(slot, g_wt_spm.slot[slot].caller, PSA_IPC_CONNECT) ==
          1);
    return wt_spm_connect_finish(slot);
}

static psa_handle_t connect_ns(psa_client_id_t caller)
{
    uint8_t slot = WT_SPM_NO_SLOT;

    CHECK(connect_begin(caller, 0x100U, 1U, &slot) == PSA_SUCCESS);
    return serve_connect(0U, 0x10U, slot, PSA_SUCCESS);
}

static void close_handle(psa_client_id_t caller, psa_handle_t handle,
                         uint8_t sp, psa_signal_t signal)
{
    uint8_t slot = WT_SPM_NO_SLOT;
    psa_msg_t msg;

    CHECK(close_begin(caller, handle, &slot) == PSA_SUCCESS);
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
    CHECK(connect_begin(NS1, 0x100U, 0U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(connect_begin(NS1, 0x100U, 2U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(connect_begin(NS1, 0x999U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(connect_begin(NS1, 0x200U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(connect_begin(SP_B, 0x200U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(connect_begin(SP_A, 0x200U, 3U, &slot) ==
          PSA_ERROR_CONNECTION_REFUSED);
    CHECK(connect_begin(NS1, 0x300U, 1U, &slot) ==
          PSA_ERROR_NOT_SUPPORTED);
    CHECK(wt_spm_service_version(NS1, 0x100U) == 1U);
    CHECK(wt_spm_service_version(NS1, 0x200U) == PSA_VERSION_NONE);
    CHECK(wt_spm_service_version(SP_A, 0x200U) == 2U);

    CHECK(connect_begin(SP_A, 0x200U, 1U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_done(slot, SP_A, PSA_IPC_CONNECT) == 0);
    CHECK(wt_spm_done(slot, NS1, PSA_IPC_CONNECT) < 0);
    CHECK(wt_spm_done(slot, SP_A, PSA_IPC_CALL) < 0);
    CHECK(wt_spm_done(slot, SP_A, PSA_IPC_DISCONNECT) < 0);
    CHECK((wt_spm_pending(1U) & 0x20U) != 0U);
    handle = serve_connect(1U, 0x20U, slot, PSA_ERROR_CONNECTION_REFUSED);
    CHECK(handle == PSA_ERROR_CONNECTION_REFUSED);
    CHECK(wt_spm_pending(1U) == 0U);

    handle = connect_ns(NS1);
    CHECK(handle > 0);
    close_handle(NS1, handle, 0U, 0x10U);
    CHECK(close_begin(NS1, handle, &slot) == WT_SPM_E_HANDLE);
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
    CHECK(call_begin(NS1, handle, 7, vec, 1U, 1U, &slot) ==
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
    CHECK(wt_spm_done(slot, g_wt_spm.slot[slot].caller, PSA_IPC_CALL) == 1);
    CHECK(wt_spm_done(slot, g_wt_spm.slot[slot].caller, PSA_IPC_CONNECT) <
          0);
    CHECK(call_finish(slot, out_len) == 42);
    CHECK(out_len[0] == 4U && memcmp(out, "wxyz", 4U) == 0);
    CHECK(out_len[1] == 0U);

    vec[0].len = 1000U;
    vec[1].len = 100U;
    CHECK(call_begin(NS1, handle, 0, vec, 1U, 1U, &slot) ==
          PSA_ERROR_INVALID_ARGUMENT);
    vec[0].len = 3U;
    vec[1].len = sizeof(out);
    CHECK(call_begin(NS2, handle, 0, vec, 1U, 1U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(call_begin(NS1, handle + 0x80, 0, vec, 1U, 1U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(close_begin(NS2, handle, &slot) == WT_SPM_E_POLICY);

    g_write_ok = 0;
    CHECK(call_begin(NS1, handle, 0, vec, 1U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "zz", 2U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(call_finish(slot, out_len) == PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(out_len[0] == 0U && out[0] == 'w');
    g_write_ok = 1;
    CHECK(call_begin(NS1, handle, 0, vec, 1U, 1U, &slot) ==
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
    CHECK(call_begin(NS1, handle, -1, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    close_handle(NS1, handle, 0U, 0x10U);

    handle = connect_ns(NS1);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_SUCCESS);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &other) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(close_begin(NS1, handle, &other) == WT_SPM_E_STATE);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(call_finish(slot, out_len) == PSA_SUCCESS);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);

    wt_spm_call_refuse(NS1, handle);
    close_handle(NS1, handle, 0U, 0x10U);
    CHECK(close_begin(NS1, PSA_NULL_HANDLE, &slot) == PSA_SUCCESS);
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
    CHECK(connect_begin(NS1, 0x100U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_BUSY);
    for (; i < WT_SPM_NS_SLOTS; i++) {
        handle[i] = connect_ns(NS2);
    }
    CHECK(connect_begin(NS2, 0x100U, 1U, &slot) ==
          PSA_ERROR_CONNECTION_BUSY);
    CHECK(connect_begin(SP_A, 0x200U, 1U, &slot) == PSA_SUCCESS);
    wt_spm_abandon(slot);

    for (i = 0U; i < WT_SPM_TRANSFERS; i++) {
        CHECK(call_begin(i < WT_SPM_SLOTS_PER_CLIENT ? NS1 : NS2, handle[i],
                         0, vec, 0U, 0U, &slot) == PSA_SUCCESS);
    }
    CHECK(call_begin(i < WT_SPM_SLOTS_PER_CLIENT ? NS1 : NS2, handle[i], 0,
                     vec, 0U, 0U, &slot) == PSA_ERROR_INSUFFICIENT_MEMORY);
#if defined(WT_SPM_CLIENT_SWEEP)
    wt_spm_client_gone(NS1);
    wt_spm_client_gone(NS2);
    for (i = 0U; i < WT_SPM_SLOTS; i++) {
        CHECK(g_wt_spm.slot[i].state == 0U);
    }
    for (i = 0U; i < WT_SPM_TRANSFERS; i++) {
        CHECK(g_wt_spm.xfer[i].used == 0U);
    }
#endif
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
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    wt_spm_abandon(slot);
    CHECK(close_begin(NS1, handle, &closing) == PSA_SUCCESS);
    CHECK(closing == WT_SPM_NO_SLOT);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "ab", 2U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(out[0] == 0);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_DISCONNECT);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(g_wt_spm.slot[slot].state == 0U);
    CHECK(g_wt_spm.xfer[0].used == 0U);

#if defined(WT_SPM_CLIENT_SWEEP)
    handle = connect_ns(NS1);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    wt_spm_client_gone(NS1);
    CHECK(close_begin(NS1, handle, &closing) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_DISCONNECT);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(g_wt_spm.slot[slot].state == 0U);
#endif

    CHECK(connect_begin(NS1, 0x100U, 1U, &slot) == PSA_SUCCESS);
    wt_spm_abandon(slot);
    CHECK(g_wt_spm.slot[slot].state == 0U);
    CHECK(wt_spm_pending(0U) == 0U);
}

static int eoi(uint8_t sp, psa_signal_t signal)
{
    uint32_t irq = 0U;
    int ret = wt_spm_irq_of(sp, signal, &irq);

    return ret != WT_SPM_OK ? ret : wt_spm_clear(sp, signal);
}

static void test_signals(void)
{
    psa_signal_t asserted = 0U;
    uint32_t irq = 0U;

    wt_spm_core_init();
    CHECK(wt_spm_wait(0U, 0x20U, &asserted) == WT_SPM_E_ARGUMENT);
    CHECK(wt_spm_wait(0U, 0x10U | 0x20U, &asserted) == WT_SPM_E_NOT_READY);
    CHECK(wt_spm_clear(0U, PSA_DOORBELL) == WT_SPM_E_STATE);
    CHECK(wt_spm_notify(SP_A) == WT_SPM_OK);
    CHECK(wt_spm_notify(9) == WT_SPM_E_POLICY);
    CHECK(wt_spm_wait(0U, PSA_WAIT_ANY, &asserted) == WT_SPM_OK);
    CHECK(asserted == PSA_DOORBELL);
    CHECK(wt_spm_clear(0U, PSA_DOORBELL) == WT_SPM_OK);

    CHECK(wt_spm_irq_assert(6U) == WT_SPM_E_POLICY);
    CHECK(wt_spm_irq_assert(5U) == 0);
    CHECK(wt_spm_irq_of(0U, 0x100U, &irq) == WT_SPM_OK && irq == 5U);
    CHECK(eoi(0U, 0x180U) == WT_SPM_E_ARGUMENT);
    CHECK(eoi(0U, 0x10U) == WT_SPM_E_POLICY);
    CHECK(eoi(1U, 0x100U) == WT_SPM_E_POLICY);
    CHECK(eoi(0U, 0x100U) == WT_SPM_OK);
    CHECK(eoi(0U, 0x100U) == WT_SPM_E_STATE);
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
    CHECK(connect_begin(SP_A, 0x200U, 1U, &own_slot) == PSA_SUCCESS);
    own = serve_connect(1U, 0x20U, own_slot, PSA_SUCCESS);
    CHECK(own > 0);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "ab", 2U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_notify(SP_A) == WT_SPM_OK);
    CHECK(wt_spm_sp_restarted(0U, PSA_ERROR_CONNECTION_REFUSED) == 1);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_done(slot, NS1, PSA_IPC_CALL) == 1);
    CHECK(call_finish(slot, out_len) == PSA_ERROR_CONNECTION_REFUSED);
    CHECK(out_len[0] == 0U && out[0] == 0);
    CHECK(wt_spm_pending(0U) == 0U);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 1U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(close_begin(SP_A, own, &slot) == WT_SPM_E_HANDLE);
    close_handle(NS1, handle, 0U, 0x10U);
}
#endif

/* A freed transfer keeps nothing of the message it carried. */
static int transfers_clean(void)
{
    static const wt_spm_xfer_t zero;
    uint32_t i;
    int clean = 1;

    for (i = 0U; i < WT_SPM_TRANSFERS; i++) {
        if (memcmp(&g_wt_spm.xfer[i], &zero, sizeof(zero)) != 0) {
            clean = 0;
        }
    }
    return clean;
}

static void test_handle_reuse(void)
{
    psa_handle_t first;
    psa_handle_t second;
    psa_handle_t first_msg;
    psa_msg_t msg;
    uint8_t slot = 0U;

    wt_spm_core_init();
    CHECK(connect_begin(NS1, 0x100U, 1U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    first_msg = msg.handle;
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    first = wt_spm_connect_finish(slot);
    close_handle(NS1, first, 0U, 0x10U);
    /* 65,535 more reuses: a 16-bit generation would revive both handles. */
    g_wt_spm.slot[slot].gen += 0xFFFFU;
    g_wt_spm.slot[slot].mgen += 0xFFFFU;

    /* The slot is reused: neither old handle may name the new connection. */
    CHECK(connect_begin(NS1, 0x100U, 1U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.handle != first_msg);
    CHECK(wt_spm_reply(0U, first_msg, PSA_SUCCESS) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    second = wt_spm_connect_finish(slot);
    CHECK(second > 0 && second != first);
    CHECK(close_begin(NS1, first, &slot) == WT_SPM_E_HANDLE);
    CHECK(call_begin(NS1, (psa_handle_t)((uint32_t)second ^ 0x60U), 0, NULL,
                     0U, 0U, &slot) == PSA_ERROR_PROGRAMMER_ERROR);
    close_handle(NS1, second, 0U, 0x10U);
}

static void test_fifo(void)
{
    wt_spm_vec_t vec[1] = { { NULL, 0U } };
    size_t out_len[PSA_MAX_IOVEC];
    psa_handle_t first;
    psa_handle_t second;
    psa_handle_t other;
    psa_msg_t msg;
    uint8_t slot = 0U;
    uint8_t other_slot = 0U;
    uint32_t i;

    wt_spm_core_init();
    g_wt_spm.ticket -= 128U;
    first = connect_ns(NS1);
    second = connect_ns(NS2);
    CHECK(connect_begin(SP_A, 0x200U, 1U, &other_slot) == PSA_SUCCESS);
    other = serve_connect(1U, 0x20U, other_slot, PSA_SUCCESS);
    CHECK(call_begin(NS1, first, 1, vec, 0U, 0U, &slot) == PSA_SUCCESS);
    CHECK(call_begin(NS2, second, 2, vec, 0U, 0U, &slot) == PSA_SUCCESS);
    /* 254 more messages pass while the two wait: the ticket wraps. */
    for (i = 0U; i < 254U; i++) {
        CHECK(call_begin(SP_A, other, 0, vec, 0U, 0U, &other_slot) ==
              PSA_SUCCESS);
        CHECK(wt_spm_get(1U, 0x20U, &msg) == PSA_SUCCESS);
        CHECK(wt_spm_reply(1U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
        CHECK(call_finish(other_slot, out_len) == PSA_SUCCESS);
    }
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == 1 && msg.client_id == NS1);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == 2 && msg.client_id == NS2);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_ERROR_DOES_NOT_EXIST);
    CHECK(wt_spm_get(0U, 0U, &msg) == PSA_ERROR_PROGRAMMER_ERROR);
}

static void test_vectors(void)
{
    char in_a[] = "ab";
    char in_b[] = "cde";
    char out_a[3] = { 0 };
    char out_b[2] = { 0 };
    char got[4] = { 0 };
    wt_spm_vec_t vec[5] = { { in_a, 2U }, { in_b, 3U }, { out_a, 3U },
                            { out_b, 2U }, { NULL, 0U } };
    size_t out_len[PSA_MAX_IOVEC];
    size_t done = 0U;
    psa_handle_t handle;
    psa_msg_t msg;
    uint8_t slot = 0U;

    wt_spm_core_init();
    handle = connect_ns(NS1);
    CHECK(call_begin(NS1, handle, 3, vec, 2U, 2U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.in_size[0] == 2U && msg.in_size[1] == 3U);
    CHECK(msg.in_size[2] == 0U && msg.in_size[3] == 0U);
    CHECK(msg.out_size[0] == 3U && msg.out_size[1] == 2U);
    CHECK(msg.out_size[2] == 0U && msg.out_size[3] == 0U);
    CHECK(wt_spm_copy(0U, msg.handle, 1U, got, 3U, 0, &done) == WT_SPM_OK);
    CHECK(done == 3U && memcmp(got, "cde", 3U) == 0);
    /* A NULL buffer skips: the next read starts one byte in. */
    CHECK(wt_spm_copy(0U, msg.handle, 0U, NULL, 1U, 0, &done) == WT_SPM_OK);
    CHECK(done == 1U);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, got, 4U, 0, &done) == WT_SPM_OK);
    CHECK(done == 1U && got[0] == 'b');
    CHECK(wt_spm_copy(0U, msg.handle, 1U, "ZZ", 2U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, "Y", 1U, 1, &done) == WT_SPM_OK);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(call_finish(slot, out_len) == PSA_SUCCESS);
    CHECK(out_len[0] == 1U && out_len[1] == 2U);
    CHECK(out_a[0] == 'Y' && memcmp(out_b, "ZZ", 2U) == 0);
    CHECK(transfers_clean());

    /* Five vectors is a PROGRAMMER ERROR that drops the connection. */
    CHECK(call_begin(NS1, handle, 0, vec, 3U, 2U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    close_handle(NS1, handle, 0U, 0x10U);
}

static void test_reply_rules(void)
{
    wt_spm_vec_t vec[1] = { { NULL, 0U } };
    size_t out_len[PSA_MAX_IOVEC];
    size_t done = 0U;
    psa_handle_t handle;
    psa_msg_t msg;
    uint8_t slot = 0U;

    wt_spm_core_init();
    CHECK(connect_begin(NS1, 0x100U, 1U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_copy(0U, msg.handle, 0U, &done, 1U, 0, &done) ==
          WT_SPM_E_STATE);
    CHECK(wt_spm_reply(0U, msg.handle, 42) == WT_SPM_E_ARGUMENT);
    CHECK(wt_spm_reply(1U, msg.handle, PSA_SUCCESS) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    handle = wt_spm_connect_finish(slot);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_ERROR_CONNECTION_REFUSED) ==
          WT_SPM_E_ARGUMENT);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_ERROR_PROGRAMMER_ERROR) ==
          WT_SPM_OK);
    CHECK(call_finish(slot, out_len) == PSA_ERROR_PROGRAMMER_ERROR);
    /* The service reported a PROGRAMMER ERROR: only a close is left. */
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    close_handle(NS1, handle, 0U, 0x10U);
}

static void test_abandon(void)
{
    wt_spm_vec_t vec[1] = { { NULL, 0U } };
    psa_handle_t handle;
    psa_msg_t msg;
    uint8_t slot = 0U;

    wt_spm_core_init();
    /* A queued call is withdrawn: the service never sees it. */
    handle = connect_ns(NS1);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) == PSA_SUCCESS);
    wt_spm_abandon(slot);
    CHECK(wt_spm_pending(0U) == 0U);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_ERROR_DOES_NOT_EXIST);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    CHECK(transfers_clean());
    close_handle(NS1, handle, 0U, 0x10U);

    /* A held connect that then succeeds is disconnected and released. */
    CHECK(connect_begin(NS1, 0x100U, 1U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    wt_spm_abandon(slot);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(wt_spm_done(slot, NS1, PSA_IPC_CONNECT) != 1);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.type == PSA_IPC_DISCONNECT);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(g_wt_spm.slot[slot].state == 0U);

    /* A held call left without a close keeps the connection in error. */
    handle = connect_ns(NS1);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    wt_spm_abandon(slot);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(wt_spm_done(slot, NS1, PSA_IPC_CALL) != 1 && transfers_clean());
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) ==
          PSA_ERROR_PROGRAMMER_ERROR);
    close_handle(NS1, handle, 0U, 0x10U);
    CHECK(wt_spm_done(WT_SPM_NO_SLOT, NS1, PSA_IPC_CALL) < 0);
    wt_spm_abandon(WT_SPM_NO_SLOT);
    CHECK(transfers_clean());
}

#if defined(WT_FFM_SP_RHANDLE) && (WT_FFM_SP_RHANDLE == 1)
static void test_rhandle(void)
{
    wt_spm_vec_t vec[1] = { { NULL, 0U } };
    size_t out_len[PSA_MAX_IOVEC];
    int marker = 0;
    psa_handle_t handle;
    psa_msg_t msg;
    uint8_t slot = 0U;

    wt_spm_core_init();
    CHECK(connect_begin(NS1, 0x100U, 1U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.rhandle == NULL);
    CHECK(wt_spm_set_rhandle(1U, msg.handle, &marker) == WT_SPM_E_HANDLE);
    CHECK(wt_spm_set_rhandle(0U, msg.handle, &marker) == WT_SPM_OK);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    handle = wt_spm_connect_finish(slot);
    CHECK(call_begin(NS1, handle, 0, vec, 0U, 0U, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.rhandle == &marker);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    CHECK(call_finish(slot, out_len) == PSA_SUCCESS);
    CHECK(close_begin(NS1, handle, &slot) == PSA_SUCCESS);
    CHECK(wt_spm_get(0U, 0x10U, &msg) == PSA_SUCCESS);
    CHECK(msg.rhandle == &marker);
    CHECK(wt_spm_set_rhandle(0U, msg.handle, NULL) == WT_SPM_OK);
    CHECK(g_wt_spm.slot[slot].rhandle == (uintptr_t)&marker);
    CHECK(wt_spm_reply(0U, msg.handle, PSA_SUCCESS) == WT_SPM_OK);
    wt_spm_close_finish(slot);
}
#endif

/* Prints a requirement line only when the test before it added no failure. */
static void report(int before, const char* requirement)
{
    if (g_failures == before) {
        printf("PASS: %s\n", requirement);
    }
}

int main(void)
{
    int before;

    before = g_failures;
    test_connect_policy();
    report(before, "WT-FFM-0020 framework version and connect policy");
    before = g_failures;
    test_call_io();
    report(before, "WT-FFM-0021/0033 connection, messages, vectors and "
           "output revalidation");
    before = g_failures;
    test_error_latch();
    report(before, "WT-FFM-0022 client error latch and dropped close");
    before = g_failures;
    test_quotas();
    report(before, "WT-FFM-0035 bounded pools and scrubbing");
    before = g_failures;
    test_detach();
    report(before, "WT-FFM-0025 a close during a call reaches the service");
    before = g_failures;
    test_signals();
    report(before, "WT-FFM-0036 invalid arguments and empty wait");
    test_handle_reuse();
    test_fifo();
    before = g_failures;
    test_vectors();
    report(before, "WT-FFM-0032 bounded vector rejection");
    before = g_failures;
    test_reply_rules();
    test_abandon();
    report(before, "WT-FFM-0023/0024 reply rules and abandoned messages");
#if defined(WT_FFM_SP_RHANDLE) && (WT_FFM_SP_RHANDLE == 1)
    test_rhandle();
#endif
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
