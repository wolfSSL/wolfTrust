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

/* Host proof for SERVICE_VNET (WT-FFM-0056): two simulated non-secure
 * guests drive the neutral PSA client core through host veneer stubs into
 * the registered SERVICE_VNET relay, which runs the real vnet_switch data
 * plane. Proves the mediated round trip (guest0 TX -> SERVICE_VNET ->
 * switch -> guest1 RX_FETCH), that the SPM-stamped caller identity selects
 * the port, and that spoofed sources, unknown destinations, malformed
 * vectors, and out-of-range identities are refused. */

#include "wolftrust/ffm_boot.h"
#include "wolftrust/spm_sched.h"
#include "wolftrust/services/vnet_relay.h"
#include "wolftrust/vnet/vnet_errors.h"
#include "wolftrust/vnet_psa_transport.h"
#include "wolftrust/ffm_veneer.h"
#include "psa/client.h"
#include "psa_manifest/pid.h"

#include <stdio.h>
#include <string.h>

#define TEST_VNET_SID   4103U
#define TEST_NVM        2U
#define TEST_GUEST0     (-1)
#define TEST_GUEST1     (-2)

/* ---- platform + scheduler stubs the neutral boot core needs ---- */
void wt_platform_panic(void)
{
}

int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg)
{
    (void)runtime; (void)partition_id; (void)entry; (void)arg;
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_validate(void)
{
    return WT_FFM_SUCCESS;
}

int wt_spm_sched_start_all(void)
{
    return WT_FFM_SUCCESS;
}

int wt_spm_hsm_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

int wt_spm_vault_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

int wt_spm_its_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

int wt_spm_ps_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

int wt_spm_vnet_start(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    (void)runtime; (void)partition_id;
    return WT_FFM_SUCCESS;
}

/* ---- host memcheck standing in for the Armv8-M CMSE checker ---- */
static int test_ns_check_read(wt_guest_id_t guest_id, const void* address,
                              size_t size)
{
    (void)guest_id;
    return size == 0U || address != NULL;
}

static int test_ns_check_write(wt_guest_id_t guest_id, void* address,
                               size_t size)
{
    (void)guest_id;
    return size == 0U || address != NULL;
}

/* ---- host veneer stubs: the active simulated guest selects the
 * SPM-stamped client identity, exactly as the CMSE gateway does from the
 * live guest context on target ---- */
static int32_t g_active_client = TEST_GUEST0;

int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version)
{
    return (int32_t)wt_ffm_connect(wt_ffm_boot_runtime_mut(),
                                   g_active_client, sid, version);
}

void WolfTrust_FFM_Close(int32_t handle)
{
    (void)wt_ffm_close(wt_ffm_boot_runtime_mut(), g_active_client, handle);
}

int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                           wt_ffm_veneer_iovec_t* iv)
{
    psa_invec in[WT_FFM_VENEER_IOVEC_MAX];
    psa_outvec out[WT_FFM_VENEER_IOVEC_MAX];
    psa_status_t st;
    uint32_t i;

    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    for (i = 0u; i < iv->in_count; i++) {
        in[i].base = iv->in[i].base;
        in[i].len = iv->in[i].len;
    }
    for (i = 0u; i < iv->out_count; i++) {
        out[i].base = iv->out[i].base;
        out[i].len = iv->out[i].len;
    }
    st = wt_ffm_call(wt_ffm_boot_runtime_mut(), g_active_client, handle,
                     type, in, iv->in_count, out, iv->out_count);
    for (i = 0u; i < iv->out_count; i++) {
        iv->out[i].len = (uint32_t)out[i].len;
    }
    return (int32_t)st;
}

uint32_t WolfTrust_FFM_FrameworkVersion(void)
{
    return PSA_FRAMEWORK_VERSION;
}

uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid)
{
    (void)sid;
    return 1u;
}

/* ---- switch storage, caller-owned per the dataplane contract ---- */
static vnet_vnic_t      g_vnics[TEST_NVM];
static vnet_frame_t     g_frames[8];
static vnet_fdb_entry_t g_fdb[16];
static vnet_rx_desc_t   g_ring_storage[TEST_NVM][8];
static vnet_rx_desc_t*  g_rings[TEST_NVM];
static vnet_switch_t    g_switch;

static uint32_t g_test_tick = 42U;

static uint32_t test_tick(void)
{
    return g_test_tick;
}

/* Stamps the scheduler tick on every gate return, as the target SVC gate
 * does, so the relay ages frames on its production clock. */
static int test_ticking_transport(wt_ffm_runtime_t* runtime,
                                  wt_spm_call_t* call)
{
    int ret;

    ret = wt_spm_transport_direct(runtime, call);
    call->ret_tick = g_test_tick;
    return ret;
}

/* ---- manifest fixture: the VNET partition as production declares it,
 * plus the HSM relay partition the boot core registers unconditionally ---- */
static const wt_service_descriptor_t g_vnet_services[] = {
    {
        "SERVICE_VNET", TEST_VNET_SID, 1U, WT_SERVICE_VERSION_RELAXED,
        0x10U, 0U, 1U, 1U
    }
};

static const wt_service_descriptor_t g_hsm_services[] = {
    {
        "SERVICE_HSM", 4102U, 1U, WT_SERVICE_VERSION_RELAXED,
        0x20U, 0U, 1U, 1U
    }
};

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_HSM", PARTITION_HSM_ID, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_hsm_services, sizeof(g_hsm_services) / sizeof(g_hsm_services[0]),
        NULL, 0U, NULL, 0U
    },
    {
        "PARTITION_VNET", PARTITION_VNET_ID, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_vnet_services,
        sizeof(g_vnet_services) / sizeof(g_vnet_services[0]),
        NULL, 0U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "vnet-relay-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static int g_failures;

static void check(int ok, const char* what)
{
    if (ok) {
        printf("PASS: %s\n", what);
    }
    else {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static void build_frame(uint8_t* f, const uint8_t* dst, const uint8_t* src,
                        const char* payload, size_t payload_len)
{
    memset(f, 0, 64);
    memcpy(&f[0], dst, 6);
    memcpy(&f[6], src, 6);
    f[12] = 0x08U;
    f[13] = 0x00U;
    memcpy(&f[14], payload, payload_len);
}

/* A SERVICE_VNET restart as production performs it: every connection to the
 * partition drops and the switch returns to its boot state. */
static int test_vnet_restart(void)
{
    if (wt_ffm_partition_restarted(wt_ffm_boot_runtime_mut(),
                                   PARTITION_VNET_ID,
                                   PSA_ERROR_COMMUNICATION_FAILURE) < 0) {
        return -1;
    }
    return vnet_switch_init(&g_switch, g_vnics, TEST_NVM, g_frames, 8U,
                            g_fdb, 16U, g_rings, 8U, false);
}

int main(void)
{
    static const uint8_t mac0[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0A };
    static const uint8_t mac1[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0B };
    static const uint8_t mac_unknown[6] =
        { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0C };
    static const char payload[] = "wolfTrust mediated vnet frame";
    uint8_t frame[64];
    uint8_t rx_buf[64];
    uint8_t big_frame[WT_VNET_PSA_MTU + 4U];
    vnet_info_t info;
    vnet_rx_meta_t meta;
    psa_handle_t h0;
    psa_handle_t h1;
    psa_handle_t h_bad;
    psa_invec in_vec;
    psa_outvec out_vec[2];
    psa_status_t status;
    wt_vnet_psa_ctx_t c0;
    wt_vnet_psa_ctx_t c1;
    int n;
    uint32_t i;

    for (i = 0U; i < TEST_NVM; i++) {
        g_rings[i] = g_ring_storage[i];
    }

    check(wt_ffm_boot_init(&g_manifest) == WT_FFM_SUCCESS,
          "WT-FFM-0056 boot core initializes from the manifest");
    wt_ffm_boot_set_memcheck(test_ns_check_read, test_ns_check_write);

    check(wt_ffm_register_partition(wt_ffm_boot_runtime_mut(),
                                    PARTITION_VNET_ID,
                                    wt_vnet_relay_dispatch,
                                    NULL) == WT_FFM_SUCCESS,
          "WT-FFM-0056 SERVICE_VNET partition registers with the SPM");

    /* Fail-closed proof: connected but no switch installed. */
    g_active_client = TEST_GUEST0;
    h0 = psa_connect(TEST_VNET_SID, 1U);
    check(PSA_HANDLE_IS_VALID(h0),
          "WT-FFM-0056 psa_connect(SERVICE_VNET) returns a valid handle");
    build_frame(frame, mac1, mac0, payload, sizeof(payload) - 1U);
    in_vec.base = frame;
    in_vec.len = sizeof(frame);
    status = psa_call(h0, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == PSA_ERROR_NOT_SUPPORTED,
          "WT-FFM-0056 relay fails closed with no switch installed");

    check(vnet_switch_init(&g_switch, g_vnics, TEST_NVM,
                           g_frames, 8U, g_fdb, 16U, g_rings, 8U,
                           false) == WT_VNET_OK,
          "WT-FFM-0056 switch data plane initializes");
    wt_vnet_relay_set_switch(&g_switch);
    wt_vnet_relay_set_tick(test_tick);

    /* Open + bind both guest ports through the mediated path. */
    memset(&info, 0, sizeof(info));
    out_vec[0].base = &info;
    out_vec[0].len = sizeof(info);
    status = psa_call(h0, WT_VNET_OP_OPEN, NULL, 0U, out_vec, 1U);
    check(status == PSA_SUCCESS && info.abi_version == WT_VNET_ABI_VERSION,
          "WT-FFM-0056 guest0 OPEN returns the switch ABI info");
    check(info.mtu <= WT_VNET_PSA_MTU,
          "WT-FFM-0056 OPEN caps the reported MTU to the transfer budget");

    in_vec.base = mac0;
    in_vec.len = sizeof(mac0);
    status = psa_call(h0, WT_VNET_OP_SET_MAC, &in_vec, 1U, NULL, 0U);
    check(status == PSA_SUCCESS,
          "WT-FFM-0056 guest0 SET_MAC binds its port MAC");

    g_active_client = TEST_GUEST1;
    h1 = psa_connect(TEST_VNET_SID, 1U);
    check(PSA_HANDLE_IS_VALID(h1),
          "WT-FFM-0056 guest1 psa_connect returns a distinct handle");
    memset(&info, 0, sizeof(info));
    out_vec[0].base = &info;
    out_vec[0].len = sizeof(info);
    status = psa_call(h1, WT_VNET_OP_OPEN, NULL, 0U, out_vec, 1U);
    check(status == PSA_SUCCESS,
          "WT-FFM-0056 guest1 OPEN succeeds on its own port");
    in_vec.base = mac1;
    in_vec.len = sizeof(mac1);
    status = psa_call(h1, WT_VNET_OP_SET_MAC, &in_vec, 1U, NULL, 0U);
    check(status == PSA_SUCCESS,
          "WT-FFM-0056 guest1 SET_MAC binds its port MAC");

    /* The mediated round trip: guest0 TX -> switch -> guest1 RX_FETCH. */
    g_active_client = TEST_GUEST0;
    build_frame(frame, mac1, mac0, payload, sizeof(payload) - 1U);
    in_vec.base = frame;
    in_vec.len = sizeof(frame);
    status = psa_call(h0, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == PSA_SUCCESS,
          "WT-FFM-0056 guest0 TX unicast to guest1 succeeds");

    g_active_client = TEST_GUEST1;
    memset(&meta, 0, sizeof(meta));
    memset(rx_buf, 0, sizeof(rx_buf));
    out_vec[0].base = &meta;
    out_vec[0].len = sizeof(meta);
    out_vec[1].base = rx_buf;
    out_vec[1].len = sizeof(rx_buf);
    status = psa_call(h1, WT_VNET_OP_RX_FETCH, NULL, 0U, out_vec, 2U);
    check(status == PSA_SUCCESS && meta.len == sizeof(frame) &&
              meta.src_vm == 0U,
          "WT-FFM-0056 guest1 RX_FETCH returns the delivered frame meta");
    check(memcmp(rx_buf, frame, sizeof(frame)) == 0,
          "WT-FFM-0056 mediated frame payload is byte-exact");

    status = psa_call(h1, WT_VNET_OP_RX_FETCH, NULL, 0U, out_vec, 2U);
    check(status == (psa_status_t)WT_VNET_E_EMPTY,
          "WT-FFM-0056 guest1 queue drains after one fetch (slot released)");

    g_active_client = TEST_GUEST0;
    out_vec[0].base = &meta;
    out_vec[0].len = sizeof(meta);
    out_vec[1].base = rx_buf;
    out_vec[1].len = sizeof(rx_buf);
    status = psa_call(h0, WT_VNET_OP_RX_FETCH, NULL, 0U, out_vec, 2U);
    check(status == (psa_status_t)WT_VNET_E_EMPTY,
          "WT-FFM-0056 no reflected or cross-port delivery to guest0");

    /* Source spoof: guest0 transmitting with guest1's MAC is refused. */
    build_frame(frame, mac1, mac1, payload, sizeof(payload) - 1U);
    in_vec.base = frame;
    in_vec.len = sizeof(frame);
    status = psa_call(h0, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == (psa_status_t)WT_VNET_E_SPOOF,
          "WT-FFM-0056 spoofed source MAC is refused at the port");

    /* Unknown unicast with flooding disabled is dropped. */
    build_frame(frame, mac_unknown, mac0, payload, sizeof(payload) - 1U);
    in_vec.base = frame;
    in_vec.len = sizeof(frame);
    status = psa_call(h0, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == (psa_status_t)WT_VNET_E_DROPPED_UNKNOWN,
          "WT-FFM-0056 unknown unicast is dropped, not flooded");

    /* Malformed vectors are refused before the switch runs. */
    in_vec.base = frame;
    in_vec.len = 10U;
    status = psa_call(h0, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == (psa_status_t)WT_VNET_E_FRAME_LEN,
          "WT-FFM-0056 a runt frame is refused");

    in_vec.base = mac0;
    in_vec.len = 5U;
    status = psa_call(h0, WT_VNET_OP_SET_MAC, &in_vec, 1U, NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "WT-FFM-0056 a short SET_MAC vector is refused");

    out_vec[0].base = &meta;
    out_vec[0].len = sizeof(meta) - 1U;
    out_vec[1].base = rx_buf;
    out_vec[1].len = sizeof(rx_buf);
    status = psa_call(h0, WT_VNET_OP_RX_FETCH, NULL, 0U, out_vec, 2U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "WT-FFM-0056 an undersized RX meta vector is refused");

    /* SEC review: OPEN advertises WT_VNET_PSA_MTU, so TX must refuse a larger
     * frame; otherwise an oversized frame enters a peer's queue and wedges a
     * receiver whose buffer is sized to the advertised MTU. */
    memset(big_frame, 0, sizeof(big_frame));
    memcpy(&big_frame[0], mac1, sizeof(mac1));
    memcpy(&big_frame[6], mac0, sizeof(mac0));
    in_vec.base = big_frame;
    in_vec.len = (size_t)WT_VNET_PSA_MTU + 1U;
    status = psa_call(h0, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "SEC an over-MTU frame is refused at TX");

    /* SEC review: a receiver that offers a payload buffer smaller than the
     * head frame must not wedge the queue or pin the shared pool slot; the
     * relay drops and releases the undeliverable frame so the queue drains. */
    g_active_client = TEST_GUEST0;
    build_frame(frame, mac1, mac0, payload, sizeof(payload) - 1U);
    in_vec.base = frame;
    in_vec.len = sizeof(frame);
    status = psa_call(h0, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == PSA_SUCCESS, "SEC undersized-RX setup TX succeeds");

    g_active_client = TEST_GUEST1;
    out_vec[0].base = &meta;
    out_vec[0].len = sizeof(meta);
    out_vec[1].base = rx_buf;
    out_vec[1].len = sizeof(frame) - 1U;
    status = psa_call(h1, WT_VNET_OP_RX_FETCH, NULL, 0U, out_vec, 2U);
    check(status == (psa_status_t)WT_VNET_E_BADARG,
          "SEC an undersized RX payload buffer is refused");

    out_vec[0].base = &meta;
    out_vec[0].len = sizeof(meta);
    out_vec[1].base = rx_buf;
    out_vec[1].len = sizeof(rx_buf);
    status = psa_call(h1, WT_VNET_OP_RX_FETCH, NULL, 0U, out_vec, 2U);
    check(status == (psa_status_t)WT_VNET_E_EMPTY,
          "SEC the undeliverable frame is dropped, not wedged at the head");

    g_active_client = TEST_GUEST0;
    status = psa_call(h0, 99, NULL, 0U, NULL, 0U);
    check(status == PSA_ERROR_NOT_SUPPORTED,
          "WT-FFM-0056 an unknown operation is refused");

    /* An identity beyond the port table has no port to operate on. */
    g_active_client = -3;
    h_bad = psa_connect(TEST_VNET_SID, 1U);
    check(PSA_HANDLE_IS_VALID(h_bad),
          "WT-FFM-0056 out-of-range client can connect");
    build_frame(frame, mac1, mac0, payload, sizeof(payload) - 1U);
    in_vec.base = frame;
    in_vec.len = sizeof(frame);
    status = psa_call(h_bad, WT_VNET_OP_TX, &in_vec, 1U, NULL, 0U);
    check(status == (psa_status_t)WT_VNET_E_BADARG,
          "WT-FFM-0056 an out-of-range stamped identity is refused");
    psa_close(h_bad);

    g_active_client = TEST_GUEST1;
    psa_close(h1);
    g_active_client = TEST_GUEST0;
    psa_close(h0);

    /* The guest-side transport itself: the exact client code the reference
     * guests run, driven through the same stubbed gateway. */
    g_active_client = TEST_GUEST0;
    memset(&info, 0, sizeof(info));
    check(wt_vnet_psa_open(&c0, TEST_VNET_SID, 1U, &info) == 0 &&
              info.abi_version == WT_VNET_ABI_VERSION,
          "WT-FFM-0056 client transport open connects and reads info");
    build_frame(frame, mac1, mac0, payload, sizeof(payload) - 1U);
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == 0,
          "WT-FFM-0056 client transport TX succeeds");

    g_active_client = TEST_GUEST1;
    check(wt_vnet_psa_open(&c1, TEST_VNET_SID, 1U, &info) == 0,
          "WT-FFM-0056 client transport guest1 open succeeds");
    memset(rx_buf, 0, sizeof(rx_buf));
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == (int)sizeof(frame) &&
              memcmp(rx_buf, frame, sizeof(frame)) == 0,
          "WT-FFM-0056 client transport RX_FETCH returns the frame");
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == WT_VNET_E_EMPTY,
          "WT-FFM-0056 client transport surfaces EMPTY unchanged");

    /* Idle client connections across a SERVICE_VNET restart, which clears
     * every port and MAC: each endpoint re-registers on its next operation. */
    g_active_client = TEST_GUEST0;
    check(wt_vnet_psa_set_mac(&c0, mac0) == 0,
          "WT-FFM-0056 client transport guest0 binds its MAC");
    g_active_client = TEST_GUEST1;
    check(wt_vnet_psa_set_mac(&c1, mac1) == 0,
          "WT-FFM-0056 client transport guest1 binds its MAC");

    check(test_vnet_restart() == WT_VNET_OK,
          "WT-FFM-0056 SERVICE_VNET restarts with idle client connections");
    g_active_client = TEST_GUEST0;
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) ==
              WT_VNET_E_DROPPED_UNKNOWN,
          "WT-FFM-0056 TX to a peer that has not re-registered is dropped");
    g_active_client = TEST_GUEST1;
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == WT_VNET_E_EMPTY,
          "WT-FFM-0056 RX_FETCH re-registers the receiver after a restart");
    g_active_client = TEST_GUEST0;
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == 0,
          "WT-FFM-0056 TX is delivered once both endpoints re-register");
    g_active_client = TEST_GUEST1;
    memset(rx_buf, 0, sizeof(rx_buf));
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == (int)sizeof(frame) &&
              memcmp(rx_buf, frame, sizeof(frame)) == 0,
          "WT-FFM-0056 client transport RX_FETCH recovers after a sender-first "
          "restart");

    check(test_vnet_restart() == WT_VNET_OK,
          "WT-FFM-0056 SERVICE_VNET restarts again");
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == WT_VNET_E_EMPTY,
          "WT-FFM-0056 the receiver re-registers first");
    g_active_client = TEST_GUEST0;
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == 0,
          "WT-FFM-0056 TX re-registers the sender and is delivered");
    g_active_client = TEST_GUEST1;
    memset(rx_buf, 0, sizeof(rx_buf));
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == (int)sizeof(frame) &&
              memcmp(rx_buf, frame, sizeof(frame)) == 0,
          "WT-FFM-0056 client transport RX_FETCH recovers after a "
          "receiver-first restart");

    /* A receiver that stops draining holds the shared frame pool only until
     * its queued frames age out. */
    wt_vnet_relay_set_tick(NULL);
    wt_vnet_relay_set_transport(test_ticking_transport);
    g_active_client = TEST_GUEST0;
    for (i = 0U; i < 8U; i++) {
        frame[14] = (uint8_t)i;
        check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == 0,
              "SEC TX to a non-draining receiver is queued");
    }
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == WT_VNET_E_POOL_FULL,
          "SEC TX beyond the frame pool is refused while frames are fresh");
    g_test_tick += WT_VNET_TIMEOUT_TICKS;
    frame[14] = 0xA5U;
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == 0,
          "SEC TX succeeds once the undrained frames have expired");
    g_active_client = TEST_GUEST1;
    memset(rx_buf, 0, sizeof(rx_buf));
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == (int)sizeof(frame) &&
              memcmp(rx_buf, frame, sizeof(frame)) == 0,
          "SEC the receiver sees only the frame queued after expiry");
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == WT_VNET_E_EMPTY,
          "SEC expired frames are gone from the receive queue");

    /* Below pool pressure an aged frame still reaches a slow receiver. */
    g_active_client = TEST_GUEST0;
    frame[14] = 0x11U;
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == 0,
          "SEC TX queues a frame for a slow receiver");
    g_test_tick += WT_VNET_TIMEOUT_TICKS;
    frame[14] = 0x22U;
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) == 0,
          "SEC TX past the timeout with free pool slots is queued");
    g_active_client = TEST_GUEST1;
    memset(rx_buf, 0, sizeof(rx_buf));
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == (int)sizeof(frame) && rx_buf[14] == 0x11U,
          "SEC an aged frame is kept while the pool has free slots");
    memset(rx_buf, 0, sizeof(rx_buf));
    n = wt_vnet_psa_rx_fetch(&c1, &meta, rx_buf, sizeof(rx_buf));
    check(n == (int)sizeof(frame) && rx_buf[14] == 0x22U,
          "SEC the newer frame follows the aged one");
    wt_vnet_psa_close(&c1);
    g_active_client = TEST_GUEST0;
    wt_vnet_psa_close(&c0);
    check(wt_vnet_psa_tx(&c0, frame, sizeof(frame)) != 0 &&
              c0.handle == (int32_t)PSA_NULL_HANDLE,
          "WT-FFM-0056 client transport stays closed after close");

    if (g_failures == 0) {
        printf("PASS: vnet_relay (SERVICE_VNET mediated switch dispatch)\n");
        return 0;
    }
    printf("FAIL: vnet_relay (%d failures)\n", g_failures);
    return 1;
}
