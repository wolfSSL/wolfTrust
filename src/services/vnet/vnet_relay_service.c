/* vnet_relay_service.c
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

#include "wolftrust/services/vnet_relay.h"
#include "wolftrust/vnet/vnet_errors.h"
#include "wolftrust/vnet/vnet_config.h"

#include <string.h>

/* SWD forensics: last op handled ((type<<24)) with the reply status low
 * 24 bits, and a count of dispatch-loop passes. */
volatile uint32_t g_wt_vnet_last_reply;
volatile uint32_t g_wt_vnet_dispatch_count;

static vnet_switch_t* g_vnet_sw = NULL;
static uint32_t (*g_vnet_tick)(void) = NULL;
static wt_spm_transport_fn g_vnet_transport = wt_spm_transport_direct;
/* Confined time source: the SVC stamps the scheduler tick into every gate
 * return (ret_tick), so the unprivileged relay ages frames without a tick
 * callback that would dereference monitor state outside its MPU domain. */
static uint32_t g_vnet_now_tick;

/* Frame staging between the FF-M copied vectors and the switch. One
 * message is in flight at a time in the cooperative SPM, and file scope
 * keeps the 1536-byte frames off the partition stack. */
static uint8_t g_vnet_tx_scratch[WT_VNET_FRAME_MAX];
static uint8_t g_vnet_rx_scratch[WT_VNET_FRAME_MAX];
/* Reply staging in service .bss: the gate bounds-checks every psa_write
 * buffer against the partition whitelist, which does not cover the
 * vnet coroutine stack band. */
static vnet_info_t g_vnet_info_scratch;
static vnet_rx_meta_t g_vnet_meta_scratch;

void wt_vnet_relay_set_switch(vnet_switch_t* sw)
{
    g_vnet_sw = sw;
}

void wt_vnet_relay_set_tick(uint32_t (*tick_fn)(void))
{
    g_vnet_tick = tick_fn;
}

void wt_vnet_relay_set_transport(wt_spm_transport_fn fn)
{
    g_vnet_transport = (fn != NULL) ? fn : wt_spm_transport_direct;
}

/* The SPM stamps NS callers as -(guest + 1); the mapping mirrors
 * wt_ffm_boot_caller_guest. Secure-origin callers have no switch port. */
static int wt_vnet_relay_caller_vm(const vnet_switch_t* sw, int32_t client_id,
                                   uint32_t* out_vm)
{
    uint32_t vm;

    if (client_id >= 0) {
        return WT_VNET_E_BADARG;
    }
    vm = (uint32_t)(-(client_id + 1));
    if (vm >= sw->nvm) {
        return WT_VNET_E_BADARG;
    }
    *out_vm = vm;
    return WT_VNET_OK;
}

static int wt_vnet_relay_read_vec(wt_ffm_runtime_t* runtime,
                                  int32_t partition_id,
                                  psa_handle_t msg_handle, uint32_t vec_idx,
                                  uint8_t* buffer, size_t capacity,
                                  size_t* out_len)
{
    wt_spm_call_t call;
    size_t len = 0U;

    for (;;) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_READ;
        call.partition_id = partition_id;
        call.msg_handle = msg_handle;
        call.vec_idx = vec_idx;
        call.buffer = buffer + len;
        call.num_bytes = capacity - len;
        if (g_vnet_transport(runtime, &call) != WT_FFM_SUCCESS) {
            return WT_FFM_ERROR_STATE;
        }
        if (call.ret_size == 0U) {
            break;
        }
        len += call.ret_size;
        if (len >= capacity) {
            break;
        }
    }
    *out_len = len;
    return WT_FFM_SUCCESS;
}

static int wt_vnet_relay_write_vec(wt_ffm_runtime_t* runtime,
                                   int32_t partition_id,
                                   psa_handle_t msg_handle, uint32_t vec_idx,
                                   const void* data, size_t len)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WRITE;
    call.partition_id = partition_id;
    call.msg_handle = msg_handle;
    call.vec_idx = vec_idx;
    call.buffer = (void*)(uintptr_t)data;
    call.num_bytes = len;
    if (g_vnet_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

static psa_status_t wt_vnet_relay_open(wt_ffm_runtime_t* runtime,
                                       int32_t partition_id,
                                       vnet_switch_t* sw, uint32_t vm,
                                       const psa_msg_t* msg)
{
    int rc;

    if (msg->out_size[0] < sizeof(g_vnet_info_scratch)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    rc = vnet_switch_open(sw, vm, &g_vnet_info_scratch);
    if (rc != WT_VNET_OK) {
        return (psa_status_t)rc;
    }
    if (g_vnet_info_scratch.mtu > (uint16_t)WT_VNET_PSA_MTU) {
        g_vnet_info_scratch.mtu = (uint16_t)WT_VNET_PSA_MTU;
    }
    if (wt_vnet_relay_write_vec(runtime, partition_id, msg->handle, 0U,
                                &g_vnet_info_scratch,
                                sizeof(g_vnet_info_scratch)) !=
            WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_vnet_relay_set_mac(wt_ffm_runtime_t* runtime,
                                          int32_t partition_id,
                                          vnet_switch_t* sw, uint32_t vm,
                                          const psa_msg_t* msg)
{
    vnet_mac_t mac;
    size_t len = 0U;
    int rc;

    if (msg->in_size[0] != VNET_MAC_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_vnet_relay_read_vec(runtime, partition_id, msg->handle, 0U,
                               mac.b, VNET_MAC_LEN,
                               &len) != WT_FFM_SUCCESS ||
            len != VNET_MAC_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    rc = vnet_switch_assign_mac(sw, vm, &mac);
    if (rc != WT_VNET_OK) {
        return (psa_status_t)rc;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_vnet_relay_tx(wt_ffm_runtime_t* runtime,
                                     int32_t partition_id,
                                     vnet_switch_t* sw, uint32_t vm,
                                     const psa_msg_t* msg)
{
    size_t len = 0U;
    uint32_t tick;
    int rc;

    if (msg->in_size[0] == 0U ||
            msg->in_size[0] > (size_t)WT_VNET_PSA_MTU) {
        /* OPEN advertises WT_VNET_PSA_MTU as the link MTU; refuse larger
         * frames here so an oversized frame can never enter a peer's queue
         * and wedge a receiver sized to the advertised MTU. */
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (msg->in_size[0] < (size_t)WT_VNET_FRAME_MIN) {
        return (psa_status_t)WT_VNET_E_FRAME_LEN;
    }
    if (wt_vnet_relay_read_vec(runtime, partition_id, msg->handle, 0U,
                               g_vnet_tx_scratch,
                               sizeof(g_vnet_tx_scratch),
                               &len) != WT_FFM_SUCCESS ||
            len != msg->in_size[0]) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    tick = (g_vnet_tick != NULL) ? g_vnet_tick() : g_vnet_now_tick;
    rc = vnet_switch_tx(sw, vm, g_vnet_tx_scratch, (uint16_t)len, tick);
    if (rc != WT_VNET_OK) {
        return (psa_status_t)rc;
    }
    return PSA_SUCCESS;
}

/* Dequeue one frame: poll, copy the payload out, release the slot, then return
 * metadata including the now-consumed slot/generation token to the caller. */
static psa_status_t wt_vnet_relay_rx_fetch(wt_ffm_runtime_t* runtime,
                                           int32_t partition_id,
                                           vnet_switch_t* sw, uint32_t vm,
                                           const psa_msg_t* msg)
{
    size_t dst_cap;
    int rc;
    int n;

    if (msg->out_size[0] < sizeof(g_vnet_meta_scratch) ||
            msg->out_size[1] == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    rc = vnet_switch_poll_rx(sw, vm, &g_vnet_meta_scratch);
    if (rc != WT_VNET_OK) {
        return (psa_status_t)rc;
    }
    dst_cap = msg->out_size[1];
    if (dst_cap > sizeof(g_vnet_rx_scratch)) {
        dst_cap = sizeof(g_vnet_rx_scratch);
    }
    n = vnet_switch_read_rx(sw, vm, g_vnet_meta_scratch.token_slot,
                            g_vnet_meta_scratch.token_gen,
                            g_vnet_rx_scratch, (uint16_t)dst_cap);
    if (n < 0) {
        if (n == WT_VNET_E_BADARG) {
            /* Head frame does not fit the caller's buffer: drop and release
             * it so an undeliverable frame cannot wedge the queue or pin its
             * shared pool slot until an expiry sweep that has no caller. */
            (void)vnet_switch_release_rx(sw, vm,
                                         g_vnet_meta_scratch.token_slot,
                                         g_vnet_meta_scratch.token_gen);
        }
        return (psa_status_t)n;
    }
    rc = vnet_switch_release_rx(sw, vm, g_vnet_meta_scratch.token_slot,
                                g_vnet_meta_scratch.token_gen);
    if (rc != WT_VNET_OK) {
        return (psa_status_t)rc;
    }
    g_vnet_meta_scratch.len = (uint16_t)n;
    if (wt_vnet_relay_write_vec(runtime, partition_id, msg->handle, 0U,
                                &g_vnet_meta_scratch,
                                sizeof(g_vnet_meta_scratch)) !=
            WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (n > 0 &&
            wt_vnet_relay_write_vec(runtime, partition_id, msg->handle, 1U,
                                    g_vnet_rx_scratch,
                                    (size_t)n) != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_vnet_relay_op(wt_ffm_runtime_t* runtime,
                                     int32_t partition_id,
                                     const psa_msg_t* msg)
{
    vnet_switch_t* sw = g_vnet_sw;
    uint32_t vm = 0U;
    int rc;

    if (sw == NULL) {
        /* Fail closed: no switch installed, no path to any port. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    rc = wt_vnet_relay_caller_vm(sw, msg->client_id, &vm);
    if (rc != WT_VNET_OK) {
        return (psa_status_t)rc;
    }
    switch (msg->type) {
        case WT_VNET_OP_OPEN:
            return wt_vnet_relay_open(runtime, partition_id, sw, vm, msg);
        case WT_VNET_OP_SET_MAC:
            return wt_vnet_relay_set_mac(runtime, partition_id, sw, vm, msg);
        case WT_VNET_OP_TX:
            return wt_vnet_relay_tx(runtime, partition_id, sw, vm, msg);
        case WT_VNET_OP_RX_FETCH:
            return wt_vnet_relay_rx_fetch(runtime, partition_id, sw, vm, msg);
        case WT_VNET_OP_IRQ_ACK:
            rc = vnet_switch_irq_ack(sw, vm);
            return (rc != WT_VNET_OK) ? (psa_status_t)rc : PSA_SUCCESS;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

int wt_vnet_relay_dispatch(void* context, wt_ffm_runtime_t* runtime,
                           int32_t partition_id)
{
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    psa_status_t reply_status;
    wt_spm_call_t call;

    (void)context;
    if (wt_spm_wait_service_signal(g_vnet_transport, runtime, partition_id,
                                   &asserted, &g_vnet_now_tick) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (asserted == 0U) {
        return WT_FFM_SUCCESS;
    }

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = partition_id;
    call.signal = asserted;
    call.msg = &msg;
    if (g_vnet_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_status != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }

    if (msg.type == PSA_IPC_CONNECT || msg.type == PSA_IPC_DISCONNECT) {
        reply_status = PSA_SUCCESS;
    } else {
        reply_status = wt_vnet_relay_op(runtime, partition_id, &msg);
    }
    g_wt_vnet_dispatch_count++;
    g_wt_vnet_last_reply = ((uint32_t)msg.type << 24) |
        ((uint32_t)reply_status & 0x00FFFFFFUL);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = msg.handle;
    call.status = reply_status;
    if (g_vnet_transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
