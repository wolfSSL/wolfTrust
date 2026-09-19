/* ffm.h
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

#ifndef WOLFTRUST_FFM_H
#define WOLFTRUST_FFM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "psa/service.h"
#include "wolftrust/ipc.h"
#include "wolftrust/manifest.h"

#define WT_FFM_MAX_PARTITIONS     9U
#define WT_FFM_MAX_SERVICES       20U
#define WT_FFM_MAX_CONNECTIONS    16U
/* Per-client connection quota: no single client may hold more than half the
 * shared pool, so one guest cannot exhaust it and starve peers (CWE-400). */
#define WT_FFM_MAX_CONNECTIONS_PER_CLIENT (WT_FFM_MAX_CONNECTIONS / 2U)
#define WT_FFM_MAX_MESSAGES       16U
#define WT_FFM_TRANSFER_BYTES     1024U
#define WT_FFM_QUEUE_NONE         UINT16_MAX

typedef struct wt_ffm_runtime wt_ffm_runtime_t;

typedef int (*wt_ffm_dispatch_fn)(void* context, wt_ffm_runtime_t* runtime,
                                  int32_t partition_id);

typedef struct wt_ffm_port_ops {
    int (*check_read)(void* context, psa_client_id_t caller,
                      const void* address, size_t size);
    int (*check_write)(void* context, psa_client_id_t caller,
                       void* address, size_t size);
    int (*dispatch)(void* context, wt_ffm_runtime_t* runtime,
                    int32_t partition_id);
    void (*panic)(void* context, int32_t partition_id);
} wt_ffm_port_ops_t;

typedef struct wt_ffm_partition_runtime {
    const wt_partition_manifest_t* manifest;
    wt_ffm_dispatch_fn dispatch;
    void* dispatch_context;
    psa_signal_t asserted_signals;
    uint8_t initialized;
} wt_ffm_partition_runtime_t;

typedef struct wt_ffm_service_runtime {
    const wt_service_descriptor_t* descriptor;
    uint16_t partition_index;
    uint16_t queue_head;
    uint16_t queue_tail;
} wt_ffm_service_runtime_t;

typedef struct wt_ffm_connection_runtime {
    wt_ipc_connection_state_t state;
    psa_client_id_t caller;
    uint32_t generation;
    uintptr_t rhandle;
    uint16_t service_index;
    uint8_t allocated;
    uint8_t error_latch;   /* client programmer error: connection stays in
                            * the error state once in-flight work completes,
                            * until the client closes the handle (FF-M A) */
} wt_ffm_connection_runtime_t;

typedef struct wt_ffm_message_runtime {
    psa_client_id_t caller;
    psa_status_t reply_status;
    uint32_t generation;
    uint16_t connection_index;
    uint16_t service_index;
    uint16_t next;
    int32_t type;
    size_t in_count;
    size_t out_count;
    size_t in_size[PSA_MAX_IOVEC];
    size_t out_size[PSA_MAX_IOVEC];
    size_t in_offset[PSA_MAX_IOVEC];
    size_t out_offset[PSA_MAX_IOVEC];
    size_t in_position[PSA_MAX_IOVEC];
    size_t out_position[PSA_MAX_IOVEC];
    void* client_output[PSA_MAX_IOVEC];
    uint8_t input[WT_FFM_TRANSFER_BYTES];
    uint8_t output[WT_FFM_TRANSFER_BYTES];
    uint8_t allocated;
    uint8_t active;
    uint8_t complete;
    uint8_t abandoned; /* Client returned; retain ownership until service reply. */
} wt_ffm_message_runtime_t;

struct wt_ffm_runtime {
    const wt_system_manifest_t* manifest;
    const wt_ffm_port_ops_t* ops;
    void* port_context;
    wt_ffm_partition_runtime_t partitions[WT_FFM_MAX_PARTITIONS];
    wt_ffm_service_runtime_t services[WT_FFM_MAX_SERVICES];
    wt_ffm_connection_runtime_t connections[WT_FFM_MAX_CONNECTIONS];
    wt_ffm_message_runtime_t messages[WT_FFM_MAX_MESSAGES];
    size_t partition_count;
    size_t service_count;
    uint32_t lifecycle;
};

typedef enum wt_ffm_result {
    WT_FFM_SUCCESS = 0,
    WT_FFM_ERROR_ARGUMENT = -600,
    WT_FFM_ERROR_MANIFEST = -601,
    WT_FFM_ERROR_POLICY = -602,
    WT_FFM_ERROR_RESOURCE = -603,
    WT_FFM_ERROR_HANDLE = -604,
    WT_FFM_ERROR_STATE = -605,
    WT_FFM_ERROR_NOT_READY = -606,
    WT_FFM_ERROR_BUFFER = -607
} wt_ffm_result_t;

int wt_ffm_init(wt_ffm_runtime_t* runtime,
                const wt_system_manifest_t* manifest,
                const wt_ffm_port_ops_t* ops, void* port_context);
int wt_ffm_register_partition(wt_ffm_runtime_t* runtime, int32_t partition_id,
                              wt_ffm_dispatch_fn dispatch, void* context);
uint32_t wt_ffm_framework_version(const wt_ffm_runtime_t* runtime);
void wt_ffm_set_lifecycle(wt_ffm_runtime_t* runtime, uint32_t lifecycle);
uint32_t wt_ffm_service_version(const wt_ffm_runtime_t* runtime,
                                psa_client_id_t caller, uint32_t sid);
psa_handle_t wt_ffm_connect(wt_ffm_runtime_t* runtime,
                            psa_client_id_t caller, uint32_t sid,
                            uint32_t version);
psa_status_t wt_ffm_call(wt_ffm_runtime_t* runtime,
                         psa_client_id_t caller, psa_handle_t handle,
                         int32_t type, const psa_invec* in_vec,
                         size_t in_len, psa_outvec* out_vec,
                         size_t out_len);
/* Drops the caller's valid connection to the error state after a call the
 * gateway had to refuse before dispatch (bad descriptor or vector count);
 * an unknown handle is left alone. */
void wt_ffm_call_refuse(wt_ffm_runtime_t* runtime, psa_client_id_t caller,
                        psa_handle_t handle);
int wt_ffm_close(wt_ffm_runtime_t* runtime, psa_client_id_t caller,
                 psa_handle_t handle);

/* Deferred client IPC for Secure-Partition callers (WT-FFM-0014). A partition
 * cannot be dispatched from another partition's SVC context, so an SP-side
 * connect/call/close splits into begin (validate + enqueue, no dispatch) and
 * finish (harvest after the scheduler ran the target and the message
 * completed). begin returns the same immediate refusals as the synchronous
 * forms; on success *msg_index tracks the pending message. */
psa_handle_t wt_ffm_connect_begin(wt_ffm_runtime_t* runtime,
                                  psa_client_id_t caller, uint32_t sid,
                                  uint32_t version, uint16_t* msg_index);
psa_status_t wt_ffm_call_begin(wt_ffm_runtime_t* runtime,
                               psa_client_id_t caller, psa_handle_t handle,
                               int32_t type, const psa_invec* in_vec,
                               size_t in_len, psa_outvec* out_vec,
                               size_t out_len, uint16_t* msg_index);
int wt_ffm_close_begin(wt_ffm_runtime_t* runtime, psa_client_id_t caller,
                       psa_handle_t handle, uint16_t* msg_index);
int wt_ffm_msg_complete(const wt_ffm_runtime_t* runtime, uint16_t msg_index);
int wt_ffm_fail_partition_messages(wt_ffm_runtime_t* runtime,
                                   int32_t partition_id, psa_status_t status);
/* Releases every connection (and any request still in flight) owned by a
 * client that terminated abnormally and can no longer close its handles. */
int wt_ffm_fail_client_connections(wt_ffm_runtime_t* runtime,
                                   psa_client_id_t caller);

/* Dispatch one queued-but-undelivered message inline. The scheduler wake
 * loop does this on target; the direct transport uses it as the host
 * stand-in so SP-as-client begin/finish pairs complete synchronously. */
int wt_ffm_dispatch_pending(wt_ffm_runtime_t* runtime, uint16_t msg_index);
psa_handle_t wt_ffm_connect_finish(wt_ffm_runtime_t* runtime,
                                   uint16_t msg_index);
psa_status_t wt_ffm_call_finish(wt_ffm_runtime_t* runtime, uint16_t msg_index,
                                psa_outvec* out_vec, size_t out_len);
int wt_ffm_close_finish(wt_ffm_runtime_t* runtime, uint16_t msg_index);

int wt_ffm_wait(wt_ffm_runtime_t* runtime, int32_t partition_id,
                psa_signal_t signal_mask, psa_signal_t* asserted);
int wt_ffm_notify(wt_ffm_runtime_t* runtime, int32_t partition_id);
int wt_ffm_clear(wt_ffm_runtime_t* runtime, int32_t partition_id);
int wt_ffm_eoi(wt_ffm_runtime_t* runtime, int32_t partition_id,
               psa_signal_t irq_signal);
int wt_ffm_irq_lookup(wt_ffm_runtime_t* runtime, int32_t partition_id,
                      psa_signal_t irq_signal, uint32_t* irq_out);
int wt_ffm_irq_route(wt_ffm_runtime_t* runtime, uint32_t irq,
                     int32_t* partition_id_out, psa_signal_t* signal_out);
int wt_ffm_assert_signal(wt_ffm_runtime_t* runtime, int32_t partition_id,
                         psa_signal_t irq_signal);
psa_status_t wt_ffm_get(wt_ffm_runtime_t* runtime, int32_t partition_id,
                        psa_signal_t signal, psa_msg_t* msg);
int wt_ffm_set_rhandle(wt_ffm_runtime_t* runtime, int32_t partition_id,
                       psa_handle_t msg_handle, void* rhandle);
size_t wt_ffm_read(wt_ffm_runtime_t* runtime, int32_t partition_id,
                   psa_handle_t msg_handle, uint32_t invec_idx,
                   void* buffer, size_t num_bytes);
size_t wt_ffm_skip(wt_ffm_runtime_t* runtime, int32_t partition_id,
                   psa_handle_t msg_handle, uint32_t invec_idx,
                   size_t num_bytes);
int wt_ffm_write(wt_ffm_runtime_t* runtime, int32_t partition_id,
                 psa_handle_t msg_handle, uint32_t outvec_idx,
                 const void* buffer, size_t num_bytes);
int wt_ffm_msg_access_check(wt_ffm_runtime_t* runtime, int32_t partition_id,
                            psa_handle_t msg_handle, uint32_t vec_idx);
int wt_ffm_reply(wt_ffm_runtime_t* runtime, int32_t partition_id,
                 psa_handle_t msg_handle, psa_status_t status);

#endif /* WOLFTRUST_FFM_H */
