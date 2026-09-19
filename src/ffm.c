/* ffm.c
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

#include "wolftrust/ffm.h"

#include <string.h>

#define WT_FFM_HANDLE_INDEX_MASK 0x1FU
#define WT_FFM_HANDLE_TYPE_SHIFT 5U
#define WT_FFM_HANDLE_TYPE_MASK  0x3U
#define WT_FFM_HANDLE_GEN_SHIFT  7U
#define WT_FFM_HANDLE_GEN_MASK   0x00FFFFFFU
#define WT_FFM_HANDLE_CONNECTION 1U
#define WT_FFM_HANDLE_MESSAGE    2U
#define WT_FFM_ABANDONED_REPLY   1U
#define WT_FFM_ABANDONED_CLOSE   2U

static uint32_t wt_ffm_next_generation(uint32_t generation)
{
    generation = (generation + 1U) & WT_FFM_HANDLE_GEN_MASK;
    return generation == 0U ? 1U : generation;
}

static psa_handle_t wt_ffm_make_handle(uint32_t type, uint16_t index,
                                       uint32_t generation)
{
    uint32_t value;

    value = ((generation & WT_FFM_HANDLE_GEN_MASK) <<
             WT_FFM_HANDLE_GEN_SHIFT) |
            ((type & WT_FFM_HANDLE_TYPE_MASK) <<
             WT_FFM_HANDLE_TYPE_SHIFT) |
            ((uint32_t)index + 1U);
    return (psa_handle_t)value;
}

static int wt_ffm_decode_handle(psa_handle_t handle, uint32_t type,
                                size_t limit, uint16_t* index,
                                uint32_t* generation)
{
    uint32_t value;
    uint32_t encoded_type;
    uint32_t encoded_index;

    if (handle <= 0 || index == NULL || generation == NULL)
        return WT_FFM_ERROR_HANDLE;

    value = (uint32_t)handle;
    encoded_type = (value >> WT_FFM_HANDLE_TYPE_SHIFT) &
                   WT_FFM_HANDLE_TYPE_MASK;
    encoded_index = value & WT_FFM_HANDLE_INDEX_MASK;
    if (encoded_type != type || encoded_index == 0U ||
            encoded_index > limit) {
        return WT_FFM_ERROR_HANDLE;
    }

    *index = (uint16_t)(encoded_index - 1U);
    *generation = value >> WT_FFM_HANDLE_GEN_SHIFT;
    if (*generation == 0U)
        return WT_FFM_ERROR_HANDLE;

    return WT_FFM_SUCCESS;
}

static int wt_ffm_find_partition(const wt_ffm_runtime_t* runtime,
                                 int32_t partition_id,
                                 uint16_t* partition_index)
{
    size_t i;

    if (runtime == NULL || partition_index == NULL || partition_id <= 0)
        return WT_FFM_ERROR_ARGUMENT;

    for (i = 0U; i < runtime->partition_count; i++) {
        if (runtime->partitions[i].manifest->domain_id ==
                (wt_domain_id_t)partition_id) {
            *partition_index = (uint16_t)i;
            return WT_FFM_SUCCESS;
        }
    }

    return WT_FFM_ERROR_POLICY;
}

static int wt_ffm_find_service(const wt_ffm_runtime_t* runtime, uint32_t sid,
                               uint16_t* service_index)
{
    size_t i;

    if (runtime == NULL || service_index == NULL || sid == 0U)
        return WT_FFM_ERROR_ARGUMENT;

    for (i = 0U; i < runtime->service_count; i++) {
        if (runtime->services[i].descriptor->sid == sid) {
            *service_index = (uint16_t)i;
            return WT_FFM_SUCCESS;
        }
    }

    return WT_FFM_ERROR_POLICY;
}

static int wt_ffm_caller_allowed(const wt_ffm_runtime_t* runtime,
                                 psa_client_id_t caller,
                                 uint16_t service_index)
{
    const wt_ffm_service_runtime_t* service;
    const wt_partition_manifest_t* partition;
    size_t i;
    size_t j;

    if (caller == 0 || service_index >= runtime->service_count)
        return 0;

    service = &runtime->services[service_index];
    if (caller < 0)
        return service->descriptor->nonsecure_clients != 0U;

    for (i = 0U; i < runtime->partition_count; i++) {
        partition = runtime->partitions[i].manifest;
        if (partition->domain_id != (wt_domain_id_t)caller)
            continue;
        if (i == service->partition_index)
            return 0;
        for (j = 0U; j < partition->dependency_count; j++) {
            if (partition->dependencies[j] == service->descriptor->sid)
                return 1;
        }
        return 0;
    }

    return 0;
}

static int wt_ffm_version_allowed(const wt_service_descriptor_t* service,
                                  uint32_t requested)
{
    if (requested == 0U)
        return 0;
    if (service->version_policy == WT_SERVICE_VERSION_UNSPECIFIED)
        return 1;
    if (service->version_policy == WT_SERVICE_VERSION_STRICT)
        return requested == service->version;
    return requested <= service->version;
}

static int wt_ffm_alloc_connection(wt_ffm_runtime_t* runtime,
                                   uint16_t* connection_index)
{
    size_t i;

    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        if (runtime->connections[i].allocated == 0U) {
            runtime->connections[i].allocated = 1U;
            runtime->connections[i].state = WT_IPC_CONNECTION_FREE;
            runtime->connections[i].error_latch = 0U;
            *connection_index = (uint16_t)i;
            return WT_FFM_SUCCESS;
        }
    }

    return WT_FFM_ERROR_RESOURCE;
}

static void wt_ffm_release_connection(wt_ffm_runtime_t* runtime,
                                      uint16_t connection_index)
{
    wt_ffm_connection_runtime_t* connection;
    uint32_t generation;

    connection = &runtime->connections[connection_index];
    generation = wt_ffm_next_generation(connection->generation);
    (void)memset(connection, 0, sizeof(*connection));
    connection->generation = generation;
    connection->state = WT_IPC_CONNECTION_FREE;
}

static int wt_ffm_connection_from_handle(wt_ffm_runtime_t* runtime,
                                         psa_client_id_t caller,
                                         psa_handle_t handle,
                                         uint16_t* connection_index)
{
    wt_ffm_connection_runtime_t* connection;
    uint32_t generation;
    uint16_t index;
    int ret;

    ret = wt_ffm_decode_handle(handle, WT_FFM_HANDLE_CONNECTION,
                               WT_FFM_MAX_CONNECTIONS, &index, &generation);
    if (ret != WT_FFM_SUCCESS)
        return ret;

    connection = &runtime->connections[index];
    if (connection->allocated == 0U ||
            connection->generation != generation)
        return WT_FFM_ERROR_HANDLE;
    if (connection->caller != caller)
        return WT_FFM_ERROR_POLICY;

    *connection_index = index;
    return WT_FFM_SUCCESS;
}

static int wt_ffm_alloc_message(wt_ffm_runtime_t* runtime,
                                uint16_t* message_index)
{
    size_t i;

    for (i = 0U; i < WT_FFM_MAX_MESSAGES; i++) {
        if (runtime->messages[i].allocated == 0U) {
            runtime->messages[i].allocated = 1U;
            runtime->messages[i].next = WT_FFM_QUEUE_NONE;
            *message_index = (uint16_t)i;
            return WT_FFM_SUCCESS;
        }
    }

    return WT_FFM_ERROR_RESOURCE;
}

static void wt_ffm_release_message(wt_ffm_runtime_t* runtime,
                                   uint16_t message_index)
{
    wt_ffm_message_runtime_t* message;
    uint32_t generation;

    message = &runtime->messages[message_index];
    generation = wt_ffm_next_generation(message->generation);
    (void)memset(message, 0, sizeof(*message));
    message->generation = generation;
    message->next = WT_FFM_QUEUE_NONE;
}

static int wt_ffm_message_from_handle(wt_ffm_runtime_t* runtime,
                                      int32_t partition_id,
                                      psa_handle_t handle,
                                      uint16_t* message_index)
{
    wt_ffm_message_runtime_t* message;
    wt_ffm_service_runtime_t* service;
    uint32_t generation;
    uint16_t index;
    int ret;

    ret = wt_ffm_decode_handle(handle, WT_FFM_HANDLE_MESSAGE,
                               WT_FFM_MAX_MESSAGES, &index, &generation);
    if (ret != WT_FFM_SUCCESS)
        return ret;

    message = &runtime->messages[index];
    if (message->allocated == 0U || message->active == 0U ||
            message->generation != generation)
        return WT_FFM_ERROR_HANDLE;

    service = &runtime->services[message->service_index];
    if (runtime->partitions[service->partition_index].manifest->domain_id !=
            (wt_domain_id_t)partition_id) {
        return WT_FFM_ERROR_POLICY;
    }

    *message_index = index;
    return WT_FFM_SUCCESS;
}

static int wt_ffm_close_abandoned(wt_ffm_runtime_t* runtime,
                                   uint16_t connection_index)
{
    size_t i;

    for (i = 0U; i < WT_FFM_MAX_MESSAGES; i++) {
        wt_ffm_message_runtime_t* message = &runtime->messages[i];

        if (message->allocated != 0U && message->abandoned != 0U &&
                message->connection_index == connection_index) {
            message->abandoned = WT_FFM_ABANDONED_CLOSE;
            runtime->connections[connection_index].state =
                WT_IPC_CONNECTION_DISCONNECTING;
            return 1;
        }
    }
    return 0;
}

static void wt_ffm_update_service_signal(wt_ffm_runtime_t* runtime,
                                         uint16_t service_index)
{
    wt_ffm_service_runtime_t* service;
    wt_ffm_partition_runtime_t* partition;
    uint32_t signal;

    service = &runtime->services[service_index];
    partition = &runtime->partitions[service->partition_index];
    signal = service->descriptor->signal;
    if (service->queue_head == WT_FFM_QUEUE_NONE)
        partition->asserted_signals &= ~signal;
    else
        partition->asserted_signals |= signal;
}

static void wt_ffm_enqueue(wt_ffm_runtime_t* runtime, uint16_t service_index,
                           uint16_t message_index)
{
    wt_ffm_service_runtime_t* service;

    service = &runtime->services[service_index];
    if (service->queue_tail == WT_FFM_QUEUE_NONE)
        service->queue_head = message_index;
    else
        runtime->messages[service->queue_tail].next = message_index;
    service->queue_tail = message_index;
    wt_ffm_update_service_signal(runtime, service_index);
}

/* Unlink an undelivered message from its service queue so its slot can be
 * released: a released-but-still-queued slot would alias the next request
 * that reuses it (a dispatch refusal must not corrupt the queue). */
static void wt_ffm_dequeue_message(wt_ffm_runtime_t* runtime,
                                   uint16_t service_index,
                                   uint16_t message_index)
{
    wt_ffm_service_runtime_t* service = &runtime->services[service_index];
    uint16_t current = service->queue_head;
    uint16_t previous = WT_FFM_QUEUE_NONE;

    while (current != WT_FFM_QUEUE_NONE) {
        if (current == message_index) {
            if (previous == WT_FFM_QUEUE_NONE)
                service->queue_head = runtime->messages[current].next;
            else
                runtime->messages[previous].next =
                    runtime->messages[current].next;
            if (service->queue_tail == current)
                service->queue_tail = previous;
            runtime->messages[current].next = WT_FFM_QUEUE_NONE;
            break;
        }
        previous = current;
        current = runtime->messages[current].next;
    }
    wt_ffm_update_service_signal(runtime, service_index);
}

/* SWD-readable record of the last refused client vector: (kind<<28) |
 * (index<<24) | (caller low byte<<16) | length low 16; kind 1=in policy,
 * 2=out policy, 3=transfer cap. Forensics for silicon-only refusals. */
volatile uint32_t g_wt_ffm_refuse_info;
volatile uint32_t g_wt_ffm_refuse_base;

/* Companion trace: last psa_call shape seen ((type<<16)|(in<<8)|out) with a
 * refusal-site nibble in bits 31..28 (1/2 veneer, 4 counts, 5 handle,
 * 6 state, 7 alloc). */
volatile uint32_t g_wt_ffm_call_trace;

static int wt_ffm_prepare_vectors(wt_ffm_runtime_t* runtime,
                                  wt_ffm_message_runtime_t* message,
                                  const psa_invec* in_vec, size_t in_len,
                                  psa_outvec* out_vec, size_t out_len)
{
    wt_ipc_vector_t inputs[PSA_MAX_IOVEC];
    wt_ipc_vector_t outputs[PSA_MAX_IOVEC];
    size_t input_offset = 0U;
    size_t output_offset = 0U;
    size_t total = 0U;
    size_t i;
    int ret;

    if ((in_len != 0U && in_vec == NULL) ||
            (out_len != 0U && out_vec == NULL))
        return WT_FFM_ERROR_ARGUMENT;

    for (i = 0U; i < in_len && i < PSA_MAX_IOVEC; i++) {
        inputs[i].base = (uintptr_t)in_vec[i].base;
        inputs[i].length = in_vec[i].len;
    }
    for (i = 0U; i < out_len && i < PSA_MAX_IOVEC; i++) {
        outputs[i].base = (uintptr_t)out_vec[i].base;
        outputs[i].length = out_vec[i].len;
    }
    /* FF-M: a vector whose range escapes the caller's memory is a PROGRAMMER
     * ERROR, judged before the implementation transfer cap so an out-of-bounds
     * end address never downgrades into a size error. */
    for (i = 0U; i < in_len && i < PSA_MAX_IOVEC; i++) {
        if (in_vec[i].len != 0U &&
                runtime->ops->check_read(runtime->port_context,
                    message->caller, in_vec[i].base, in_vec[i].len) == 0) {
            g_wt_ffm_refuse_info = (1UL << 28) | ((uint32_t)i << 24) |
                (((uint32_t)message->caller & 0xFFU) << 16) |
                ((uint32_t)in_vec[i].len & 0xFFFFU);
            g_wt_ffm_refuse_base = (uint32_t)(uintptr_t)in_vec[i].base;
            return WT_FFM_ERROR_POLICY;
        }
    }
    for (i = 0U; i < out_len && i < PSA_MAX_IOVEC; i++) {
        if (out_vec[i].len != 0U &&
                runtime->ops->check_write(runtime->port_context,
                    message->caller, out_vec[i].base, out_vec[i].len) == 0) {
            g_wt_ffm_refuse_info = (2UL << 28) | ((uint32_t)i << 24) |
                (((uint32_t)message->caller & 0xFFU) << 16) |
                ((uint32_t)out_vec[i].len & 0xFFFFU);
            g_wt_ffm_refuse_base = (uint32_t)(uintptr_t)out_vec[i].base;
            return WT_FFM_ERROR_POLICY;
        }
    }

    ret = wt_ipc_validate_vectors(inputs, in_len, outputs, out_len,
                                  WT_FFM_TRANSFER_BYTES, &total);
    if (ret != WT_IPC_VALID) {
        g_wt_ffm_refuse_info = (3UL << 28) | ((uint32_t)total & 0xFFFFU);
        g_wt_ffm_refuse_base = 0U;
        return WT_FFM_ERROR_BUFFER;
    }

    message->in_count = in_len;
    message->out_count = out_len;
    for (i = 0U; i < in_len; i++) {
        message->in_offset[i] = input_offset;
        message->in_size[i] = in_vec[i].len;
        if (in_vec[i].len != 0U)
            (void)memcpy(&message->input[input_offset], in_vec[i].base,
                         in_vec[i].len);
        input_offset += in_vec[i].len;
    }
    for (i = 0U; i < out_len; i++) {
        message->out_offset[i] = output_offset;
        message->out_size[i] = out_vec[i].len;
        message->client_output[i] = out_vec[i].base;
        output_offset += out_vec[i].len;
    }

    return WT_FFM_SUCCESS;
}

static int wt_ffm_dispatch_message(wt_ffm_runtime_t* runtime,
                                   uint16_t message_index)
{
    wt_ffm_message_runtime_t* message = &runtime->messages[message_index];
    wt_ffm_service_runtime_t* service;
    int32_t partition_id;
    int ret;

    wt_ffm_partition_runtime_t* partition;

    service = &runtime->services[message->service_index];
    partition = &runtime->partitions[service->partition_index];
    partition_id = (int32_t)partition->manifest->domain_id;
    if (partition->dispatch != NULL) {
        ret = partition->dispatch(partition->dispatch_context, runtime,
                                  partition_id);
    }
    else {
        ret = runtime->ops->dispatch(runtime->port_context, runtime,
                                     partition_id);
    }
    if (ret != WT_FFM_SUCCESS)
        return ret;
    if (message->complete == 0U)
        return WT_FFM_ERROR_NOT_READY;
    return WT_FFM_SUCCESS;
}

int wt_ffm_init(wt_ffm_runtime_t* runtime,
                const wt_system_manifest_t* manifest,
                const wt_ffm_port_ops_t* ops, void* port_context)
{
    size_t service_count = 0U;
    size_t i;
    size_t j;

    if (runtime == NULL || manifest == NULL || ops == NULL ||
            ops->check_read == NULL || ops->check_write == NULL ||
            ops->dispatch == NULL || ops->panic == NULL) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    if (manifest->partition_count > WT_FFM_MAX_PARTITIONS)
        return WT_FFM_ERROR_MANIFEST;
    for (i = 0U; i < manifest->partition_count; i++) {
        if (manifest->partitions[i].model != WT_PARTITION_MODEL_IPC)
            return WT_FFM_ERROR_MANIFEST;
        /* A partition declaring a framework newer than the compiled public
         * contract must fail activation: the build cannot honor its ABI. */
        if (manifest->partitions[i].framework_version >
                (uint32_t)PSA_FRAMEWORK_VERSION) {
            return WT_FFM_ERROR_MANIFEST;
        }
        if (manifest->partitions[i].service_count >
                WT_FFM_MAX_SERVICES - service_count) {
            return WT_FFM_ERROR_MANIFEST;
        }
        service_count += manifest->partitions[i].service_count;
    }

    (void)memset(runtime, 0, sizeof(*runtime));
    runtime->manifest = manifest;
    runtime->ops = ops;
    runtime->port_context = port_context;
    runtime->partition_count = manifest->partition_count;
    runtime->service_count = service_count;
    service_count = 0U;
    for (i = 0U; i < manifest->partition_count; i++) {
        runtime->partitions[i].manifest = &manifest->partitions[i];
        for (j = 0U; j < manifest->partitions[i].service_count; j++) {
            runtime->services[service_count].descriptor =
                &manifest->partitions[i].services[j];
            runtime->services[service_count].partition_index = (uint16_t)i;
            runtime->services[service_count].queue_head = WT_FFM_QUEUE_NONE;
            runtime->services[service_count].queue_tail = WT_FFM_QUEUE_NONE;
            service_count++;
        }
    }
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++)
        runtime->connections[i].generation = 1U;
    for (i = 0U; i < WT_FFM_MAX_MESSAGES; i++) {
        runtime->messages[i].generation = 1U;
        runtime->messages[i].next = WT_FFM_QUEUE_NONE;
    }

    return WT_FFM_SUCCESS;
}

int wt_ffm_register_partition(wt_ffm_runtime_t* runtime, int32_t partition_id,
                              wt_ffm_dispatch_fn dispatch, void* context)
{
    uint16_t partition_index;
    int ret;

    if (runtime == NULL || dispatch == NULL)
        return WT_FFM_ERROR_ARGUMENT;

    ret = wt_ffm_find_partition(runtime, partition_id, &partition_index);
    if (ret != WT_FFM_SUCCESS)
        return ret;

    runtime->partitions[partition_index].dispatch = dispatch;
    runtime->partitions[partition_index].dispatch_context = context;
    return WT_FFM_SUCCESS;
}

uint32_t wt_ffm_framework_version(const wt_ffm_runtime_t* runtime)
{
    const wt_system_manifest_t* manifest;
    uint32_t version;
    size_t i;

    if (runtime == NULL || runtime->manifest == NULL)
        return 0U;
    /* Report the version the loaded manifest actually enforces, never a
     * fixed constant, so discovery cannot advertise an unenforced 1.1
     * capability. A 1.1-only feature or partition raises the report to 1.1. */
    manifest = runtime->manifest;
    version = WT_FFM_VERSION_1_0;
    if ((manifest->features & (WT_MANIFEST_FEATURE_SFN |
            WT_MANIFEST_FEATURE_STATELESS |
            WT_MANIFEST_FEATURE_MM_IOVEC)) != 0U) {
        version = WT_FFM_VERSION_1_1;
    }
    for (i = 0U; i < manifest->partition_count; i++) {
        if (manifest->partitions[i].framework_version ==
                WT_FFM_VERSION_1_1) {
            version = WT_FFM_VERSION_1_1;
            break;
        }
    }
    /* The compiled public contract (PSA_FRAMEWORK_VERSION in psa/client.h)
     * is the ceiling: one build must never advertise 1.1 to Non-secure
     * clients while its headers and Secure Partitions report 1.0. */
    if (version > PSA_FRAMEWORK_VERSION)
        version = PSA_FRAMEWORK_VERSION;
    return version;
}

void wt_ffm_set_lifecycle(wt_ffm_runtime_t* runtime, uint32_t lifecycle)
{
    if (runtime != NULL)
        runtime->lifecycle = lifecycle;
}

uint32_t wt_ffm_service_version(const wt_ffm_runtime_t* runtime,
                                psa_client_id_t caller, uint32_t sid)
{
    uint16_t service_index;

    if (wt_ffm_find_service(runtime, sid, &service_index) != WT_FFM_SUCCESS ||
            !wt_ffm_caller_allowed(runtime, caller, service_index)) {
        return PSA_VERSION_NONE;
    }
    return runtime->services[service_index].descriptor->version;
}

static size_t wt_ffm_client_connection_count(const wt_ffm_runtime_t* runtime,
                                             psa_client_id_t caller)
{
    size_t count = 0U;
    size_t i;

    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        if (runtime->connections[i].allocated != 0U &&
                runtime->connections[i].caller == caller) {
            count++;
        }
    }
    return count;
}

psa_handle_t wt_ffm_connect(wt_ffm_runtime_t* runtime,
                            psa_client_id_t caller, uint32_t sid,
                            uint32_t version)
{
    wt_ffm_connection_runtime_t* connection;
    wt_ffm_message_runtime_t* message;
    uint16_t connection_index;
    uint16_t message_index;
    uint16_t service_index;
    psa_handle_t handle;
    psa_status_t status;
    int ret;

    if (runtime == NULL || caller == 0)
        return (psa_handle_t)PSA_ERROR_INVALID_ARGUMENT;
    ret = wt_ffm_find_service(runtime, sid, &service_index);
    if (ret != WT_FFM_SUCCESS ||
            !wt_ffm_caller_allowed(runtime, caller, service_index) ||
            !wt_ffm_version_allowed(
                runtime->services[service_index].descriptor, version)) {
        return (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED;
    }
    if (runtime->services[service_index].descriptor->connection_based == 0U)
        return (psa_handle_t)PSA_ERROR_NOT_SUPPORTED;

    /* Per-client quota: a single client cannot reserve the whole shared
     * connection pool and starve peers of every service (CWE-400). */
    if (wt_ffm_client_connection_count(runtime, caller) >=
            WT_FFM_MAX_CONNECTIONS_PER_CLIENT)
        return (psa_handle_t)PSA_ERROR_CONNECTION_BUSY;

    if (wt_ffm_alloc_connection(runtime, &connection_index) !=
            WT_FFM_SUCCESS)
        return (psa_handle_t)PSA_ERROR_CONNECTION_BUSY;
    if (wt_ffm_alloc_message(runtime, &message_index) != WT_FFM_SUCCESS) {
        wt_ffm_release_connection(runtime, connection_index);
        return (psa_handle_t)PSA_ERROR_CONNECTION_BUSY;
    }

    connection = &runtime->connections[connection_index];
    connection->caller = caller;
    connection->service_index = service_index;
    connection->state = WT_IPC_CONNECTION_PENDING_CONNECT;
    handle = wt_ffm_make_handle(WT_FFM_HANDLE_CONNECTION, connection_index,
                                connection->generation);

    message = &runtime->messages[message_index];
    message->caller = caller;
    message->connection_index = connection_index;
    message->service_index = service_index;
    message->type = PSA_IPC_CONNECT;
    wt_ffm_enqueue(runtime, service_index, message_index);
    ret = wt_ffm_dispatch_message(runtime, message_index);
    status = message->reply_status;
    if (ret != WT_FFM_SUCCESS && message->active != 0U) {
        message->abandoned = WT_FFM_ABANDONED_CLOSE;
        return ret == WT_FFM_ERROR_RESOURCE ?
            (psa_handle_t)PSA_ERROR_CONNECTION_BUSY :
            (psa_handle_t)PSA_ERROR_GENERIC_ERROR;
    }
    if (ret != WT_FFM_SUCCESS) {
        /* A refused CONNECT dispatch must unlink the message before its slot
         * is released, or the slot aliases the next queued request. */
        wt_ffm_dequeue_message(runtime, service_index, message_index);
    }
    wt_ffm_release_message(runtime, message_index);
    if (ret != WT_FFM_SUCCESS || status != PSA_SUCCESS) {
        wt_ffm_release_connection(runtime, connection_index);
        return ret == WT_FFM_ERROR_RESOURCE ?
            (psa_handle_t)PSA_ERROR_CONNECTION_BUSY :
            (psa_handle_t)(status == PSA_SUCCESS ?
                PSA_ERROR_GENERIC_ERROR : status);
    }

    return handle;
}

psa_status_t wt_ffm_call(wt_ffm_runtime_t* runtime,
                         psa_client_id_t caller, psa_handle_t handle,
                         int32_t type, const psa_invec* in_vec,
                         size_t in_len, psa_outvec* out_vec,
                         size_t out_len)
{
    wt_ffm_connection_runtime_t* connection;
    wt_ffm_message_runtime_t* message;
    uint16_t connection_index;
    uint16_t message_index;
    psa_status_t status;
    size_t i;
    int ret;

    if (runtime == NULL || caller == 0)
        return PSA_ERROR_INVALID_ARGUMENT;
    if ((g_wt_ffm_call_trace & 0xF0000000UL) == 0U) {
        g_wt_ffm_call_trace = ((uint32_t)type << 16) |
            (((uint32_t)in_len & 0xFFU) << 8) | ((uint32_t)out_len & 0xFFU);
    }
    ret = wt_ffm_connection_from_handle(runtime, caller, handle,
                                        &connection_index);
    if (ret != WT_FFM_SUCCESS) {
        g_wt_ffm_call_trace |= 5UL << 28;
        g_wt_ffm_refuse_base = (uint32_t)handle;
        /* FF-M: a forged, stale, or wrong-owner handle is invalid-handle use,
         * a PROGRAMMER ERROR the Secure gate must panic the caller for. */
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    connection = &runtime->connections[connection_index];
    /* FF-M: a negative call type and in_len + out_len > PSA_MAX_IOVEC are
     * both PROGRAMMER ERRORs, and the valid connection they arrived on must
     * drop to the error state rather than stay usable. */
    if (type < 0 || in_len > PSA_MAX_IOVEC || out_len > PSA_MAX_IOVEC ||
            in_len + out_len > PSA_MAX_IOVEC) {
        g_wt_ffm_call_trace |= 4UL << 28;
        if (connection->state == WT_IPC_CONNECTION_IDLE)
            connection->state = WT_IPC_CONNECTION_ERROR;
        else
            connection->error_latch = 1U;
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (connection->state != WT_IPC_CONNECTION_IDLE) {
        g_wt_ffm_call_trace |= 6UL << 28;
        /* FF-M: calling a connection that is already handling a request, or one
         * dropped by a prior PROGRAMMER ERROR, is itself a PROGRAMMER ERROR
         * until the client closes the handle; the latch keeps the connection
         * in the error state once the in-flight request completes. */
        connection->error_latch = 1U;
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (wt_ffm_alloc_message(runtime, &message_index) != WT_FFM_SUCCESS) {
        g_wt_ffm_call_trace |= 7UL << 28;
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    message = &runtime->messages[message_index];
    message->caller = caller;
    message->connection_index = connection_index;
    message->service_index = connection->service_index;
    message->type = type;
    ret = wt_ffm_prepare_vectors(runtime, message, in_vec, in_len,
                                 out_vec, out_len);
    if (ret != WT_FFM_SUCCESS) {
        wt_ffm_release_message(runtime, message_index);
        /* FF-M: a vector referencing memory the caller cannot access is a
         * PROGRAMMER ERROR, not a permission denial; the connection stays in
         * the error state until the client closes the handle. */
        if (ret != WT_FFM_ERROR_BUFFER)
            connection->state = WT_IPC_CONNECTION_ERROR;
        return ret == WT_FFM_ERROR_BUFFER ? PSA_ERROR_INVALID_ARGUMENT :
                                            PSA_ERROR_PROGRAMMER_ERROR;
    }

    connection->state = WT_IPC_CONNECTION_PENDING_REQUEST;
    wt_ffm_enqueue(runtime, connection->service_index, message_index);
    ret = wt_ffm_dispatch_message(runtime, message_index);
    if (ret != WT_FFM_SUCCESS) {
        connection->state = WT_IPC_CONNECTION_ERROR;
        if (message->active != 0U) {
            connection->error_latch = 1U;
            message->abandoned = WT_FFM_ABANDONED_REPLY;
            (void)memset(message->client_output, 0,
                         sizeof(message->client_output));
            return PSA_ERROR_GENERIC_ERROR;
        }
        wt_ffm_dequeue_message(runtime, connection->service_index,
                               message_index);
        wt_ffm_release_message(runtime, message_index);
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = message->reply_status;
    /* FF-M requires atomic output publication: revalidate every destination
     * before writing any, so a later revalidation failure cannot leave partial
     * data or a partial length in the client's buffers. */
    for (i = 0U; i < message->out_count; i++) {
        if (message->out_position[i] != 0U &&
                runtime->ops->check_write(runtime->port_context,
                    message->caller, message->client_output[i],
                    message->out_position[i]) == 0) {
            /* FF-M: an invalid caller output reference is a PROGRAMMER
             * ERROR, never a permission denial; the connection stays in the
             * error state until close, and nothing was written (two-phase). */
            connection->state = WT_IPC_CONNECTION_ERROR;
            wt_ffm_release_message(runtime, message_index);
            return PSA_ERROR_PROGRAMMER_ERROR;
        }
    }
    for (i = 0U; i < message->out_count; i++) {
        if (message->out_position[i] != 0U) {
            (void)memcpy(message->client_output[i],
                &message->output[message->out_offset[i]],
                message->out_position[i]);
        }
        out_vec[i].len = message->out_position[i];
    }
    wt_ffm_release_message(runtime, message_index);
    return status;
}

void wt_ffm_call_refuse(wt_ffm_runtime_t* runtime, psa_client_id_t caller,
                        psa_handle_t handle)
{
    wt_ffm_connection_runtime_t* connection;
    uint16_t connection_index;

    if (runtime == NULL || caller == 0)
        return;
    if (wt_ffm_connection_from_handle(runtime, caller, handle,
                                      &connection_index) != WT_FFM_SUCCESS)
        return;
    connection = &runtime->connections[connection_index];
    if (connection->state == WT_IPC_CONNECTION_IDLE)
        connection->state = WT_IPC_CONNECTION_ERROR;
    else
        connection->error_latch = 1U;
}

int wt_ffm_close(wt_ffm_runtime_t* runtime, psa_client_id_t caller,
                 psa_handle_t handle)
{
    wt_ffm_connection_runtime_t* connection;
    wt_ffm_message_runtime_t* message;
    uint16_t connection_index;
    uint16_t message_index;
    int ret;

    if (handle == PSA_NULL_HANDLE)
        return WT_FFM_SUCCESS;
    if (runtime == NULL || caller == 0)
        return WT_FFM_ERROR_ARGUMENT;
    ret = wt_ffm_connection_from_handle(runtime, caller, handle,
                                        &connection_index);
    if (ret != WT_FFM_SUCCESS)
        return ret;
    connection = &runtime->connections[connection_index];
    /* FF-M: a client may close a connection dropped by a PROGRAMMER ERROR
     * (WT_IPC_CONNECTION_ERROR), not only an idle one. */
    if (connection->state != WT_IPC_CONNECTION_IDLE &&
            connection->state != WT_IPC_CONNECTION_ERROR)
        return WT_FFM_ERROR_STATE;
    if (wt_ffm_close_abandoned(runtime, connection_index) != 0)
        return WT_FFM_SUCCESS;
    if (wt_ffm_alloc_message(runtime, &message_index) != WT_FFM_SUCCESS)
        return WT_FFM_ERROR_RESOURCE;

    connection->state = WT_IPC_CONNECTION_DISCONNECTING;
    message = &runtime->messages[message_index];
    message->caller = caller;
    message->connection_index = connection_index;
    message->service_index = connection->service_index;
    message->type = PSA_IPC_DISCONNECT;
    wt_ffm_enqueue(runtime, connection->service_index, message_index);
    ret = wt_ffm_dispatch_message(runtime, message_index);
    if (ret != WT_FFM_SUCCESS && message->active != 0U) {
        message->abandoned = WT_FFM_ABANDONED_CLOSE;
        return ret;
    }
    if (ret != WT_FFM_SUCCESS) {
        wt_ffm_dequeue_message(runtime, connection->service_index,
                               message_index);
    }
    wt_ffm_release_message(runtime, message_index);
    if (ret == WT_FFM_SUCCESS)
        wt_ffm_release_connection(runtime, connection_index);
    return ret;
}

psa_handle_t wt_ffm_connect_begin(wt_ffm_runtime_t* runtime,
                                  psa_client_id_t caller, uint32_t sid,
                                  uint32_t version, uint16_t* msg_index)
{
    wt_ffm_connection_runtime_t* connection;
    wt_ffm_message_runtime_t* message;
    uint16_t connection_index;
    uint16_t message_index;
    uint16_t service_index;
    psa_handle_t handle;
    int ret;

    if (runtime == NULL || caller == 0 || msg_index == NULL)
        return (psa_handle_t)PSA_ERROR_INVALID_ARGUMENT;
    ret = wt_ffm_find_service(runtime, sid, &service_index);
    if (ret != WT_FFM_SUCCESS ||
            !wt_ffm_caller_allowed(runtime, caller, service_index) ||
            !wt_ffm_version_allowed(
                runtime->services[service_index].descriptor, version)) {
        return (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED;
    }
    if (runtime->services[service_index].descriptor->connection_based == 0U)
        return (psa_handle_t)PSA_ERROR_NOT_SUPPORTED;

    /* Per-client quota: a single client cannot reserve the whole shared
     * connection pool and starve peers of every service (CWE-400). */
    if (wt_ffm_client_connection_count(runtime, caller) >=
            WT_FFM_MAX_CONNECTIONS_PER_CLIENT)
        return (psa_handle_t)PSA_ERROR_CONNECTION_BUSY;

    if (wt_ffm_alloc_connection(runtime, &connection_index) !=
            WT_FFM_SUCCESS)
        return (psa_handle_t)PSA_ERROR_CONNECTION_BUSY;
    if (wt_ffm_alloc_message(runtime, &message_index) != WT_FFM_SUCCESS) {
        wt_ffm_release_connection(runtime, connection_index);
        return (psa_handle_t)PSA_ERROR_CONNECTION_BUSY;
    }

    connection = &runtime->connections[connection_index];
    connection->caller = caller;
    connection->service_index = service_index;
    connection->state = WT_IPC_CONNECTION_PENDING_CONNECT;
    handle = wt_ffm_make_handle(WT_FFM_HANDLE_CONNECTION, connection_index,
                                connection->generation);

    message = &runtime->messages[message_index];
    message->caller = caller;
    message->connection_index = connection_index;
    message->service_index = service_index;
    message->type = PSA_IPC_CONNECT;
    wt_ffm_enqueue(runtime, service_index, message_index);
    *msg_index = message_index;
    return handle;
}

psa_status_t wt_ffm_call_begin(wt_ffm_runtime_t* runtime,
                               psa_client_id_t caller, psa_handle_t handle,
                               int32_t type, const psa_invec* in_vec,
                               size_t in_len, psa_outvec* out_vec,
                               size_t out_len, uint16_t* msg_index)
{
    wt_ffm_connection_runtime_t* connection;
    wt_ffm_message_runtime_t* message;
    uint16_t connection_index;
    uint16_t message_index;
    int ret;

    if (runtime == NULL || caller == 0 || msg_index == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;
    ret = wt_ffm_connection_from_handle(runtime, caller, handle,
                                        &connection_index);
    if (ret != WT_FFM_SUCCESS)
        /* FF-M: a forged, stale, or wrong-owner handle is a PROGRAMMER ERROR. */
        return PSA_ERROR_PROGRAMMER_ERROR;
    connection = &runtime->connections[connection_index];
    /* FF-M: a malformed call on a valid connection drops it to the error
     * state; it must not stay usable after the PROGRAMMER ERROR. */
    if (type < 0 || in_len > PSA_MAX_IOVEC || out_len > PSA_MAX_IOVEC ||
            in_len + out_len > PSA_MAX_IOVEC) {
        if (connection->state == WT_IPC_CONNECTION_IDLE)
            connection->state = WT_IPC_CONNECTION_ERROR;
        else
            connection->error_latch = 1U;
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (connection->state != WT_IPC_CONNECTION_IDLE) {
        /* FF-M: a busy or programmer-error-dropped connection is a PROGRAMMER
         * ERROR until close; latch so it lands in the error state once the
         * in-flight request completes. */
        connection->error_latch = 1U;
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (wt_ffm_alloc_message(runtime, &message_index) != WT_FFM_SUCCESS)
        return PSA_ERROR_INSUFFICIENT_MEMORY;

    message = &runtime->messages[message_index];
    message->caller = caller;
    message->connection_index = connection_index;
    message->service_index = connection->service_index;
    message->type = type;
    ret = wt_ffm_prepare_vectors(runtime, message, in_vec, in_len,
                                 out_vec, out_len);
    if (ret != WT_FFM_SUCCESS) {
        wt_ffm_release_message(runtime, message_index);
        /* FF-M: a vector referencing memory the caller cannot access is a
         * PROGRAMMER ERROR, not a permission denial; the connection stays in
         * the error state until close. */
        if (ret != WT_FFM_ERROR_BUFFER)
            connection->state = WT_IPC_CONNECTION_ERROR;
        return ret == WT_FFM_ERROR_BUFFER ? PSA_ERROR_INVALID_ARGUMENT :
                                            PSA_ERROR_PROGRAMMER_ERROR;
    }

    connection->state = WT_IPC_CONNECTION_PENDING_REQUEST;
    wt_ffm_enqueue(runtime, connection->service_index, message_index);
    *msg_index = message_index;
    return PSA_SUCCESS;
}

int wt_ffm_close_begin(wt_ffm_runtime_t* runtime, psa_client_id_t caller,
                       psa_handle_t handle, uint16_t* msg_index)
{
    wt_ffm_connection_runtime_t* connection;
    wt_ffm_message_runtime_t* message;
    uint16_t connection_index;
    uint16_t message_index;
    int ret;

    if (msg_index == NULL)
        return WT_FFM_ERROR_ARGUMENT;
    if (handle == PSA_NULL_HANDLE) {
        *msg_index = WT_FFM_QUEUE_NONE;
        return WT_FFM_SUCCESS;
    }
    if (runtime == NULL || caller == 0)
        return WT_FFM_ERROR_ARGUMENT;
    ret = wt_ffm_connection_from_handle(runtime, caller, handle,
                                        &connection_index);
    if (ret != WT_FFM_SUCCESS)
        return ret;
    connection = &runtime->connections[connection_index];
    if (connection->state != WT_IPC_CONNECTION_IDLE &&
            connection->state != WT_IPC_CONNECTION_ERROR)
        return WT_FFM_ERROR_STATE;
    if (wt_ffm_close_abandoned(runtime, connection_index) != 0) {
        *msg_index = WT_FFM_QUEUE_NONE;
        return WT_FFM_SUCCESS;
    }
    if (wt_ffm_alloc_message(runtime, &message_index) != WT_FFM_SUCCESS)
        return WT_FFM_ERROR_RESOURCE;

    connection->state = WT_IPC_CONNECTION_DISCONNECTING;
    message = &runtime->messages[message_index];
    message->caller = caller;
    message->connection_index = connection_index;
    message->service_index = connection->service_index;
    message->type = PSA_IPC_DISCONNECT;
    wt_ffm_enqueue(runtime, connection->service_index, message_index);
    *msg_index = message_index;
    return WT_FFM_SUCCESS;
}

int wt_ffm_msg_complete(const wt_ffm_runtime_t* runtime, uint16_t msg_index)
{
    if (runtime == NULL || msg_index >= WT_FFM_MAX_MESSAGES)
        return 0;
    return runtime->messages[msg_index].allocated != 0U &&
           runtime->messages[msg_index].complete != 0U;
}

/* WT-FFM-0017: when a Secure Partition faults, force-complete every message it
 * was serving so any pinned client unblocks with a defined error instead of
 * hanging on a response that will never arrive. A message is owned by the
 * faulted partition when its service resolves to that partition's domain id.
 * Undelivered (queued, never dispatched) and in-flight (active) messages both
 * complete; the connection drops to ERROR so the client cannot reuse it.
 * Returns the number of messages failed. */
int wt_ffm_fail_partition_messages(wt_ffm_runtime_t* runtime,
                                   int32_t partition_id, psa_status_t status)
{
    wt_ffm_message_runtime_t* message;
    wt_ffm_connection_runtime_t* connection;
    wt_ffm_service_runtime_t* service;
    wt_ffm_partition_runtime_t* partition;
    int failed = 0;
    size_t i;

    if (runtime == NULL) {
        return 0;
    }

    for (i = 0U; i < WT_FFM_MAX_MESSAGES; i++) {
        message = &runtime->messages[i];
        if (message->allocated == 0U || message->complete != 0U) {
            continue;
        }
        service = &runtime->services[message->service_index];
        partition = &runtime->partitions[service->partition_index];
        if (partition->manifest == NULL ||
                partition->manifest->domain_id !=
                    (wt_domain_id_t)partition_id) {
            continue;
        }
        message->reply_status = status;
        message->active = 0U;
        message->complete = 1U;
        runtime->connections[message->connection_index].state =
            WT_IPC_CONNECTION_ERROR;
        if (message->abandoned != 0U) {
            if (message->abandoned == WT_FFM_ABANDONED_CLOSE)
                wt_ffm_release_connection(runtime, message->connection_index);
            wt_ffm_release_message(runtime, (uint16_t)i);
        }
        failed++;
    }

    /* Drain the dead partition's service queues and deassert their signals:
     * a restarted partition must wake for NEW work only, or its first
     * psa_wait spins on messages that were already force-completed above. */
    for (i = 0U; i < runtime->service_count; i++) {
        service = &runtime->services[i];
        partition = &runtime->partitions[service->partition_index];
        if (partition->manifest == NULL ||
                partition->manifest->domain_id !=
                    (wt_domain_id_t)partition_id) {
            continue;
        }
        service->queue_head = WT_FFM_QUEUE_NONE;
        service->queue_tail = WT_FFM_QUEUE_NONE;
        wt_ffm_update_service_signal(runtime, (uint16_t)i);
    }

    /* Every connection to the dead partition drops to ERROR, idle ones
     * included (an idle connection owns no message, so the loops above never
     * visit it), and its reverse handle is cleared: the restarted instance
     * must never receive a pointer into the domain that was just scrubbed.
     * The client still has to close the handle to release the slot (FF-M A). */
    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        connection = &runtime->connections[i];
        if (connection->allocated == 0U ||
                connection->state == WT_IPC_CONNECTION_FREE ||
                connection->state == WT_IPC_CONNECTION_TERMINAL) {
            continue;
        }
        service = &runtime->services[connection->service_index];
        partition = &runtime->partitions[service->partition_index];
        if (partition->manifest == NULL ||
                partition->manifest->domain_id !=
                    (wt_domain_id_t)partition_id) {
            continue;
        }
        connection->state = WT_IPC_CONNECTION_ERROR;
        connection->rhandle = 0U;
    }
    return failed;
}

/* WT-FFM-0026: when a client terminates abnormally (a Non-secure guest is
 * quarantined or restarted) nothing will ever close its handles, so release
 * every connection it owns outright; otherwise each restart leaks slots until
 * every psa_connect on the system reports CONNECTION_BUSY forever. Any
 * request still in flight on such a connection is force-completed and its
 * slot released first, so a later service reply cannot land in a slot that
 * has been handed to a new client. Returns the number of connections freed. */
int wt_ffm_fail_client_connections(wt_ffm_runtime_t* runtime,
                                   psa_client_id_t caller)
{
    wt_ffm_message_runtime_t* message;
    wt_ffm_connection_runtime_t* connection;
    int freed = 0;
    size_t i;

    if (runtime == NULL) {
        return 0;
    }

    for (i = 0U; i < WT_FFM_MAX_MESSAGES; i++) {
        message = &runtime->messages[i];
        if (message->allocated == 0U || message->caller != caller) {
            continue;
        }
        if (message->complete == 0U && message->active == 0U) {
            wt_ffm_dequeue_message(runtime, message->service_index,
                                   (uint16_t)i);
        }
        wt_ffm_release_message(runtime, (uint16_t)i);
    }

    for (i = 0U; i < WT_FFM_MAX_CONNECTIONS; i++) {
        connection = &runtime->connections[i];
        if (connection->allocated == 0U || connection->caller != caller) {
            continue;
        }
        /* Release only: the abnormal-termination path runs in the guest
         * fault handler, where dispatching a service inline to deliver a
         * cleanup disconnection is unsafe (it re-enters the scheduler and
         * breaks restart recovery). The service's per-connection state is
         * reclaimed on its own next run; see the scoped deviation. */
        wt_ffm_release_connection(runtime, (uint16_t)i);
        freed++;
    }
    return freed;
}

int wt_ffm_dispatch_pending(wt_ffm_runtime_t* runtime, uint16_t msg_index)
{
    if (runtime == NULL || msg_index >= WT_FFM_MAX_MESSAGES ||
            runtime->messages[msg_index].allocated == 0U) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    return wt_ffm_dispatch_message(runtime, msg_index);
}

psa_handle_t wt_ffm_connect_finish(wt_ffm_runtime_t* runtime,
                                   uint16_t msg_index)
{
    wt_ffm_message_runtime_t* message;
    uint16_t connection_index;
    psa_status_t status;
    psa_handle_t handle;

    if (runtime == NULL || msg_index >= WT_FFM_MAX_MESSAGES)
        return (psa_handle_t)PSA_ERROR_INVALID_ARGUMENT;
    message = &runtime->messages[msg_index];
    connection_index = message->connection_index;
    status = message->reply_status;
    wt_ffm_release_message(runtime, msg_index);
    if (status != PSA_SUCCESS) {
        wt_ffm_release_connection(runtime, connection_index);
        return (psa_handle_t)status;
    }
    handle = wt_ffm_make_handle(WT_FFM_HANDLE_CONNECTION, connection_index,
                                runtime->connections[connection_index].
                                    generation);
    return handle;
}

psa_status_t wt_ffm_call_finish(wt_ffm_runtime_t* runtime, uint16_t msg_index,
                                psa_outvec* out_vec, size_t out_len)
{
    wt_ffm_message_runtime_t* message;
    wt_ffm_connection_runtime_t* connection;
    psa_status_t status;
    size_t i;

    if (runtime == NULL || msg_index >= WT_FFM_MAX_MESSAGES)
        return PSA_ERROR_INVALID_ARGUMENT;
    message = &runtime->messages[msg_index];
    connection = &runtime->connections[message->connection_index];
    status = message->reply_status;
    /* Atomic output publication (FF-M): validate every destination first. */
    for (i = 0U; i < message->out_count; i++) {
        if (message->out_position[i] != 0U &&
                runtime->ops->check_write(runtime->port_context,
                    message->caller, message->client_output[i],
                    message->out_position[i]) == 0) {
            /* FF-M: invalid caller output reference = PROGRAMMER ERROR (see
             * the synchronous path above). */
            connection->state = WT_IPC_CONNECTION_ERROR;
            wt_ffm_release_message(runtime, msg_index);
            return PSA_ERROR_PROGRAMMER_ERROR;
        }
    }
    for (i = 0U; i < message->out_count; i++) {
        if (message->out_position[i] != 0U) {
            (void)memcpy(message->client_output[i],
                &message->output[message->out_offset[i]],
                message->out_position[i]);
        }
        if (out_vec != NULL && i < out_len)
            out_vec[i].len = message->out_position[i];
    }
    wt_ffm_release_message(runtime, msg_index);
    return status;
}

int wt_ffm_close_finish(wt_ffm_runtime_t* runtime, uint16_t msg_index)
{
    uint16_t connection_index;

    if (runtime == NULL || msg_index >= WT_FFM_MAX_MESSAGES)
        return WT_FFM_ERROR_ARGUMENT;
    connection_index = runtime->messages[msg_index].connection_index;
    wt_ffm_release_message(runtime, msg_index);
    wt_ffm_release_connection(runtime, connection_index);
    return WT_FFM_SUCCESS;
}

static psa_signal_t wt_ffm_partition_signal_set(
    const wt_ffm_runtime_t* runtime, uint16_t partition_index)
{
    const wt_partition_manifest_t* manifest;
    psa_signal_t set = PSA_DOORBELL;
    size_t i;

    for (i = 0U; i < runtime->service_count; i++) {
        if (runtime->services[i].partition_index == partition_index)
            set |= runtime->services[i].descriptor->signal;
    }
    manifest = runtime->partitions[partition_index].manifest;
    for (i = 0U; i < manifest->interrupt_count; i++)
        set |= manifest->interrupts[i].signal;
    return set;
}

int wt_ffm_wait(wt_ffm_runtime_t* runtime, int32_t partition_id,
                psa_signal_t signal_mask, psa_signal_t* asserted)
{
    uint16_t partition_index;

    if (runtime == NULL || asserted == NULL || signal_mask == 0U)
        return WT_FFM_ERROR_ARGUMENT;
    if (wt_ffm_find_partition(runtime, partition_id, &partition_index) !=
            WT_FFM_SUCCESS)
        return WT_FFM_ERROR_POLICY;
    if ((signal_mask & wt_ffm_partition_signal_set(runtime,
            partition_index)) == 0U) {
        /* FF-M 4.5.3: psa_wait is a PROGRAMMER ERROR only when the mask
         * selects no signal assigned to the caller (i062); unassigned bits
         * mixed with an assigned one are ignored, not a fault. */
        return WT_FFM_ERROR_ARGUMENT;
    }
    *asserted = runtime->partitions[partition_index].asserted_signals &
                signal_mask;
    return *asserted == 0U ? WT_FFM_ERROR_NOT_READY : WT_FFM_SUCCESS;
}

int wt_ffm_notify(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    uint16_t partition_index;

    if (wt_ffm_find_partition(runtime, partition_id, &partition_index) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_POLICY;
    }
    runtime->partitions[partition_index].asserted_signals |= PSA_DOORBELL;
    return WT_FFM_SUCCESS;
}

int wt_ffm_clear(wt_ffm_runtime_t* runtime, int32_t partition_id)
{
    uint16_t partition_index;
    psa_signal_t* asserted_signals;

    if (wt_ffm_find_partition(runtime, partition_id, &partition_index) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_POLICY;
    }
    asserted_signals = &runtime->partitions[partition_index].asserted_signals;
    if ((*asserted_signals & PSA_DOORBELL) == 0U)
        return WT_FFM_ERROR_STATE;
    *asserted_signals &= ~PSA_DOORBELL;
    return WT_FFM_SUCCESS;
}

int wt_ffm_eoi(wt_ffm_runtime_t* runtime, int32_t partition_id,
               psa_signal_t irq_signal)
{
    uint16_t partition_index;
    const wt_partition_manifest_t* manifest;
    psa_signal_t* asserted_signals;
    psa_signal_t interrupt_mask;
    size_t i;

    if (runtime == NULL)
        return WT_FFM_ERROR_ARGUMENT;
    if (wt_ffm_find_partition(runtime, partition_id, &partition_index) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_POLICY;
    }
    /* FF-M: psa_eoi takes exactly one interrupt signal. Zero or more than one
     * asserted bit is a programmer error. */
    if (irq_signal == 0U || (irq_signal & (irq_signal - 1U)) != 0U)
        return WT_FFM_ERROR_ARGUMENT;
    manifest = runtime->partitions[partition_index].manifest;
    interrupt_mask = 0U;
    if (manifest != NULL) {
        for (i = 0; i < manifest->interrupt_count; i++)
            interrupt_mask |= (psa_signal_t)manifest->interrupts[i].signal;
    }
    /* The signal must be one this partition declared as an interrupt... */
    if ((irq_signal & interrupt_mask) == 0U)
        return WT_FFM_ERROR_POLICY;
    asserted_signals = &runtime->partitions[partition_index].asserted_signals;
    /* ...and it must currently be asserted. */
    if ((*asserted_signals & irq_signal) == 0U)
        return WT_FFM_ERROR_STATE;
    *asserted_signals &= ~irq_signal;
    return WT_FFM_SUCCESS;
}

int wt_ffm_irq_lookup(wt_ffm_runtime_t* runtime, int32_t partition_id,
                      psa_signal_t irq_signal, uint32_t* irq_out)
{
    uint16_t partition_index;
    const wt_partition_manifest_t* manifest;
    size_t i;

    if (runtime == NULL)
        return WT_FFM_ERROR_ARGUMENT;
    if (wt_ffm_find_partition(runtime, partition_id, &partition_index) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_POLICY;
    }
    if (irq_signal == 0U || (irq_signal & (irq_signal - 1U)) != 0U)
        return WT_FFM_ERROR_ARGUMENT;
    manifest = runtime->partitions[partition_index].manifest;
    if (manifest != NULL) {
        for (i = 0; i < manifest->interrupt_count; i++) {
            if ((psa_signal_t)manifest->interrupts[i].signal == irq_signal) {
                if (irq_out != NULL)
                    *irq_out = manifest->interrupts[i].interrupt;
                return WT_FFM_SUCCESS;
            }
        }
    }
    return WT_FFM_ERROR_POLICY;
}

int wt_ffm_irq_route(wt_ffm_runtime_t* runtime, uint32_t irq,
                     int32_t* partition_id_out, psa_signal_t* signal_out)
{
    const wt_partition_manifest_t* manifest;
    size_t p;
    size_t i;

    if (runtime == NULL)
        return WT_FFM_ERROR_ARGUMENT;
    for (p = 0; p < runtime->partition_count; p++) {
        manifest = runtime->partitions[p].manifest;
        if (manifest == NULL)
            continue;
        for (i = 0; i < manifest->interrupt_count; i++) {
            if (manifest->interrupts[i].interrupt == irq) {
                if (partition_id_out != NULL)
                    *partition_id_out = (int32_t)manifest->domain_id;
                if (signal_out != NULL) {
                    *signal_out =
                        (psa_signal_t)manifest->interrupts[i].signal;
                }
                return WT_FFM_SUCCESS;
            }
        }
    }
    return WT_FFM_ERROR_POLICY;
}

int wt_ffm_assert_signal(wt_ffm_runtime_t* runtime, int32_t partition_id,
                         psa_signal_t irq_signal)
{
    uint16_t partition_index;
    int ret;

    ret = wt_ffm_irq_lookup(runtime, partition_id, irq_signal, NULL);
    if (ret != WT_FFM_SUCCESS)
        return ret;
    if (wt_ffm_find_partition(runtime, partition_id, &partition_index) !=
            WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_POLICY;
    }
    runtime->partitions[partition_index].asserted_signals |= irq_signal;
    return WT_FFM_SUCCESS;
}

psa_status_t wt_ffm_get(wt_ffm_runtime_t* runtime, int32_t partition_id,
                        psa_signal_t signal, psa_msg_t* msg)
{
    wt_ffm_service_runtime_t* service = NULL;
    wt_ffm_message_runtime_t* message;
    wt_ffm_connection_runtime_t* connection;
    uint16_t partition_index;
    uint16_t message_index;
    size_t i;

    if (runtime == NULL || msg == NULL || signal == 0U ||
            wt_ffm_find_partition(runtime, partition_id,
                &partition_index) != WT_FFM_SUCCESS) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    for (i = 0U; i < runtime->service_count; i++) {
        if (runtime->services[i].partition_index == partition_index &&
                runtime->services[i].descriptor->signal == signal) {
            service = &runtime->services[i];
            break;
        }
    }
    if (service == NULL || service->queue_head == WT_FFM_QUEUE_NONE)
        return PSA_ERROR_DOES_NOT_EXIST;

    message_index = service->queue_head;
    message = &runtime->messages[message_index];
    service->queue_head = message->next;
    if (service->queue_head == WT_FFM_QUEUE_NONE)
        service->queue_tail = WT_FFM_QUEUE_NONE;
    message->next = WT_FFM_QUEUE_NONE;
    message->active = 1U;
    wt_ffm_update_service_signal(runtime, message->service_index);

    connection = &runtime->connections[message->connection_index];
    if (message->type == PSA_IPC_CONNECT)
        connection->state = WT_IPC_CONNECTION_CONNECTING;
    else if (message->type >= PSA_IPC_CALL)
        connection->state = WT_IPC_CONNECTION_ACTIVE;

    (void)memset(msg, 0, sizeof(*msg));
    msg->handle = wt_ffm_make_handle(WT_FFM_HANDLE_MESSAGE, message_index,
                                     message->generation);
    msg->type = message->type;
    msg->client_id = message->caller;
    msg->rhandle = (void*)connection->rhandle;
    for (i = 0U; i < PSA_MAX_IOVEC; i++) {
        msg->in_size[i] = message->in_size[i];
        msg->out_size[i] = message->out_size[i];
    }
    return PSA_SUCCESS;
}

int wt_ffm_set_rhandle(wt_ffm_runtime_t* runtime, int32_t partition_id,
                       psa_handle_t msg_handle, void* rhandle)
{
    wt_ffm_message_runtime_t* message;
    uint16_t message_index;

    if (wt_ffm_message_from_handle(runtime, partition_id, msg_handle,
            &message_index) != WT_FFM_SUCCESS)
        return WT_FFM_ERROR_HANDLE;
    message = &runtime->messages[message_index];
    if (message->type == PSA_IPC_DISCONNECT)
        return WT_FFM_SUCCESS; /* FF-M: no observable effect on disconnect */
    runtime->connections[message->connection_index].rhandle =
        (uintptr_t)rhandle;
    return WT_FFM_SUCCESS;
}

int wt_ffm_msg_access_check(wt_ffm_runtime_t* runtime, int32_t partition_id,
                            psa_handle_t msg_handle, uint32_t vec_idx)
{
    wt_ffm_message_runtime_t* message;
    uint16_t message_index;

    if (vec_idx >= PSA_MAX_IOVEC)
        return WT_FFM_ERROR_ARGUMENT;
    if (wt_ffm_message_from_handle(runtime, partition_id, msg_handle,
            &message_index) != WT_FFM_SUCCESS)
        return WT_FFM_ERROR_HANDLE;
    message = &runtime->messages[message_index];
    /* FF-M: read/write/skip are only legal on request (call) messages. */
    if (message->type < PSA_IPC_CALL)
        return WT_FFM_ERROR_STATE;
    return WT_FFM_SUCCESS;
}

size_t wt_ffm_read(wt_ffm_runtime_t* runtime, int32_t partition_id,
                   psa_handle_t msg_handle, uint32_t invec_idx,
                   void* buffer, size_t num_bytes)
{
    wt_ffm_message_runtime_t* message;
    uint16_t message_index;
    size_t remaining;
    size_t length;

    if (buffer == NULL || invec_idx >= PSA_MAX_IOVEC ||
            wt_ffm_message_from_handle(runtime, partition_id, msg_handle,
                &message_index) != WT_FFM_SUCCESS) {
        return 0U;
    }
    message = &runtime->messages[message_index];
    if (message->type < PSA_IPC_CALL || invec_idx >= message->in_count)
        return 0U;
    remaining = message->in_size[invec_idx] -
                message->in_position[invec_idx];
    length = num_bytes < remaining ? num_bytes : remaining;
    if (length != 0U) {
        (void)memcpy(buffer,
            &message->input[message->in_offset[invec_idx] +
                            message->in_position[invec_idx]], length);
        message->in_position[invec_idx] += length;
    }
    return length;
}

size_t wt_ffm_skip(wt_ffm_runtime_t* runtime, int32_t partition_id,
                   psa_handle_t msg_handle, uint32_t invec_idx,
                   size_t num_bytes)
{
    wt_ffm_message_runtime_t* message;
    uint16_t message_index;
    size_t remaining;
    size_t length;

    if (invec_idx >= PSA_MAX_IOVEC ||
            wt_ffm_message_from_handle(runtime, partition_id, msg_handle,
                &message_index) != WT_FFM_SUCCESS) {
        return 0U;
    }
    message = &runtime->messages[message_index];
    if (message->type < PSA_IPC_CALL || invec_idx >= message->in_count)
        return 0U;
    remaining = message->in_size[invec_idx] -
                message->in_position[invec_idx];
    length = num_bytes < remaining ? num_bytes : remaining;
    message->in_position[invec_idx] += length;
    return length;
}

int wt_ffm_write(wt_ffm_runtime_t* runtime, int32_t partition_id,
                 psa_handle_t msg_handle, uint32_t outvec_idx,
                 const void* buffer, size_t num_bytes)
{
    wt_ffm_message_runtime_t* message;
    uint16_t message_index;
    size_t remaining;

    if ((buffer == NULL && num_bytes != 0U) ||
            outvec_idx >= PSA_MAX_IOVEC ||
            wt_ffm_message_from_handle(runtime, partition_id, msg_handle,
                &message_index) != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_ARGUMENT;
    }
    message = &runtime->messages[message_index];
    if (message->type < PSA_IPC_CALL)
        return WT_FFM_ERROR_STATE;
    /* FF-M: an omitted output vector is a zero-sized entry through
     * PSA_MAX_IOVEC; a zero-byte write to it succeeds, a payload exceeds its
     * zero capacity and panics like any over-length write. */
    if (outvec_idx >= message->out_count)
        return num_bytes == 0U ? WT_FFM_SUCCESS : WT_FFM_ERROR_BUFFER;
    remaining = message->out_size[outvec_idx] -
                message->out_position[outvec_idx];
    if (num_bytes > remaining)
        return WT_FFM_ERROR_BUFFER;
    if (num_bytes != 0U) {
        (void)memcpy(&message->output[message->out_offset[outvec_idx] +
                                      message->out_position[outvec_idx]],
                     buffer, num_bytes);
        message->out_position[outvec_idx] += num_bytes;
    }
    return WT_FFM_SUCCESS;
}

static void wt_ffm_finish_abandoned(wt_ffm_runtime_t* runtime,
                                    uint16_t message_index)
{
    wt_ffm_message_runtime_t* message = &runtime->messages[message_index];
    uint16_t connection_index = message->connection_index;
    wt_ffm_connection_runtime_t* connection =
        &runtime->connections[connection_index];
    int disconnect;

    disconnect = (message->type == PSA_IPC_CONNECT &&
                  message->reply_status == PSA_SUCCESS) ||
                 (message->type >= PSA_IPC_CALL &&
                  message->abandoned == WT_FFM_ABANDONED_CLOSE);
    if (!disconnect && message->type < PSA_IPC_CALL)
        wt_ffm_release_connection(runtime, connection_index);
    wt_ffm_release_message(runtime, message_index);
    if (disconnect) {
        /* Reuse the replied slot so cleanup cannot fail on pool exhaustion. */
        message->allocated = 1U;
        message->abandoned = WT_FFM_ABANDONED_CLOSE;
        message->caller = connection->caller;
        message->connection_index = connection_index;
        message->service_index = connection->service_index;
        message->type = PSA_IPC_DISCONNECT;
        connection->state = WT_IPC_CONNECTION_DISCONNECTING;
        wt_ffm_enqueue(runtime, message->service_index, message_index);
    }
}

int wt_ffm_reply(wt_ffm_runtime_t* runtime, int32_t partition_id,
                 psa_handle_t msg_handle, psa_status_t status)
{
    wt_ffm_message_runtime_t* message;
    wt_ffm_connection_runtime_t* connection;
    uint16_t message_index;

    if (wt_ffm_message_from_handle(runtime, partition_id, msg_handle,
            &message_index) != WT_FFM_SUCCESS)
        return WT_FFM_ERROR_HANDLE;
    message = &runtime->messages[message_index];
    connection = &runtime->connections[message->connection_index];

    if (message->type == PSA_IPC_CONNECT) {
        /* FF-M restricts a connect reply to SUCCESS/REFUSED/BUSY; any other
         * status is a server-side PROGRAMMER ERROR (i020). */
        if (status != PSA_SUCCESS &&
                status != PSA_ERROR_CONNECTION_REFUSED &&
                status != PSA_ERROR_CONNECTION_BUSY) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        connection->state = status == PSA_SUCCESS ?
            WT_IPC_CONNECTION_IDLE : WT_IPC_CONNECTION_ERROR;
    }
    else if (message->type == PSA_IPC_DISCONNECT) {
        connection->state = WT_IPC_CONNECTION_TERMINAL;
    }
    else if (message->type >= PSA_IPC_CALL) {
        /* FF-M reserves CONNECTION_REFUSED/BUSY for connect replies; returning
         * either on a request message is a server-side PROGRAMMER ERROR. */
        if (status == PSA_ERROR_CONNECTION_REFUSED ||
                status == PSA_ERROR_CONNECTION_BUSY) {
            return WT_FFM_ERROR_ARGUMENT;
        }
        /* A client PROGRAMMER ERROR latched while this request was in flight
         * (a call on the busy connection) drops it to the error state now. */
        connection->state = (status == PSA_ERROR_PROGRAMMER_ERROR ||
                             connection->error_latch != 0U) ?
            WT_IPC_CONNECTION_ERROR : WT_IPC_CONNECTION_IDLE;
    }
    else {
        return WT_FFM_ERROR_STATE;
    }

    message->reply_status = status;
    message->active = 0U;
    message->complete = 1U;
    if (message->abandoned != 0U)
        wt_ffm_finish_abandoned(runtime, message_index);
    return WT_FFM_SUCCESS;
}
