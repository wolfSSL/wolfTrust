/* spm_core.h
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

#ifndef WOLFTRUST_SPM_CORE_H
#define WOLFTRUST_SPM_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/client.h"
#include "psa/service.h"
#include "wolftrust/types.h"

#define WT_SPM_SLOTS              16U
#define WT_SPM_SLOTS_PER_CLIENT   (WT_SPM_SLOTS / 2U)
/* Slots Non-secure clients can never take, kept for Secure dependencies. */
#define WT_SPM_SECURE_RESERVED    4U
#define WT_SPM_NS_SLOTS           (WT_SPM_SLOTS - WT_SPM_SECURE_RESERVED)
#define WT_SPM_TRANSFER_BYTES     1024U
#define WT_SPM_NO_SLOT            0xFFU

#ifndef WT_SPM_TRANSFERS
#if (WT_MAX_GUESTS > 1) || defined(CONFIG_VNET) || \
    (defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1))
#define WT_SPM_TRANSFERS          8U
#else
#define WT_SPM_TRANSFERS          4U
#endif
#endif

typedef enum wt_spm_result {
    WT_SPM_OK = 0,
    WT_SPM_E_ARGUMENT = -600,
    WT_SPM_E_POLICY = -602,
    WT_SPM_E_RESOURCE = -603,
    WT_SPM_E_HANDLE = -604,
    WT_SPM_E_STATE = -605,
    WT_SPM_E_NOT_READY = -606,
    WT_SPM_E_BUFFER = -607
} wt_spm_result_t;

/* Generated, one row per RoT Service. */
typedef struct wt_spm_service {
    uint32_t sid;
    uint32_t version;
    psa_signal_t signal;
    uint8_t sp;
    uint8_t policy;
    uint8_t ns_ok;
    uint8_t conn;
} wt_spm_service_t;

typedef struct wt_spm_irq {
    uint32_t irq;
    psa_signal_t signal;
    uint8_t sp;
} wt_spm_irq_t;

/* Generated, one row per Secure Partition. deps has bit n set when the SP
 * may connect service n (never its own); signals is all it may wait on. */
typedef struct wt_spm_sp_ipc {
    int32_t pid;
    uint32_t deps;
    psa_signal_t signals;
} wt_spm_sp_ipc_t;

extern const wt_spm_service_t g_wt_spm_services[];
extern const uint8_t g_wt_spm_service_count;
extern const wt_spm_sp_ipc_t g_wt_spm_sps[];
extern const uint8_t g_wt_spm_sp_count;
extern const wt_spm_irq_t g_wt_spm_irqs[];
extern const uint8_t g_wt_spm_irq_count;
extern const uint32_t g_wt_spm_framework_version;

typedef struct wt_spm_vec {
    void* base;
    size_t len;
} wt_spm_vec_t;

typedef struct wt_spm_xfer {
    void* dst[PSA_MAX_IOVEC];
    uint16_t len[PSA_MAX_IOVEC];
    uint16_t pos[PSA_MAX_IOVEC];
    uint16_t off[PSA_MAX_IOVEC];
    uint8_t in_count;
    uint8_t out_count;
    uint8_t used;
    uint8_t buf[WT_SPM_TRANSFER_BYTES];
} wt_spm_xfer_t;

/* One slot is a connection and its single in-flight message. */
typedef struct wt_spm_slot {
    uintptr_t rhandle;
    psa_client_id_t caller;
    psa_status_t status;
    int32_t type;
    uint16_t gen;
    uint16_t mgen;
    uint8_t state;
    uint8_t msg;
    uint8_t svc;
    uint8_t ticket;
    uint8_t xfer;
    uint8_t latch;
    uint8_t detached;
} wt_spm_slot_t;

#define WT_SPM_MAX_SPS 9U

typedef struct wt_spm_core {
    wt_spm_slot_t slot[WT_SPM_SLOTS];
    wt_spm_xfer_t xfer[WT_SPM_TRANSFERS];
    psa_signal_t asserted[WT_SPM_MAX_SPS];
    uint8_t ticket;
    uint32_t lifecycle;
    volatile psa_client_id_t ns_entry_caller;
} wt_spm_core_t;

extern wt_spm_core_t g_wt_spm;

/* Boundary hook: may caller still write [base, base + len)? */
int wt_spm_caller_can_write(psa_client_id_t caller, void* base, size_t len);

void wt_spm_core_init(void);
int wt_spm_sp_index(int32_t pid);
uint32_t wt_spm_service_version(psa_client_id_t caller, uint32_t sid);

/* Client side: begin queues a message on a slot, done reports its reply,
 * finish harvests it and abandon detaches a client that will not wait. */
psa_status_t wt_spm_connect_begin(psa_client_id_t caller, uint32_t sid,
                                  uint32_t version, uint8_t* slot);
/* vec holds in_len inputs then out_len outputs, already access-checked. */
psa_status_t wt_spm_call_begin(psa_client_id_t caller, psa_handle_t handle,
                               int32_t type, const wt_spm_vec_t* vec,
                               size_t in_len, size_t out_len, uint8_t* slot);
psa_status_t wt_spm_close_begin(psa_client_id_t caller, psa_handle_t handle,
                                uint8_t* slot);
void wt_spm_call_refuse(psa_client_id_t caller, psa_handle_t handle);
int wt_spm_done(uint8_t slot);
psa_handle_t wt_spm_connect_finish(uint8_t slot);
psa_status_t wt_spm_call_finish(uint8_t slot, size_t out_len[PSA_MAX_IOVEC]);
void wt_spm_close_finish(uint8_t slot);
void wt_spm_abandon(uint8_t slot);

/* Service side, partition identified by its SP index. */
psa_signal_t wt_spm_pending(uint8_t sp);
int wt_spm_wait(uint8_t sp, psa_signal_t mask, psa_signal_t* asserted);
psa_status_t wt_spm_get(uint8_t sp, psa_signal_t signal, psa_msg_t* msg);
int wt_spm_set_rhandle(uint8_t sp, psa_handle_t msg, void* rhandle);
/* psa_read (buffer NULL for psa_skip) or psa_write on vector idx. */
int wt_spm_copy(uint8_t sp, psa_handle_t msg, uint32_t idx, void* buffer,
                size_t len, int write, size_t* done);
int wt_spm_reply(uint8_t sp, psa_handle_t msg, psa_status_t status);
int wt_spm_notify(int32_t pid);
int wt_spm_clear(uint8_t sp);
int wt_spm_eoi(uint8_t sp, psa_signal_t irq_signal);
int wt_spm_irq_of(uint8_t sp, psa_signal_t irq_signal, uint32_t* irq);
int wt_spm_irq_assert(uint32_t irq);

/* Abnormal termination: a client that left, a partition that restarted. */
void wt_spm_client_gone(psa_client_id_t caller);
#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
int wt_spm_sp_restarted(uint8_t sp, psa_status_t status);
#endif

#endif /* WOLFTRUST_SPM_CORE_H */
