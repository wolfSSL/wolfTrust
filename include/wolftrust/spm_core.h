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

/* Trims default on; a build turns one off with -D<name>=0. */
#ifndef WT_FFM_SP_DOORBELL
#define WT_FFM_SP_DOORBELL 1
#endif
#ifndef WT_FFM_SP_RHANDLE
#define WT_FFM_SP_RHANDLE 1
#endif
#ifndef WT_FFM_SP_SKIP
#define WT_FFM_SP_SKIP 1
#endif

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

typedef enum wt_spm_status {
    WT_SPM_OK = 0,
    WT_SPM_E_ARGUMENT = -600,
    WT_SPM_E_POLICY = -602,
    WT_SPM_E_HANDLE = -604,
    WT_SPM_E_STATE = -605,
    WT_SPM_E_NOT_READY = -606,
    WT_SPM_E_BUFFER = -607
} wt_spm_status_t;

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

/* Host fixtures derive the tables at run time and build with it empty. */
#ifndef WT_SPM_TABLE
#define WT_SPM_TABLE const
#endif
extern WT_SPM_TABLE wt_spm_service_t g_wt_spm_services[];
extern WT_SPM_TABLE uint8_t g_wt_spm_service_count;
extern WT_SPM_TABLE wt_spm_sp_ipc_t g_wt_spm_sps[];
extern WT_SPM_TABLE uint8_t g_wt_spm_sp_count;
extern WT_SPM_TABLE wt_spm_irq_t g_wt_spm_irqs[];
extern WT_SPM_TABLE uint8_t g_wt_spm_irq_count;
extern WT_SPM_TABLE uint32_t g_wt_spm_framework_version;

typedef struct wt_spm_vec {
    void* base;
    size_t len;
} wt_spm_vec_t;

/* Vector v is input v below PSA_MAX_IOVEC, else output v - PSA_MAX_IOVEC. */
#define WT_SPM_VECS (2U * PSA_MAX_IOVEC)

typedef struct wt_spm_xfer {
    void* dst[PSA_MAX_IOVEC];
    uint16_t len[WT_SPM_VECS];
    uint16_t pos[WT_SPM_VECS];
    uint16_t off[WT_SPM_VECS];
    uint8_t used;
    uint8_t buf[WT_SPM_TRANSFER_BYTES];
} wt_spm_xfer_t;

/* wt_spm_slot_t msg: where the slot's message is. */
enum {
    WT_SPM_MSG_NONE = 0,
    WT_SPM_MSG_QUEUED,
    WT_SPM_MSG_ACTIVE,
    WT_SPM_MSG_DONE
};

/* One slot is a connection and its single in-flight message. gen and mgen
 * tag its handles and stay last: a release clears everything before them. */
typedef struct wt_spm_slot {
    uintptr_t rhandle;
    wt_spm_xfer_t* xfer;
    psa_client_id_t caller;
    psa_status_t status;
    int32_t type;
    uint32_t ticket;
    uint8_t state;
    uint8_t msg;
    uint8_t svc;
    uint8_t latch;
    uint8_t detached;
    uint32_t gen;
    uint32_t mgen;
} wt_spm_slot_t;

#define WT_SPM_MAX_SPS 9U
/* A dependency is one bit of a 32-bit mask per service row. */
#define WT_SPM_MAX_SERVICES 32U

/* The transfers go last so every other field keeps a short offset. */
typedef struct wt_spm_core {
    wt_spm_slot_t slot[WT_SPM_SLOTS];
    psa_signal_t asserted[WT_SPM_MAX_SPS];
    uint32_t lifecycle;
    volatile psa_client_id_t ns_entry_caller;
    uint32_t ticket;
    wt_spm_xfer_t xfer[WT_SPM_TRANSFERS];
} wt_spm_core_t;

extern wt_spm_core_t g_wt_spm;

/* Boundary hook: may caller still write [base, base + len)? */
int wt_spm_caller_can_write(psa_client_id_t caller, void* base, size_t len);

void wt_spm_core_init(void);
int wt_spm_sp_index(int32_t pid);
uint32_t wt_spm_service_version(psa_client_id_t caller, uint32_t sid);

/* Client side: begin queues a message and returns its slot (0 or more) or a
 * negative status; done reports the reply, finish harvests it and abandon
 * detaches a client that will not wait. */
int32_t wt_spm_connect_begin(psa_client_id_t caller, uint32_t sid,
                             uint32_t version);
/* vec holds WT_SPM_VECS entries, inputs in the first half and outputs in the
 * second, already access-checked; entries past a count are ignored. */
int32_t wt_spm_call_begin(psa_client_id_t caller, psa_handle_t handle,
                          int32_t type, const wt_spm_vec_t* vec,
                          size_t in_len, size_t out_len);
/* WT_SPM_NO_SLOT: closed with nothing to wait for. */
int32_t wt_spm_close_begin(psa_client_id_t caller, psa_handle_t handle);
void wt_spm_call_refuse(psa_client_id_t caller, psa_handle_t handle);
/* 1 once the reply is in, 0 while waiting, negative unless slot holds a
 * message of kind (CONNECT, DISCONNECT, or any call type) from caller. */
int wt_spm_done(uint8_t slot, psa_client_id_t caller, int32_t kind);
psa_handle_t wt_spm_connect_finish(uint8_t slot);
/* Writes the bytes produced into the len of every output entry of vec. */
psa_status_t wt_spm_call_finish(uint8_t slot, wt_spm_vec_t* vec);
void wt_spm_close_finish(uint8_t slot);
void wt_spm_abandon(uint8_t slot);

/* Service side, partition identified by its SP index. */
psa_signal_t wt_spm_pending(uint8_t sp);
int wt_spm_wait(uint8_t sp, psa_signal_t mask, psa_signal_t* asserted);
psa_status_t wt_spm_get(uint8_t sp, psa_signal_t signal, psa_msg_t* msg);
#if defined(WT_FFM_SP_RHANDLE) && (WT_FFM_SP_RHANDLE == 1)
int wt_spm_set_rhandle(uint8_t sp, psa_handle_t msg, void* rhandle);
#endif
/* psa_read (buffer NULL for psa_skip) or psa_write on vector idx. */
int wt_spm_copy(uint8_t sp, psa_handle_t msg, uint32_t idx, void* buffer,
                size_t len, int write, size_t* done);
int wt_spm_reply(uint8_t sp, psa_handle_t msg, psa_status_t status);
#if defined(WT_FFM_SP_DOORBELL) && (WT_FFM_SP_DOORBELL == 1)
int wt_spm_notify(int32_t pid);
#endif
/* psa_clear passes PSA_DOORBELL; psa_eoi the signal wt_spm_irq_of accepted. */
int wt_spm_clear(uint8_t sp, psa_signal_t signal);
int wt_spm_irq_of(uint8_t sp, psa_signal_t irq_signal, uint32_t* irq);
int wt_spm_irq_assert(uint32_t irq);

/* Abnormal termination: a client that left, a partition that restarted.
 * One guest that never restarts leaves no client the sweep could help. */
#if (defined(WT_GUEST_RESTART) && (WT_GUEST_RESTART == 1)) || \
    (defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)) || (WT_MAX_GUESTS > 1)
#define WT_SPM_CLIENT_SWEEP 1
void wt_spm_client_gone(psa_client_id_t caller);
#endif
#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
int wt_spm_sp_restarted(uint8_t sp, psa_status_t status);
#endif

#endif /* WOLFTRUST_SPM_CORE_H */
