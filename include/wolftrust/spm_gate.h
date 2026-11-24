/* spm_gate.h
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

#ifndef WOLFTRUST_SPM_GATE_H
#define WOLFTRUST_SPM_GATE_H

#include "wolftrust/ffm.h"
#include "wolftrust/ffm_domain.h"

/* The single privileged entry point every SP-side psa_* call funnels through.
 * On target a scheduled Secure Partition runs unprivileged on its own stack and
 * traps here via SVC; the handler unmarshals registers into wt_spm_call_t and
 * calls wt_spm_gate on the SPM (MSP_S, privileged) stack. On the host the same
 * gate is called directly, so the dispatch, argument validation, and block
 * classification are one architecture-neutral implementation exercised both
 * ways. WT-FFM-0014. */
typedef enum wt_spm_op {
    WT_SPM_OP_WAIT = 0,
    WT_SPM_OP_GET,
    WT_SPM_OP_SET_RHANDLE,
    WT_SPM_OP_READ,
    WT_SPM_OP_SKIP,
    WT_SPM_OP_WRITE,
    WT_SPM_OP_REPLY,
    WT_SPM_OP_NOTIFY,
    WT_SPM_OP_CLEAR,
    WT_SPM_OP_VERSION,
    WT_SPM_OP_CONNECT,
    WT_SPM_OP_CALL,
    WT_SPM_OP_CLOSE,
    WT_SPM_OP_EOI,
    WT_SPM_OP_IRQ_ENABLE,
    WT_SPM_OP_LIFECYCLE
    /* Production platform services, NOT FF-M IPC ops: the arch SVC layer
     * intercepts them before this gate. FWU_BACKEND is pinned to the FWU
     * partition; KEYSTORE_FLASH and KEYSTORE_LOCK are pinned to the vault
     * (the store owner) and KEYSTORE_ENTROPY to the vault and crypto
     * partitions (the DRBG owners). call_type selects the sub-operation. */
    , WT_SPM_OP_FWU_BACKEND = 0x40
    , WT_SPM_OP_KEYSTORE_FLASH = 0x41
    , WT_SPM_OP_KEYSTORE_ENTROPY = 0x42
    , WT_SPM_OP_KEYSTORE_LOCK = 0x43
    , WT_SPM_OP_MEASURE_READ = 0x44
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    /* Platform conformance services, NOT FF-M IPC ops: the arch SVC layer
     * intercepts them before this gate, so no case handles them here. Real
     * enumerators (not out-of-range constants) keep their values inside the
     * enum range so the interception compares are never folded away.
     * CONF_NVM_SYNC = flash NVM shadow sync (P5 K2). CONF_IRQ_SET = drive the
     * PAL UART interrupt source on/off (P4.2c). */
    , WT_SPM_OP_CONF_NVM_SYNC = 0x100
    , WT_SPM_OP_CONF_IRQ_SET = 0x101
#endif
} wt_spm_op_t;

/* WT_SPM_OP_FWU_BACKEND sub-operations, carried in call_type. */
#define WT_SPM_FWU_BEGIN  0
#define WT_SPM_FWU_WRITE  1
#define WT_SPM_FWU_ARM    2
#define WT_SPM_FWU_DISARM 3
#define WT_SPM_FWU_REBOOT 4
#define WT_SPM_FWU_FLOOR  5
#define WT_SPM_FWU_VERIFY 6
#define WT_SPM_FWU_ACTIVE 7

/* WT_SPM_OP_KEYSTORE_FLASH sub-operations, carried in call_type. Only the
 * callbacks that touch the flash controller trap; pure in-band bookkeeping
 * (init, partition size, write lock/unlock) never needs the gate. */
#define WT_SPM_KS_FLASH_READ       0
#define WT_SPM_KS_FLASH_PROGRAM    1
#define WT_SPM_KS_FLASH_ERASE      2
#define WT_SPM_KS_FLASH_VERIFY     3
#define WT_SPM_KS_FLASH_BLANKCHECK 4
#define WT_SPM_KS_FLASH_CLEANUP    5

/* WT_SPM_OP_KEYSTORE_LOCK sub-operations, carried in call_type. */
#define WT_SPM_KS_LOCK_ACQUIRE 0
#define WT_SPM_KS_LOCK_RELEASE 1

/* Gated Secure Partition calls, defined in the arch SVC layer. The
 * unprivileged-thread query is wt_arch_thread_unprivileged (wolftrust/arch.h). */
#ifdef WT_TARGET_BUILD
/* Gated NVM-lock hop for the keystore lock callback (defined in the arch SVC
 * layer); loops internally until the lock is granted. Returns 0 on success. */
int wt_spm_keystore_lock_call(int sub_op);
/* Gated read-only measurement snapshot for the confined attest partition
 * (defined in the arch SVC layer). Always reports the record count via
 * count when non-NULL; copies record[index] into record when non-NULL.
 * Returns 0 on success. */
int wt_spm_measure_read_call(unsigned int index, void* record,
                             unsigned int record_len, unsigned int* count);
#endif

/* SP-as-client iovec capacity per direction (i003 widens with the NS veneer). */
#define WT_SPM_SP_IOVEC 4U

typedef struct wt_spm_call {
    wt_spm_op_t  op;
    int32_t      partition_id;   /* acting partition (SVC stamps the caller) */
    int32_t      notify_partition; /* NOTIFY target */
    psa_handle_t msg_handle;   /* GET/SET_RHANDLE/READ/SKIP/WRITE/REPLY;
                                * CALL/CLOSE: connection handle */
    psa_signal_t signal_mask;  /* WAIT in */
    uint32_t     timeout;      /* WAIT in: PSA_BLOCK blocks, PSA_POLL returns */
    psa_signal_t signal;       /* GET in */
    uint32_t     vec_idx;      /* READ/SKIP/WRITE in */
    void*        buffer;       /* READ out / WRITE in (SP-domain pointer) */
    size_t       num_bytes;    /* READ/SKIP/WRITE in */
    psa_status_t status;       /* REPLY in */
    psa_msg_t*   msg;          /* GET out (SP-domain pointer) */
    psa_signal_t* asserted;    /* WAIT out (SP-domain pointer) */
    void*        rhandle;      /* SET_RHANDLE in */

    /* SP-as-client IPC (WT-FFM-0014): a partition connecting to another
     * partition's service. The op is issued twice around a block: the first
     * pass validates + enqueues (pending_valid set, NOT_READY returned), the
     * wake pass harvests the completed message. */
    uint32_t     sid;          /* CONNECT/VERSION in */
    uint32_t     version;      /* CONNECT in */
    int32_t      call_type;    /* CALL in */
    psa_invec    sp_in[WT_SPM_SP_IOVEC];   /* CALL in (SP-domain pointers) */
    psa_outvec   sp_out[WT_SPM_SP_IOVEC];  /* CALL in/out (SP-domain pointers) */
    uint8_t      sp_in_len;    /* CALL in */
    uint8_t      sp_out_len;   /* CALL in */
    uint16_t     pending_msg;  /* async resume state (gate-owned) */
    uint8_t      pending_valid;

    psa_status_t ret_status;   /* GET/REPLY/CALL result */
    size_t       ret_size;     /* READ/SKIP result */
    int          ret_int;      /* WAIT/SET_RHANDLE/WRITE/NOTIFY/CLEAR result */
    psa_handle_t ret_handle;   /* CONNECT result */
    uint32_t     ret_version;  /* VERSION result */
    uint32_t     ret_tick;     /* out: scheduler tick stamped on every SVC
                                * return, so a confined SP has a time source
                                * without reaching monitor state */

    /* Set when the op is an FF-M PROGRAMMER ERROR the SPM must panic the caller
     * for (psa_get/psa_read/psa_write with an out-of-domain buffer), rather
     * than an error the caller may recover from. The platform decides what a
     * panic means: reset in the conformance image, fail-closed in production. */
    uint8_t      must_panic;   /* out: caller committed a must-panic error */
} wt_spm_call_t;

/* Keystore platform services are pinned to the partition that owns each
 * need: flash and the NVM lock to the vault (the store owner), entropy to the
 * vault and the crypto partition (the DRBG owners). Non-zero when caller may
 * issue op. */
static inline int wt_spm_keystore_op_pinned(wt_spm_op_t op, int32_t caller,
                                            int32_t vault, int32_t crypto)
{
    if (caller <= 0) {
        return 0;
    }
    if (caller == vault) {
        return 1;
    }
    return (op == WT_SPM_OP_KEYSTORE_ENTROPY) && (caller == crypto);
}

/* Run one SPM service request against the runtime. When caller_domain is not
 * NULL, every SP-supplied pointer the op dereferences is bounds-checked against
 * that partition's resolved protection domain first; an out-of-domain pointer
 * fails the op closed rather than letting the privileged SPM touch memory the
 * unprivileged partition could not reach itself. Returns WT_FFM_SUCCESS when
 * the op ran (its PSA-level result is in the call's ret_* fields), or a
 * WT_FFM_ERROR_* code when the request itself was rejected. */
int wt_spm_gate(wt_ffm_runtime_t* runtime,
                const wt_secure_domain_t* caller_domain,
                wt_spm_call_t* call);

/* Non-zero when the just-gated call must suspend its Secure Partition: a
 * psa_wait whose signals are not yet asserted. The coroutine layer blocks the
 * SP on this and re-gates the same wait when a later signal wakes it. */
int wt_spm_call_would_block(const wt_spm_call_t* call);

/* Transport a service loop's request to the gate. The direct transport calls
 * wt_spm_gate in the same privilege context (host tests, inline dispatch);
 * the ARMv8-M port installs an SVC transport so a scheduled unprivileged
 * partition traps to the privileged SPM instead. */
typedef int (*wt_spm_transport_fn)(wt_ffm_runtime_t* runtime,
                                   wt_spm_call_t* call);
int wt_spm_transport_direct(wt_ffm_runtime_t* runtime, wt_spm_call_t* call);
/* A service's transport before it is bound: on target a partition only
 * ever traps, so the direct transport is never linked there. */
#if defined(WT_TARGET_BUILD)
int wt_spm_svc_transport(wt_ffm_runtime_t* runtime, wt_spm_call_t* call);
#define WT_SPM_TRANSPORT_DEFAULT wt_spm_svc_transport
#else
#define WT_SPM_TRANSPORT_DEFAULT wt_spm_transport_direct
#endif
/* Runs every ready partition until none can progress: the scheduler on
 * target, the fixture's bound service loops on the host. */
void wt_spm_run(void);

/* SP dispatcher front half (cross-partition containment): wait for any
 * signal, absorb a doorbell before it can reach psa_get (a peer's psa_notify
 * is not a queued message, and an unfiltered mask would be a must-panic
 * programmer error the notifier could trigger at will), and hand back
 * exactly one asserted service signal. *signal == 0 means nothing to get on
 * this pass. Production service partitions declare no interrupt signals, so
 * the surviving bits are service signals only. */
static inline int wt_spm_wait_service_signal(wt_spm_transport_fn transport,
    wt_ffm_runtime_t* runtime, int32_t partition_id, psa_signal_t* signal,
    uint32_t* ret_tick)
{
    wt_spm_call_t call = {0};
    psa_signal_t asserted = 0U;

    call.op = WT_SPM_OP_WAIT;
    call.partition_id = partition_id;
    call.signal_mask = PSA_WAIT_ANY;
    call.timeout = PSA_BLOCK;
    call.asserted = &asserted;
    if (transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (ret_tick != NULL) {
        *ret_tick = call.ret_tick;
    }
    if ((asserted & PSA_DOORBELL) != 0U) {
        wt_spm_call_t clear_call = {0};

        clear_call.op = WT_SPM_OP_CLEAR;
        clear_call.partition_id = partition_id;
        if (transport(runtime, &clear_call) != WT_FFM_SUCCESS ||
                clear_call.ret_int != WT_FFM_SUCCESS) {
            return WT_FFM_ERROR_STATE;
        }
        asserted &= (psa_signal_t)~PSA_DOORBELL;
    }
    /* psa_get takes exactly one signal; serve the lowest asserted. */
    *signal = asserted & (psa_signal_t)(0U - asserted);
    return WT_FFM_SUCCESS;
}

#endif /* WOLFTRUST_SPM_GATE_H */
