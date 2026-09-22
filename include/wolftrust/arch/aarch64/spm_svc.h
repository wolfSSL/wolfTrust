/* spm_svc.h
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

/* Secure virtual instance (SVC) conventions between S-EL0 partitions and
 * the S-EL1 SPMC. FF-A function ids ride x0 as at any instance; the
 * wolfTrust partition-message hypercall (DEV-05) uses the OEM range. */

#ifndef WOLFTRUST_ARCH_AARCH64_SPM_SVC_H
#define WOLFTRUST_ARCH_AARCH64_SPM_SVC_H

#include "wolftrust/arch/aarch64/context.h"
#include "wolftrust/types.h"

#include <stddef.h>
#include <stdint.h>

/* The FF-A echo partition is built when the EL3 test driver drives it
 * (WT_EL3_TEST_DRIVER) or when a Normal-world guest does (WT_NS_GUEST_ECHO): it
 * is the direct-message target in both proofs. */
#if (defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)) || \
    (defined(WT_NS_GUEST_ECHO) && (WT_NS_GUEST_ECHO == 1))
#define WT_SPM_ECHO_SP 1
#endif

/* x0 = this id, x1 = wt_spm_call_t*, x8 = call->op; x0 = gate status out. */
#define WT_SPM_SVC_FID_CALL  0xC3800100u
/* Scheduler yield from a partition; x1 carries a token the SPMC records. */
#define WT_SPM_SVC_FID_YIELD 0xC3800101u
/* Test-timer service for the ACS platform layer: arm a Secure interrupt
 * (x1 = intid, x2 = deadline in milliseconds) or stop the caller's own. */
#define WT_SPM_SVC_FID_TIMER_ARM  0xC3800102u
#define WT_SPM_SVC_FID_TIMER_STOP 0xC3800103u

/* The para-virtual interrupt controls of the ACS partition support layer
 * (Hafnium's values), taken at the SVC gate: enable claims an interrupt for
 * the caller, get returns the id the last FFA_INTERRUPT delivered. */
#define WT_SPM_HVC_INTERRUPT_ENABLE     0xFF03u
#define WT_SPM_HVC_INTERRUPT_GET        0xFF04u
#define WT_SPM_HVC_INTERRUPT_DEACTIVATE 0xFF08u

/* Saved S-EL0 register state of one partition, indexed by coroutine id. */
typedef struct wt_sp_arch {
    wt_trap_frame_t frame;
} wt_sp_arch_t;

/* Set while an S-EL1 exception handler runs on a partition's behalf. */
extern volatile uint32_t g_wt_spm_handler_depth;
extern volatile uint64_t g_wt_spm_trap_spsr;
/* The frame of the exception being handled (valid while depth != 0). */
extern wt_trap_frame_t* volatile g_wt_spm_live_frame;
/* The partition whose exception is being handled (valid while depth != 0);
 * a partition it runs on its behalf (an SP-to-SP message) nests under it. */
struct wt_co;
extern struct wt_co* volatile g_wt_spm_handler_co;

void wt_spm_sp_panic_trap(void);
void wt_spm_idle(void) __attribute__((noreturn));

/* Load frame into the S-EL0 state and ERET; returns when the partition's
 * exception handler unwinds back through wt_sp_el0_leave. */
void wt_sp_el0_enter(wt_trap_frame_t* frame);
void wt_sp_el0_leave(void) __attribute__((noreturn));
void wt_spm_lower_sync(wt_trap_frame_t* frame);
uint64_t wt_spm_yield_token(void);

/* Set once the core owns the partitions: the first block of each S-EL0
 * coroutine then counts as that partition's initialization. */
extern volatile uint32_t g_wt_spm_partitions_live;
uint32_t wt_spm_sp_init_count(void);

/* FF-A endpoint identity of the S-EL0 partitions, and whether one is still in
 * its initialization (before its first block). */
uint16_t wt_spm_sp_ffa_id(const struct wt_co* co);
struct wt_co* wt_spm_sp_by_ffa_id(uint16_t id);
int wt_spm_sp_initializing(const struct wt_co* co);

/* The boot handoff record the FF-A boot information named, if any. */
extern uintptr_t g_wt_spm_handoff_pa;
extern size_t g_wt_spm_handoff_size;
void wt_spm_init_partitions(void);

/* FF-A direct messaging at the Secure virtual instance. A partition that has
 * blocked in FFA_MSG_WAIT is delivered a request by loading it into the saved
 * x0-x7 of its frame and resuming it; its FFA_MSG_SEND_DIRECT_RESP is captured
 * here by the gate before the partition blocks again. */
extern uint64_t g_wt_ffa_direct_resp[18];
extern volatile uint32_t g_wt_ffa_direct_resp_ready;

/* S-EL0 echo partition (sp_entry.S): replies to each direct request with the
 * ids swapped and the first payload word complemented. */
void wt_sp_ffa_echo(void);

/* S-EL0 discovery partition (sp_entry.S): calls FFA_PARTITION_INFO_GET with a
 * Nil UUID (RX base in x0) and yields the match count and first id. */
void wt_sp_ffa_discover(void);

/* S-EL0 memory-sharing borrower (sp_entry.S): x0 = argument block {handle,
 * shared page base, TX base, retrieve request length, own id}. Retrieves the
 * shared page, reads its seeded bytes and writes a reply byte at S-EL0, yields
 * the bytes, relinquishes the page, and yields the status. */
void wt_sp_ffa_borrow(void);

/* Preemption of a running S-EL0 partition by the scheduling tick: the lower-EL
 * FIQ handler saves the partition's frame, marks it runnable, and unwinds to
 * the scheduler. wt_sp_spin is an S-EL0 partition that never blocks, used by
 * the boot self-test to prove a spinning partition is preempted. */
void wt_spm_preempt_from_fiq(wt_trap_frame_t* frame);
void wt_spm_preempt_timer_arm(void);
void wt_spm_preempt_timer_stop(void);
void wt_sp_spin(void);

/* Deliver req (x0..x17 as at FFA_MSG_WAIT's return) to a waiting partition,
 * run it until it responds or yields, and copy the response (or FFA_YIELD)
 * into resp. 0 on success; BUSY if it is not waiting, ABORTED if it faulted,
 * DENIED if it blocked without responding. */
struct wt_co;
int wt_spm_ffa_direct_deliver(struct wt_co* co, const uint64_t* req,
                              uint64_t* resp);

/* How a running endpoint handed the CPU back; the gate sets it before it
 * blocks the partition, the invoker consumes it. */
#define WT_FFA_SP_EXIT_NONE  0u
#define WT_FFA_SP_EXIT_RESP  1u
#define WT_FFA_SP_EXIT_WAIT  2u
#define WT_FFA_SP_EXIT_YIELD 3u
#define WT_FFA_SP_EXIT_CALL  4u
/* A Normal-world interrupt preempted the partition (Ch.9 NS-Int signaled):
 * the invoker sees FFA_INTERRUPT and resumes it later with FFA_RUN. */
#define WT_FFA_SP_EXIT_NSINT 5u
/* The run loop stopped a preempted partition so a waiting one could be
 * signaled first; the stopped one resumes afterwards. */
#define WT_FFA_SP_EXIT_SIGNAL 6u
extern volatile uint32_t g_wt_ffa_sp_exit;

/* FFA_RUN on behalf of caller; out is what the caller's FFA_RUN returns. */
int wt_spm_ffa_run(struct wt_co* co, uint16_t caller, uint64_t* out);
/* Arm target for caller's direct request (req) or FFA_RUN (req == NULL); on 0
 * the gate blocks the caller with WT_FFA_SP_EXIT_CALL. */
int wt_spm_ffa_sp_call(const struct wt_co* caller, struct wt_co* target,
                       const uint64_t* req);
/* Non-zero while co processes a direct request, with the request's ids. */
int wt_spm_ffa_sp_requester(const struct wt_co* co, uint16_t* requester,
                            uint16_t* self);
/* Non-zero if the request co processes arrived as FFA_MSG_SEND_DIRECT_REQ2. */
int wt_spm_ffa_sp_req2(const struct wt_co* co);
/* Non-zero if co yielded inside a direct request caller sent it. */
int wt_spm_ffa_sp_yielded_to(const struct wt_co* co, uint16_t caller);

/* Secure interrupt routing to a partition (Ch.9, Table 9.1): a declared Secure
 * interrupt is signalled to its owner with FFA_INTERRUPT while the owner waits,
 * or queued while it runs and delivered on its next FFA_MSG_WAIT. */
int wt_spm_ffa_signal_deliver(struct wt_co* co, uint32_t intid);
void wt_spm_sint_queue(uint32_t intid);
void wt_spm_sint_queue_for(struct wt_co* co, uint32_t intid);
uint32_t wt_spm_sint_take_pending(const struct wt_co* co);
extern volatile uint32_t g_wt_spm_sint_queued;
void wt_spm_prove_sint_route(struct wt_co* co);

/* Dynamic Secure-interrupt ownership, claimed through the para-virtual
 * enable; the id the last FFA_INTERRUPT delivered answers the get. */
int wt_spm_sint_own(struct wt_co* co, uint32_t intid, unsigned int enable);
struct wt_co* wt_spm_sint_owner(uint32_t intid);
void wt_spm_sint_set_delivered(const struct wt_co* co, uint32_t intid);
uint32_t wt_spm_sint_delivered(const struct wt_co* co);
/* Non-zero when owner waits while another partition runs, so the SPMC must
 * preempt that partition to signal the owner (Table 9.1). */
int wt_spm_sint_signal_needed(struct wt_co* owner);

/* A Normal-world Group 1 interrupt asserted while a partition ran. */
void wt_spm_preempt_from_irq(wt_trap_frame_t* frame);

/* The test-timer service: arm makes the interrupt pending at its deadline
 * (see spm_irq.c for when a Normal-world one lands); stop clears the caller's
 * own timers (owner NULL for the Normal world's). */
int wt_spm_twdog_arm(uint32_t intid, uint32_t ms);
void wt_spm_twdog_stop(const struct wt_co* owner);
void wt_spm_twdog_tick(void);
int wt_spm_current_is_partition(void);

/* FFA_PARTITION_INFO_GET for either instance; see spm_svc_glue.c. */
struct wt_ffa_mailbox;
int wt_spm_partition_info(const uint64_t* x, struct wt_ffa_mailbox* mb,
                          uint8_t* rx, uint32_t* count, uint32_t* size);
int wt_spm_partition_info_regs(const uint64_t* x, uint64_t* out18);

/* FF-A native partitions: separately built S-EL0 images that speak FF-A
 * directly rather than hosting an FF-M service (the FF-A ACS endpoints). The
 * port lists them; the SPMC maps each one's regions, enters it at its entry,
 * and reports it through FFA_PARTITION_INFO_GET. Conformance builds only. */
#define WT_FFA_NATIVE_SP_MAX     4u
#define WT_FFA_NATIVE_SP_REGIONS 4u

typedef struct wt_ffa_native_sp {
    uintptr_t entry;
    uintptr_t stack_base;
    size_t stack_size;
    wt_memory_region_t regions[WT_FFA_NATIVE_SP_REGIONS];
    size_t region_count;
    uint8_t uuid[16];
    uint32_t properties;
    /* FF-A "Action in response to a Non-secure interrupt": 0 queued (masked
     * while the partition runs), 2 signaled (preempts to the Normal world). */
    uint8_t ns_int_action;
} wt_ffa_native_sp_t;

const wt_ffa_native_sp_t* wt_platform_ffa_native_partitions(size_t* count);
const wt_ffa_native_sp_t* wt_spm_ffa_native_list(size_t* count);
struct wt_co* wt_spm_ffa_native_by_id(uint16_t id);
uint16_t wt_spm_ffa_native_id(size_t index);

/* A partition's RX/TX pair as the SVC gate registered it, for a producer
 * delivering into its RX; NULL when the slot has none. */
struct wt_ffa_mailbox* wt_spm_sp_mailbox_of(const struct wt_co* co);

/* FFA_MSG_SEND2 delivery from either conduit: validate the partition message
 * in the caller's TX and copy it into the receiver's RX. */
int wt_spm_msg2_deliver(uint16_t caller, const uint8_t* tx, uint32_t tx_size,
                        uint32_t w1, uint32_t w2);

/* The test echo partition (WT_FFA_ID_ECHO), NULL unless WT_EL3_TEST_DRIVER=1.
 * enable_mmu publishes its stack band (the slot after the last manifest
 * partition stack) and the init pass builds the partition on it. */
struct wt_co* wt_spm_ffa_echo_partition(void);
extern uintptr_t g_wt_spm_echo_stack_base;
extern uintptr_t g_wt_spm_echo_stack_size;

#endif /* WOLFTRUST_ARCH_AARCH64_SPM_SVC_H */
