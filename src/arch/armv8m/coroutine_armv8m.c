/* coroutine_armv8m.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/arch/armv8m/context.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/static_assert.h"

#include <stddef.h>
#include <stdint.h>

extern void wt_platform_panic(void);

WT_STATIC_ASSERT(offsetof(struct wt_co, sp) == WT_CO_SP_OFFSET,
               "struct wt_co: sp must be at offset 0");
WT_STATIC_ASSERT(offsetof(struct wt_co, stack_base) == WT_CO_STACK_BASE_OFFSET,
               "struct wt_co: stack_base must be at offset 4");
WT_STATIC_ASSERT(offsetof(struct wt_co, unprivileged) == WT_CO_UNPRIV_OFFSET,
               "struct wt_co: unprivileged must match PendSV asm offset");
WT_STATIC_ASSERT(offsetof(struct wt_co, exc_return) == WT_CO_EXCRET_OFFSET,
               "struct wt_co: exc_return must match PendSV asm offset");
WT_STATIC_ASSERT(sizeof(uintptr_t) == 4,
               "wt_co struct layout assumes 32-bit pointers");

#define WT_EXC_RETURN_S_THREAD_MSP 0xFFFFFFF9u
#define WT_EXC_RETURN_S_THREAD_PSP 0xFFFFFFFDu

struct wt_co *g_wt_co_pendsv_target __attribute__((used));

#if defined(WT_SEAL_NEG_PROBE) && (WT_SEAL_NEG_PROBE != 0)
/* Seal negatives on the first unprivileged Secure Partition (target read back
 * from R5, so the trampoline touches no SPM memory): probe 1 overwrites its
 * own seal, probe 2 damages it before dispatch, probe 4 blocks with SP on it. */
#define WT_CTX_PROBE_MAGIC 0x00F9EDA5u
static uint8_t g_wt_ctx_probe_armed __attribute__((used)) = 1u;
#endif

__attribute__((naked))
static void wt_co_trampoline(void)
{
    /* An SP or guest entry must never return. Falling off the end is
     * per-partition misbehavior, so trap here instead of panicking the whole
     * system: the fault dispatcher quarantines just this coroutine under its
     * own restart policy, the same path a must-panic PROGRAMMER ERROR takes. */
    __asm__ volatile (
#if defined(WT_SEAL_NEG_PROBE) && (WT_SEAL_NEG_PROBE == 1)
        "movw r1, #0xEDA5       \n"
        "movt r1, #0x00F9       \n"
        "cmp  r5, r1            \n"
        "bne  2f                \n"
        /* PSP points at this stack's two seal words on first entry. */
        "movw r1, #0xFFF9       \n"
        "movt r1, #0xFFFF       \n"
        "str  r1, [sp, #0]      \n"
        "2:                     \n"
#endif
        "blx  r4                \n"
        "udf  #0x51             \n"
        "1: b 1b                \n"
    );
}

void wt_co_arch_init_stack(struct wt_co *co,
                           wt_co_entry_fn entry,
                           void *arg)
{
    uintptr_t sp = (uintptr_t)co->stack_base + co->stack_size;
    uint32_t *frame;

    sp &= ~(uintptr_t)7u;
    frame = (uint32_t *)sp;

    /* Two seal words keep the frame below them 8-byte aligned. */
    *--frame = WT_ARMV8M_STACK_SEAL;
    *--frame = WT_ARMV8M_STACK_SEAL;

    *--frame = 0x01000000u;                                 /* xPSR */
    *--frame = (uint32_t)(uintptr_t)(void *)wt_co_trampoline; /* PC */
    *--frame = 0u;                                          /* LR */
    *--frame = 0u;                                          /* R12 */
    *--frame = 0u;                                          /* R3 */
    *--frame = 0u;                                          /* R2 */
    *--frame = 0u;                                          /* R1 */
    *--frame = (uint32_t)(uintptr_t)arg;                    /* R0 */

    *--frame = 0u;                                          /* R11 */
    *--frame = 0u;                                          /* R10 */
    *--frame = 0u;                                          /* R9 */
    *--frame = 0u;                                          /* R8 */
    *--frame = 0u;                                          /* R7 */
    *--frame = 0u;                                          /* R6 */
    *--frame = 0u;                                          /* R5 */
    *--frame = (uint32_t)(uintptr_t)(void *)entry;          /* R4 */

    co->sp = (uintptr_t)frame;
    co->exc_return = WT_EXC_RETURN_S_THREAD_PSP;
}

/* Latched on every seal violation so silicon can read the cause over SWD. */
volatile uint32_t g_wt_seal_violation __attribute__((used));

static uint32_t *wt_co_seal_top(const struct wt_co *co)
{
    return (uint32_t *)(void *)
           (((uintptr_t)co->stack_base + co->stack_size) & ~(uintptr_t)7u);
}


/* The bootstrap runs on MSP_S and has no coroutine stack to check. */
static int wt_co_seal_intact(const struct wt_co *co)
{
    const uint32_t *top;

    if (co == NULL || co == &g_wt_co_bootstrap || co->stack_base == NULL) {
        return 1;
    }
    top = wt_co_seal_top(co);
    return (top[-1] == WT_ARMV8M_STACK_SEAL) &&
           (top[-2] == WT_ARMV8M_STACK_SEAL);
}

static void wt_co_seal_panic(void)
{
    g_wt_seal_violation = WT_ARMV8M_STACK_SEAL;
    /* BKPT 0x6E tells a seal violation apart from other panics. */
    __asm volatile("bkpt #0x6E");
    wt_platform_panic();
}

/* A coroutine is suspended while it is being dispatched, so only SPM-level
 * corruption can have changed its seal: that halts the platform. */
static void wt_co_check_seal_in(const struct wt_co *to)
{
    if (wt_co_seal_intact(to) == 0) {
        wt_co_seal_panic();
    }
}

#if defined(WT_SEAL_NEG_PROBE) && (WT_SEAL_NEG_PROBE == 4)
/* sealpivotneg: as the armed partition is switched out, re-stack its frame on
 * its stack top, as if it had parked SP there, so the frame covers the seal. */
static void wt_co_probe_pivot_out(const struct wt_co *co)
{
    uint32_t *frame;
    uint32_t *top;
    uint32_t ipsr;
    uint32_t psp;
    int i;

    __asm volatile("mrs %0, ipsr" : "=r"(ipsr));
    __asm volatile("mrs %0, psp" : "=r"(psp));
    if (g_wt_ctx_probe_armed == 0u || co == NULL || co->domain == NULL ||
        co->unprivileged == 0u || ipsr == 0u || psp == 0u) {
        return;
    }
    frame = (uint32_t *)(uintptr_t)psp;
    top = wt_co_seal_top(co) - 8;
    for (i = 0; i < 8; i++) {
        top[i] = frame[i];
    }
    __asm volatile("msr psp, %0" : : "r"(top));
    g_wt_ctx_probe_armed = 0u;
}
#endif

/* A partition that damaged its own seal is made to fault on resume, so the
 * normal partition recovery handles it and no other domain is affected. */
static void wt_co_check_seal_out(const struct wt_co *co)
{
    wt_trap_frame_t *frame;
    uint32_t *top;
    uint32_t ipsr;
    uint32_t psp;

#if defined(WT_SEAL_NEG_PROBE) && (WT_SEAL_NEG_PROBE == 4)
    wt_co_probe_pivot_out(co);
#endif
    if (wt_co_seal_intact(co) != 0) {
        return;
    }
    __asm volatile("mrs %0, ipsr" : "=r"(ipsr));
    __asm volatile("mrs %0, psp" : "=r"(psp));
    if (co->domain == NULL || co->unprivileged == 0u || ipsr == 0u ||
        psp == 0u) {
        wt_co_seal_panic();
    }
    g_wt_seal_violation = WT_ARMV8M_STACK_SEAL;
    top = wt_co_seal_top(co);
    frame = (wt_trap_frame_t *)(uintptr_t)psp;
    /* A frame stacked over the seal words is rebuilt just below them, or
     * restoring the seal would damage the frame and the resume would halt. */
    if (psp + sizeof(*frame) > (uintptr_t)&top[-2]) {
        frame = (wt_trap_frame_t *)((uintptr_t)&top[-2] - sizeof(*frame));
        frame->xpsr = 0x01000000u;
        __asm volatile("msr psp, %0" : : "r"(frame));
    }
    top[-1] = WT_ARMV8M_STACK_SEAL;
    top[-2] = WT_ARMV8M_STACK_SEAL;
    wt_arch_sp_redirect_to_panic_trap(frame);
}

/* When the target carries a Secure Partition domain, narrow the MPU to it
 * for the coroutine's run and reinstate the SPM whitelist once control is
 * back on the bootstrap stack. The thread-domain variant keeps PRIVDEFENA
 * on so the privileged SVC/PendSV/fault handlers retain background access
 * while the unprivileged partition thread sees only its mapped regions. */
void wt_co_arch_enter(struct wt_co *to)
{
    const struct wt_secure_domain *domain = to->domain;

    g_wt_co_pendsv_target = to;
#if defined(WT_SEAL_NEG_PROBE) && (WT_SEAL_NEG_PROBE == 1 || WT_SEAL_NEG_PROBE == 2)
    /* First dispatch is first entry, so this never edits a live frame. */
    if (g_wt_ctx_probe_armed != 0u && to != NULL && to->domain != NULL &&
        to->unprivileged != 0u) {
#if (WT_SEAL_NEG_PROBE == 2)
        wt_co_seal_top(to)[-2] = 0xFFFFFFF9u;
#else
        ((volatile uint32_t *)to->sp)[1] = WT_CTX_PROBE_MAGIC;
#endif
        g_wt_ctx_probe_armed = 0u;
    }
#endif
    wt_co_check_seal_in(to);
    if (domain != NULL) {
        wt_arch_program_sp_thread_domain(domain->regions,
                                             domain->region_count);
    }
    wt_co_arch_request_preempt();
    /* Reached again only after `to` yielded/faulted back to bootstrap. */
    if (domain != NULL) {
        wt_arch_restore_spm_domain();
    }
}

void wt_co_arch_leave(void)
{
    g_wt_co_pendsv_target = (struct wt_co *)0;
    wt_co_arch_request_preempt();
}

void wt_co_arch_request_preempt(void)
{
    volatile uint32_t *icsr = (volatile uint32_t *)0xE000ED04u;

    /* No pending target means the current coroutine is being switched out,
     * by a yield or by timer preemption. */
    if (g_wt_co_pendsv_target == (struct wt_co *)0) {
        wt_co_check_seal_out(g_wt_co_current);
    }
    *icsr = 0x10000000u;
    __asm__ volatile ("dsb 0xF\nisb 0xF" ::: "memory");
}

__attribute__((naked))
void SVC_Handler(void)
{
    __asm__ volatile (
        /* Every wolfTrust SVC comes from Secure state; anything else halts. */
        "tst  lr, #0x40                    \n"
        "beq  wt_platform_panic            \n"
        "tst  lr, #4                       \n"
        "ite  eq                           \n"
        "mrseq r2, msp                     \n"
        "mrsne r2, psp                     \n"
        "ldr  r3, [r2, #24]                \n"
        "ldrb r3, [r3, #-2]                \n"
        "cmp  r3, #0x7F                    \n"
        "bne  2f                           \n"
        /* Internal guest-return is privileged MSP-thread-only: a PSP-origin
         * caller is a Secure Partition attempting the scheduler's own SVC,
         * a PROGRAMMER ERROR that panics that partition alone. */
        "tst  lr, #4                       \n"
        "beq  wt_armv8m_svc_guest_return \n"
        "mov  r0, r2                       \n"
        "b    wt_spm_svc_reject            \n"
        "2:                                \n"
        "cmp  r3, #0x01                    \n"
        "bne  1f                           \n"
        /* SVC #1: Secure Partition psa_* request. r0 = exception frame so
         * the privileged dispatcher can read the call pointer from the
         * stacked r0; it returns via the preserved EXC_RETURN in lr. */
        "mov  r0, r2                       \n"
        "b    wt_spm_svc_entry             \n"
        "1:                                \n"
        "ldr  r0, =0xE000ED04             \n"
        "ldr  r1, =0x10000000             \n"
        "str  r1, [r0]                    \n"
        "dsb  0xF                         \n"
        "isb  0xF                         \n"
        "bx   lr                          \n"
    );
}

__attribute__((naked))
void PendSV_Handler(void)
{
    __asm__ volatile (
        "tst    lr, #4                                          \n"
        "beq    1f                                              \n"

        /* Leaving a tasklet: save R4-R11 onto PSP, remember the new SP and
         * the live EXC_RETURN. An NS exception that preempted the coroutine
         * stacked the extended signed context (DCRS clear); replaying a
         * hardcoded basic-frame EXC_RETURN on resume unstacks it as 8 words
         * and faults INVPC on silicon. */
        "mrs    r0, psp                                         \n"
        "stmdb  r0!, {r4-r11}                                   \n"
        "ldr    r1, =g_wt_co_current                            \n"
        "ldr    r2, [r1]                                        \n"
        "cbz    r2, 5f                                          \n"
        "str    r0, [r2, #" WT_CO_STR(WT_CO_SP_OFFSET) "]\n"
        "str    lr, [r2, #" WT_CO_STR(WT_CO_EXCRET_OFFSET) "]\n"
        "b      2f                                              \n"

        /* Entering from bootstrap: preserve bootstrap R4-R11 on MSP. */
        "1:                                                     \n"
        "push   {r4-r11}                                        \n"
        "ldr    r0, =g_wt_co_bootstrap                          \n"
        "mov    r1, sp                                          \n"
        "str    r1, [r0, #0]                                    \n"
        "str    lr, [r0, #" WT_CO_STR(WT_CO_EXCRET_OFFSET) "]\n"

        "2:                                                     \n"
        "ldr    r0, =g_wt_co_pendsv_target                      \n"
        "ldr    r2, [r0]                                        \n"
        "cbz    r2, 4f                                          \n"

        /* Restore the target tasklet frame and return using PSP_S. A
         * Secure Partition coroutine (unprivileged flag set) returns to
         * Thread mode with CONTROL.nPRIV=1; plain tasklets keep nPRIV=0. */
        "ldr    r0, [r2, #" WT_CO_STR(WT_CO_SP_OFFSET) "]\n"
        "ldmia  r0!, {r4-r11}                                   \n"
        "msr    psp, r0                                         \n"
        "ldr    r3, [r2, #" WT_CO_STR(WT_CO_STACK_BASE_OFFSET) "]\n"
        /* Reserve a 32-byte software-save band (plus the canary word and
         * 8-byte alignment) above stack_base. The save path's
         * "stmdb r0!, {r4-r11}" writes 32 bytes below PSP through r0, and
         * PSPLIM guards only SP-relative accesses, not r0-based stores; keeping
         * PSP >= stack_base + 40 keeps that save inside the coroutine's own
         * stack instead of underflowing into the adjacent partition. */
        "adds   r3, r3, #40                                     \n"
        "msr    psplim, r3                                      \n"
        "ldrb   r3, [r2, #" WT_CO_STR(WT_CO_UNPRIV_OFFSET) "]\n"
        "mrs    r1, control                                     \n"
        "bic    r1, r1, #1                                      \n"
        "orr    r1, r1, r3                                      \n"
        "msr    control, r1                                     \n"
        "isb                                                    \n"
        "ldr    r0, =g_wt_co_current                            \n"
        "str    r2, [r0]                                        \n"
        "ldr    lr, [r2, #" WT_CO_STR(WT_CO_EXCRET_OFFSET) "]\n"
        "bx     lr                                              \n"

        /* Resume bootstrap on MSP_S, always privileged. */
        "4:                                                     \n"
        "ldr    r0, =g_wt_co_current                            \n"
        "ldr    r1, =g_wt_co_bootstrap                          \n"
        "str    r1, [r0]                                        \n"
        "ldr    lr, [r1, #" WT_CO_STR(WT_CO_EXCRET_OFFSET) "]\n"
        "movs   r0, #0                                          \n"
        "msr    psplim, r0                                      \n"
        "mrs    r1, control                                     \n"
        "bic    r1, r1, #1                                      \n"
        "msr    control, r1                                     \n"
        "pop    {r4-r11}                                        \n"
        "bx     lr                                              \n"

        "5:                                                     \n"
        "b      wt_platform_panic                               \n"
    );
}
