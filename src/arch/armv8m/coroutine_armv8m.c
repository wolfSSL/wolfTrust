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
#include "wolftrust/static_assert.h"

#include <stddef.h>
#include <stdint.h>

extern void wt_platform_panic(void);

#define WT_CO_SP_OFFSET         0
#define WT_CO_STACK_BASE_OFFSET 4
#define WT_CO_UNPRIV_OFFSET     40
#define WT_CO_EXCRET_OFFSET     44

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

__attribute__((naked))
static void wt_co_trampoline(void)
{
    /* An SP or guest entry must never return. Falling off the end is
     * per-partition misbehavior, so trap here instead of panicking the whole
     * system: the fault dispatcher quarantines just this coroutine under its
     * own restart policy, the same path a must-panic PROGRAMMER ERROR takes. */
    __asm__ volatile (
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

/* When the target carries a Secure Partition domain, narrow the MPU to it
 * for the coroutine's run and reinstate the SPM whitelist once control is
 * back on the bootstrap stack. The thread-domain variant keeps PRIVDEFENA
 * on so the privileged SVC/PendSV/fault handlers retain background access
 * while the unprivileged partition thread sees only its mapped regions. */
void wt_co_arch_enter(struct wt_co *to)
{
    const struct wt_secure_domain *domain = to->domain;

    g_wt_co_pendsv_target = to;
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

    *icsr = 0x10000000u;
    __asm__ volatile ("dsb 0xF\nisb 0xF" ::: "memory");
}

__attribute__((naked))
void SVC_Handler(void)
{
    __asm__ volatile (
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
         * which fails the platform closed instead of restoring SPM state. */
        "tst  lr, #4                       \n"
        "beq  wt_armv8m_svc_guest_return \n"
        "b    wt_platform_panic            \n"
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
        "str    r0, [r2, #" "0" "]                              \n"
        "str    lr, [r2, #" "44" "]                             \n"
        "b      2f                                              \n"

        /* Entering from bootstrap: preserve bootstrap R4-R11 on MSP. */
        "1:                                                     \n"
        "push   {r4-r11}                                        \n"
        "ldr    r0, =g_wt_co_bootstrap                          \n"
        "mov    r1, sp                                          \n"
        "str    r1, [r0, #0]                                    \n"
        "str    lr, [r0, #" "44" "]                             \n"

        "2:                                                     \n"
        "ldr    r0, =g_wt_co_pendsv_target                      \n"
        "ldr    r2, [r0]                                        \n"
        "cbz    r2, 4f                                          \n"

        /* Restore the target tasklet frame and return using PSP_S. A
         * Secure Partition coroutine (unprivileged flag set) returns to
         * Thread mode with CONTROL.nPRIV=1; plain tasklets keep nPRIV=0. */
        "ldr    r0, [r2, #" "0" "]                              \n"
        "ldmia  r0!, {r4-r11}                                   \n"
        "msr    psp, r0                                         \n"
        "ldr    r3, [r2, #" "4" "]                              \n"
        /* Reserve a 32-byte software-save band (plus the canary word and
         * 8-byte alignment) above stack_base. The save path's
         * "stmdb r0!, {r4-r11}" writes 32 bytes below PSP through r0, and
         * PSPLIM guards only SP-relative accesses, not r0-based stores; keeping
         * PSP >= stack_base + 40 keeps that save inside the coroutine's own
         * stack instead of underflowing into the adjacent partition. */
        "adds   r3, r3, #40                                     \n"
        "msr    psplim, r3                                      \n"
        "ldrb   r3, [r2, #" "40" "]                             \n"
        "mrs    r1, control                                     \n"
        "bic    r1, r1, #1                                      \n"
        "orr    r1, r1, r3                                      \n"
        "msr    control, r1                                     \n"
        "isb                                                    \n"
        "ldr    r0, =g_wt_co_current                            \n"
        "str    r2, [r0]                                        \n"
        "ldr    lr, [r2, #" "44" "]                             \n"
        "bx     lr                                              \n"

        /* Resume bootstrap on MSP_S, always privileged. */
        "4:                                                     \n"
        "ldr    r0, =g_wt_co_current                            \n"
        "ldr    r1, =g_wt_co_bootstrap                          \n"
        "str    r1, [r0]                                        \n"
        "ldr    lr, [r1, #" "44" "]                             \n"
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
