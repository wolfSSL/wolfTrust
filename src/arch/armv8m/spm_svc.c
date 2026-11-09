/* spm_svc.c
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

/* Armv8-M SVC #1 transport: the privileged frame decoder in front of the
 * neutral gate dispatch, the SP-side trap, and the trap-level primitives the
 * architecture contract owes the gate (stack forensics, panic redirect,
 * deliberate faults, privilege assertion, diagnostic trap). */

#include "wolftrust/arch/armv8m/spm_svc.h"
#include "wolftrust/arch/armv8m/context.h"

#include "wolftrust/arch.h"
#include "wolftrust/ffm.h"
#include "wolftrust/platform.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Production landing pad for an FF-M PROGRAMMER ERROR: the SVC dispatcher
 * points the erring partition's resume PC here so it faults on an undefined
 * instruction and takes the graceful quarantine path (WT-SYS-0008). */
__attribute__((naked, used))
static void wt_spm_sp_panic_trap(void)
{
    __asm volatile("udf #0x50");
}

#if defined(WT_XN_NEG_PROBE) && (WT_XN_NEG_PROBE == 1)
static uint16_t g_wt_xn_probe_thunk[2] __attribute__((aligned(4)));
static uint8_t g_wt_xn_probe_fired;

/* xnneg: call a `bx lr` thunk placed in SPM .bss from the privileged gate,
 * under the caller's thread domain; the execute-never cover must fault it
 * (IACCVIOL) before it returns, or the udf marks the escape. */
static void wt_spm_xn_probe(void)
{
    void (*thunk)(void);

    if (g_wt_xn_probe_fired != 0u) {
        return;
    }
    g_wt_xn_probe_fired = 1u;
    g_wt_xn_probe_thunk[0] = 0x4770u;
    g_wt_xn_probe_thunk[1] = 0xBF00u;
    __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    thunk = (void (*)(void))((uintptr_t)g_wt_xn_probe_thunk | 1u);
    thunk();
    __asm volatile("udf #0x52");
}
#endif

/* Tail-called from SVC_Handler with r0 = the exception frame; the stacked r0
 * carries the call block in and the gate-level status out. */
__attribute__((used))
void wt_spm_svc_entry(uint32_t* frame)
{
    wt_spm_call_t* call = (wt_spm_call_t*)(uintptr_t)frame[0];

#if defined(WT_XN_NEG_PROBE) && (WT_XN_NEG_PROBE == 1)
    wt_spm_xn_probe();
#endif
    frame[0] = (uint32_t)wt_spm_dispatch_call(call, (wt_trap_frame_t*)frame);
}

/* A partition issued the scheduler's own SVC: resume it on the panic trap so
 * it is quarantined under its policy instead of halting the platform. */
__attribute__((used))
void wt_spm_svc_reject(uint32_t* frame)
{
    wt_arch_sp_redirect_to_panic_trap((wt_trap_frame_t*)frame);
}

#if defined(WT_SVC_NEG_PROBE) && (WT_SVC_NEG_PROBE == 1)
void wt_arch_sp_guest_return_probe(void)
{
    __asm volatile("svc #0x7F");
}
#endif

uintptr_t wt_arch_sp_stack_pointer(void)
{
    uint32_t psp;

    __asm volatile("mrs %0, psp" : "=r"(psp));
    return psp;
}

void wt_arch_sp_redirect_to_panic_trap(wt_trap_frame_t* frame)
{
    frame->pc = (uint32_t)(uintptr_t)&wt_spm_sp_panic_trap & ~1u;
    /* Clear EPSR ICI/IT so the redirected resume executes the trap. */
    frame->xpsr &= ~0x0600FC00u;
}

void wt_arch_assert_privileged_thread(void)
{
    uint32_t ctrl;

    __asm volatile("mrs %0, control" : "=r"(ctrl));
    if ((ctrl & 1u) != 0u) {
        ctrl &= ~1u;
        __asm volatile("msr control, %0\n isb" : : "r"(ctrl));
    }
}

/* Deliberate undefined-instruction faults keyed by the test-build probes;
 * the immediate is what the fault dump shows. */
void wt_arch_sp_fault_probe(unsigned int code)
{
#if defined(WT_FP_NEG_PROBE) && (WT_FP_NEG_PROBE == 1)
    /* fpneg: with Secure FP disabled the FP instruction (raw-encoded, since
     * -mgeneral-regs-only refuses the mnemonic) takes a NOCP UsageFault;
     * reaching the udf means FP was still enabled. */
    __asm volatile(".inst.w 0xee000a10");   /* vmov s0, r0 */
    __asm volatile("udf #0x4E");
    return;
#endif
    switch (code) {
    case 1u:
        __asm volatile("udf #1");
        break;
    case 2u:
        __asm volatile("udf #2");
        break;
    case 3u:
        __asm volatile("udf #3");
        break;
    case 4u:
        __asm volatile("udf #4");
        break;
    default:
        __asm volatile("udf #0");
        break;
    }
}

/* A failed service-side call is a programmer error: fault the partition so
 * the SPM's fault path deals with it instead of running on bad state. The
 * faulting read also identifies the failing wrapper in the emulator's
 * register dump (PC/LR) — a silent spin here is undebuggable on target. */
__attribute__((noreturn, noinline))
void wt_arch_sp_panic(uint32_t op, uint32_t code, uint32_t extra)
{
    /* Pin the diagnostics into callee-saved registers the fault dump prints;
     * plain unused params get optimized out of the call sites entirely. */
    register uint32_t diag_op __asm__("r4") = op;
    register uint32_t diag_code __asm__("r5") = code;
    register uint32_t diag_extra __asm__("r6") = extra;
    volatile uint32_t probe;

    __asm__ volatile("" : : "r"(diag_op), "r"(diag_code), "r"(diag_extra));
    probe = *(const volatile uint32_t*)0xEFFFFFF4u;
    (void)probe;
    for (;;) {
    }
}

/* r0 = call in, r0 = gate-level status out (written into the stacked frame
 * by the privileged dispatcher). */
__attribute__((naked))
int wt_arch_sp_trap(wt_spm_call_t* call __attribute__((unused)))
{
    __asm__ volatile (
        "svc  #1   \n"
        "bx   lr   \n"
    );
}

int wt_arch_thread_unprivileged(void)
{
    unsigned int control;
    unsigned int ipsr;
    __asm volatile("mrs %0, control" : "=r"(control));
    __asm volatile("mrs %0, ipsr" : "=r"(ipsr));
    return (int)(ipsr == 0u && (control & 1u) != 0u);
}

/* Diagnostic trap for a scheduler livelock: pack the scheduler state into the
 * exception frame's r0-r2 (the emulator's MEMFAULT dump prints them) and
 * fault on purpose. Removed once the multi-SP dance is proven. */
__attribute__((noinline))
void wt_arch_diag_trap(uint32_t a, uint32_t b, uint32_t c)
{
    /* Pin the scheduler state into callee-saved registers the emulator's
     * fault dump prints; the 0xEFFFFFF4 read faults with a full dump. */
    register uint32_t diag_a __asm__("r4") = a;
    register uint32_t diag_b __asm__("r5") = b;
    register uint32_t diag_c __asm__("r6") = c;
#if defined(WT_CONF_DIAG_TRAP) && (WT_CONF_DIAG_TRAP != 0)
    volatile uint32_t probe;
#endif

#if !defined(WT_CONF_DIAG_TRAP) || (WT_CONF_DIAG_TRAP == 0)
    /* Production and hardware: no fault-dump printer exists, and the fault
     * would halt the platform (or, under conformance, reset into the suite's
     * report window), so the caller's error return must run instead. */
    (void)diag_a; (void)diag_b; (void)diag_c;
    return;
#else
    __asm__ volatile("" : : "r"(diag_a), "r"(diag_b), "r"(diag_c));
    probe = *(const volatile uint32_t*)0xEFFFFFF4u;
    (void)probe;
#endif
}

