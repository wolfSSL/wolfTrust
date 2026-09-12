/* sp_trap.c
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

/* SP-side half of the SVC gate: the partition-message hypercall and the
 * deliberate faults the gate contract owes the architecture. */

#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch.h"
#include "wolftrust/spm_gate.h"

#include <stdint.h>

int wt_arch_sp_trap(wt_spm_call_t* call)
{
    register uint64_t x0 __asm__("x0") = WT_SPM_SVC_FID_CALL;
    register uint64_t x1 __asm__("x1") = (uint64_t)(uintptr_t)call;
    register uint64_t x8 __asm__("x8") = (uint64_t)call->op;

    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return (int)(int32_t)x0;
}

/* Landing pad for an FF-M PROGRAMMER ERROR: a permanently undefined
 * instruction at EL0 takes the graceful quarantine path (EC 0x00). */
__attribute__((naked, used))
void wt_spm_sp_panic_trap(void)
{
    __asm__ volatile(".inst 0x00000000");
}

void wt_arch_sp_fault_probe(unsigned int code)
{
    switch (code) {
    case 1u:
        __asm__ volatile("brk #1");
        break;
    case 2u:
        __asm__ volatile("brk #2");
        break;
    case 3u:
        __asm__ volatile("brk #3");
        break;
    case 4u:
        __asm__ volatile("brk #4");
        break;
    default:
        __asm__ volatile(".inst 0x00000000");
        break;
    }
}

/* Pin the diagnostics into callee-saved registers the fault dump shows. */
__attribute__((noreturn, noinline))
void wt_arch_sp_panic(uint32_t op, uint32_t code, uint32_t extra)
{
    register uint64_t diag_op __asm__("x19") = op;
    register uint64_t diag_code __asm__("x20") = code;
    register uint64_t diag_extra __asm__("x21") = extra;

    __asm__ volatile("brk #0xF0" : : "r"(diag_op), "r"(diag_code),
                     "r"(diag_extra));
    for (;;) {
    }
}

__attribute__((noinline))
void wt_arch_diag_trap(uint32_t a, uint32_t b, uint32_t c)
{
    register uint64_t diag_a __asm__("x19") = a;
    register uint64_t diag_b __asm__("x20") = b;
    register uint64_t diag_c __asm__("x21") = c;

#if defined(WT_CONF_DIAG_TRAP) && (WT_CONF_DIAG_TRAP == 0)
    (void)diag_a;
    (void)diag_b;
    (void)diag_c;
#else
    __asm__ volatile("brk #0xF1" : : "r"(diag_a), "r"(diag_b), "r"(diag_c));
#endif
}

int wt_arch_thread_unprivileged(void)
{
    uint64_t id;

    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(id));
    return (id != 0u) ? 1 : 0;
}
