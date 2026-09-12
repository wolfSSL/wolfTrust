/* platform_arch.c
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

/* The wt_arch_* contract at S-EL1 minus the domain ops (domain.c): the
 * Secure-side operations are real, the Non-secure ones fail closed until
 * the NS gateway lands. */

#include "wolftrust/arch/aarch64/context.h"
#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch.h"
#include "wolftrust/platform.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

volatile uint32_t g_wt_spm_handler_depth;
volatile uint64_t g_wt_spm_trap_spsr;

void wt_arch_init(void)
{
}

void wt_arch_start_secure_timer(uint32_t timeslice_ms)
{
    wt_el3_timer_arm_ms(timeslice_ms);
}

void wt_arch_mask_all_guest_irqs(void)
{
}

void wt_arch_apply_irq_mask(const wt_irq_mask_t* mask)
{
    (void)mask;
}

void wt_arch_quarantine_pending_irqs(const wt_irq_mask_t* allowed_mask)
{
    (void)allowed_mask;
}

void wt_arch_program_guest_domain(const wt_memory_region_t* regions,
                                  size_t count)
{
    (void)regions;
    (void)count;
}

void wt_arch_guest_context_prepare(wt_guest_id_t guest_id,
                                   const wt_guest_context_t* context)
{
    (void)guest_id;
    (void)context;
}

void wt_arch_guest_context_capture(wt_guest_context_t* context,
                                   const wt_trap_frame_t* frame)
{
    unsigned int i;

    if (context == NULL || frame == NULL) {
        return;
    }
    for (i = 0u; i < 31u; i++) {
        context->x[i] = frame->x[i];
    }
    context->sp_el0 = frame->sp_el0;
    context->elr = frame->elr;
    context->spsr = frame->spsr;
    context->pc = (uintptr_t)frame->elr;
    context->frame_stacked = true;
}

/* No Normal world yet: dispatching a guest means handing the CPU back to
 * the SPMD and waiting for FF-A events. */
void wt_arch_guest_context_restore(wt_guest_context_t* context)
{
    (void)context;
    wt_spm_idle();
}

bool wt_arch_guest_context_ready(const wt_guest_context_t* context)
{
    return (context != NULL) && (context->pc != 0u);
}

uintptr_t wt_arch_trap_pc(const wt_trap_frame_t* frame)
{
    return (frame != NULL) ? (uintptr_t)frame->elr : 0u;
}

uint32_t wt_arch_active_guest_id(void)
{
    return 0u;
}

void wt_arch_zero_guest_memory(uintptr_t base, size_t size)
{
    if (base != 0u && size != 0u) {
        (void)memset((void*)base, 0, size);
    }
}

void wt_arch_restore_guest_bank(const wt_guest_context_t* context)
{
    (void)context;
}

bool wt_arch_in_handler_mode(void)
{
    return g_wt_spm_handler_depth != 0u;
}

bool wt_arch_trap_from_guest_thread(void)
{
    return false;
}

bool wt_arch_trap_from_secure_thread(void)
{
    return (g_wt_spm_handler_depth != 0u) &&
           ((g_wt_spm_trap_spsr & 0xFu) == 0u);
}

void wt_arch_return_to_secure_thread(void (*entry)(void)
                                     __attribute__((noreturn)))
{
    (void)entry;
    wt_platform_panic();
}

uintptr_t wt_arch_read_fault_address(void)
{
    uint64_t far;

    __asm__ volatile("mrs %0, FAR_EL1" : "=r"(far));
    return (uintptr_t)far;
}

void wt_arch_secure_irq_enable(uint32_t irq)
{
    wt_gic->enable(irq);
}

void wt_arch_secure_irq_disable(uint32_t irq)
{
    wt_gic->disable(irq);
}

void wt_arch_route_irq_to_guest(uint32_t irq)
{
    (void)irq;
}

void wt_arch_set_guest_irq_pending(uint32_t irq, bool asserted)
{
    (void)irq;
    (void)asserted;
}

void wt_arch_dmb(void)
{
    __asm__ volatile("dmb sy" ::: "memory");
}

void wt_arch_dsb(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

uintptr_t wt_arch_sp_stack_pointer(void)
{
    uint64_t sp;

    __asm__ volatile("mrs %0, SP_EL0" : "=r"(sp));
    return (uintptr_t)sp;
}

void wt_arch_sp_redirect_to_panic_trap(wt_trap_frame_t* frame)
{
    if (frame != NULL) {
        frame->elr = (uint64_t)(uintptr_t)&wt_spm_sp_panic_trap;
    }
}

void wt_arch_assert_privileged_thread(void)
{
}

int wt_arch_ns_check_read(wt_guest_id_t guest_id, const void* address,
                          size_t size)
{
    (void)guest_id;
    (void)address;
    (void)size;
    return -1;
}

int wt_arch_ns_check_write(wt_guest_id_t guest_id, void* address, size_t size)
{
    (void)guest_id;
    (void)address;
    (void)size;
    return -1;
}

int wt_arch_ns_check_writable(const void* address, size_t size)
{
    (void)address;
    (void)size;
    return -1;
}
