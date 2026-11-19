/* arch.h
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

#ifndef WOLFTRUST_ARCH_H
#define WOLFTRUST_ARCH_H

/* Architecture contract, implemented once under src/arch/<arch>/. */

#include "wolftrust/platform.h"

/* Called by wt_platform_init once the fabric and memory windows are set. */
void wt_arch_init(void);
void wt_arch_start_secure_timer(uint32_t timeslice_ms);
void wt_arch_mask_all_guest_irqs(void);
void wt_arch_read_guest_irq_enables(wt_irq_mask_t* out);
void wt_arch_apply_irq_mask(const wt_irq_mask_t* mask);
void wt_arch_quarantine_pending_irqs(const wt_irq_mask_t* allowed_mask);

/* Only asked of ports providing WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING. */
void wt_arch_program_guest_domain(const wt_memory_region_t* regions,
                                  size_t count);
void wt_arch_program_secure_partition_domain(
    const wt_memory_region_t* regions, size_t count);
/* Same regions, but privileged handlers keep default access. */
void wt_arch_program_sp_thread_domain(const wt_memory_region_t* regions,
                                      size_t count);
void wt_arch_restore_spm_domain(void);

void wt_arch_guest_context_prepare(wt_guest_id_t guest_id,
                                   const wt_guest_context_t* context);
void wt_arch_guest_context_capture(wt_guest_context_t* context,
                                   const wt_trap_frame_t* frame);
void wt_arch_guest_context_restore(wt_guest_context_t* context);
bool wt_arch_guest_context_ready(const wt_guest_context_t* context);
uintptr_t wt_arch_trap_pc(const wt_trap_frame_t* frame);
/* UINT32_MAX when no guest is running; never trust a guest-supplied id. */
uint32_t wt_arch_active_guest_id(void);
void wt_arch_zero_guest_memory(uintptr_t base, size_t size);
/* Return a partition's data band to its link-time image: zero it, then
 * reload the .data the image carries for it. */
void wt_arch_sp_band_reset(uintptr_t base, size_t size);
/* The blocked-tasklet resume path skips the normal context restore. */
void wt_arch_restore_guest_bank(const wt_guest_context_t* context);

bool wt_arch_in_handler_mode(void);
bool wt_arch_trap_from_guest_thread(void);
bool wt_arch_trap_from_secure_thread(void);
/* True when the interrupted context was a guest in Non-secure Handler mode. */
bool wt_arch_trap_from_guest_handler(void);
/* True when the interrupted context was Secure code in Handler mode. */
bool wt_arch_trap_from_secure_handler(void);
/* True when the interrupted context was Secure Thread code on MSP, the
 * gateway's own context, never a partition coroutine on PSP. */
bool wt_arch_trap_from_secure_main_thread(void);
/* Clear the Non-secure exception state a guest abandoned in Handler mode; a
 * later exit retires its active IRQs. */
void wt_arch_guest_abandon_handler(void);
/* True while a Non-secure IRQ is active and not queued for retirement. */
bool wt_arch_guest_irq_active(void);
/* True while an abandoned Non-secure IRQ still waits for its retiring exit. */
bool wt_arch_guest_retire_pending(void);
/* Clear the Non-secure system-handler active bits before a guest switch. */
void wt_arch_guest_drop_handler_active(void);
void wt_arch_return_to_secure_thread(
    void (*entry)(void) __attribute__((noreturn)));
/* Discard the departing handler stack before entering the idle scheduler. */
void wt_arch_return_to_idle_thread(
    void (*entry)(void) __attribute__((noreturn))) __attribute__((noreturn));
void wt_arch_wait_for_interrupt(void);

uintptr_t wt_arch_read_fault_address(void);

/* Nonzero when [base, base + size) overlaps a range the architecture's
 * default memory map treats as peripheral, device, or system space. */
int wt_arch_range_is_mmio(uintptr_t base, size_t size);

/* Disable, clear, and route a partition's line to Secure, then read it back
 * (WT-FFM-0069). Nonzero when the line is out of range or did not stick. */
int wt_arch_secure_irq_claim(uint32_t irq);
void wt_arch_secure_irq_enable(uint32_t irq);
void wt_arch_secure_irq_disable(uint32_t irq);
void wt_arch_route_irq_to_guest(uint32_t irq);
void wt_arch_set_guest_irq_pending(uint32_t irq, bool asserted);

/* No-ops on host builds. */
void wt_arch_dmb(void);
void wt_arch_dsb(void);

struct wt_spm_call;
int wt_arch_sp_trap(struct wt_spm_call* call);
uintptr_t wt_arch_sp_stack_pointer(void);
/* FF-M PROGRAMMER ERROR: resume the partition on a trap that quarantines it. */
void wt_arch_sp_redirect_to_panic_trap(wt_trap_frame_t* frame);
void wt_arch_assert_privileged_thread(void);
void wt_arch_sp_fault_probe(unsigned int code);
#if defined(WT_SVC_NEG_PROBE) && (WT_SVC_NEG_PROBE == 1)
/* svcneg: issue the scheduler's internal guest-return trap from a partition. */
void wt_arch_sp_guest_return_probe(void);
#endif
void wt_arch_diag_trap(uint32_t a, uint32_t b, uint32_t c);
void wt_arch_sp_panic(uint32_t op, uint32_t code, uint32_t extra)
    __attribute__((noreturn));

/* The two bound checks are the FF-M memcheck callback shapes. */
int wt_arch_ns_check_read(wt_guest_id_t guest_id,
                          const void* address, size_t size);
int wt_arch_ns_check_write(wt_guest_id_t guest_id, void* address, size_t size);
int wt_arch_ns_check_writable(const void* address, size_t size);

#ifdef WT_TARGET_BUILD
int wt_arch_thread_unprivileged(void);
#else
static inline int wt_arch_thread_unprivileged(void)
{
    return 0;
}
#endif

#endif /* WOLFTRUST_ARCH_H */
