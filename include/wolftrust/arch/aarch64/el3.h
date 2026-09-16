/* el3.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_EL3_H
#define WOLFTRUST_ARCH_AARCH64_EL3_H

#include <stdint.h>

/* EL3 monitor internals shared between its objects and the port's EL3 hooks. */

#define WT_EL3_MAX_CPUS 4u

/* Vector slot indexes handed to wt_el3_exception. */
#define WT_EL3_VEC_CUR_SP0_SYNC    0u
#define WT_EL3_VEC_CUR_SP0_IRQ     1u
#define WT_EL3_VEC_CUR_SP0_FIQ     2u
#define WT_EL3_VEC_CUR_SP0_SERROR  3u
#define WT_EL3_VEC_CUR_SPX_SYNC    4u
#define WT_EL3_VEC_CUR_SPX_IRQ     5u
#define WT_EL3_VEC_CUR_SPX_FIQ     6u
#define WT_EL3_VEC_CUR_SPX_SERROR  7u
#define WT_EL3_VEC_LOWER64_SYNC    8u
#define WT_EL3_VEC_LOWER64_IRQ     9u
#define WT_EL3_VEC_LOWER64_FIQ     10u
#define WT_EL3_VEC_LOWER64_SERROR  11u
#define WT_EL3_VEC_LOWER32_SYNC    12u

/* Register frame the vector table saves; layout is shared with vectors.S. The
 * full x0-x30 is captured so a world switch can resume a lower EL exactly (the
 * callee-saved x19-x28 carry the SPMC's neutral-core state across an NS
 * excursion). */
typedef struct wt_el3_frame {
    uint64_t x[31];
    uint64_t elr;
    uint64_t spsr;
    uint64_t pad;
} wt_el3_frame_t;

/* A saved world (Secure SPMC or Normal-world guest). EL1 system registers are
 * not banked by security state on these cores, so a world switch saves and
 * restores the running world's full register file (frame) and its EL1 context
 * around every SPMD entry. */
typedef struct wt_el3_world {
    wt_el3_frame_t frame;
    uint64_t scr_el3;
    uint64_t sp_el0;
    uint64_t sp_el1;
    uint64_t sctlr_el1;
    uint64_t ttbr0_el1;
    uint64_t ttbr1_el1;
    uint64_t tcr_el1;
    uint64_t mair_el1;
    uint64_t amair_el1;
    uint64_t vbar_el1;
    uint64_t tpidr_el0;
    uint64_t tpidrro_el0;
    uint64_t tpidr_el1;
    uint64_t contextidr_el1;
    uint64_t cpacr_el1;
    uint64_t elr_el1;
    uint64_t spsr_el1;
    uint64_t esr_el1;
    uint64_t far_el1;
    uint64_t par_el1;
    uint64_t mdscr_el1;
} wt_el3_world_t;

extern volatile uint8_t g_wt_el3_parked[WT_EL3_MAX_CPUS];
extern volatile uint32_t g_wt_el3_ready;
extern volatile uint32_t g_wt_el3_tick_intid;

void wt_el3_puts(const char* text);
void wt_el3_puthex(uint64_t value, unsigned int digits);
void wt_el3_putdec(uint64_t value);

void wt_el3_semihost_exit(uint64_t code) __attribute__((noreturn));
void wt_el3_enter_secure_el1(void (*entry)(void), uintptr_t stack_top,
                             uint64_t x0_arg) __attribute__((noreturn));
/* Drop to NS-EL1 to run the Normal world; x0_arg reaches it in x0. */
void wt_el3_enter_ns(void (*entry)(void), uintptr_t sp,
                     uint64_t x0_arg) __attribute__((noreturn));
/* Why the Normal world is currently paused in the Secure world. */
#define WT_NS_PENDING_NONE   0u
#define WT_NS_PENDING_REPLY  1u  /* an SMC it made is being served; deliver x0-x7 */
#define WT_NS_PENDING_RESUME 2u  /* a Secure interrupt preempted it; resume as-is */

/* The SPMC signalled initialization complete with FFA_MSG_WAIT: launch the
 * Normal world (saving the SPMC so it can be resumed), or exit when there is no
 * Normal-world payload. ERETs into the launched world; never returns. */
void wt_el3_world_launch_ns(wt_el3_frame_t* frame) __attribute__((noreturn));
/* Forward the NS call in `frame` to the SPMC as the return of its blocked
 * FFA_MSG_WAIT, and switch to the Secure world to run it. Never returns. */
void wt_el3_world_forward_to_secure(wt_el3_frame_t* frame)
    __attribute__((noreturn));
/* A Secure interrupt preempted the Normal world: deliver FFA_INTERRUPT(intid) to
 * the SPMC and switch to it, keeping the NS context to resume. Never returns. */
void wt_el3_world_preempt_to_secure(wt_el3_frame_t* frame, uint32_t intid)
    __attribute__((noreturn));
/* Deliver the SPMC's reply in `frame` back to the Normal world and switch to
 * it. Never returns. */
void wt_el3_world_return_to_ns(wt_el3_frame_t* frame) __attribute__((noreturn));
/* Resume the preempted Normal world where it left off (no reply). Never returns. */
void wt_el3_world_resume_ns(wt_el3_frame_t* frame) __attribute__((noreturn));
/* Why the Normal world is paused in the Secure world (WT_NS_PENDING_*). */
unsigned int wt_el3_world_ns_pending(void);
/* Enter a saved world: program SCR_EL3, restore its register file, and ERET. */
void wt_el3_world_eret(const wt_el3_frame_t* frame, uint64_t scr_el3)
    __attribute__((noreturn));
void wt_el3_fault(uint64_t kind, uint64_t esr, uint64_t far, uint64_t elr)
    __attribute__((noreturn));
uint64_t wt_el3_monitor_call(uint32_t fid, uint64_t arg);
void wt_el3_exception(uint64_t kind, wt_el3_frame_t* frame);
void wt_el3_main(void) __attribute__((noreturn));

void wt_el3_timer_arm_ms(uint32_t ms);
void wt_el3_timer_disable(void);

/* Port hooks the EL3 image needs (the tools/el3-symbols.allow set). */
void wt_platform_board_init(void);
void wt_platform_console_putc(char c);
void wt_platform_console_flush(void);

/* The S-EL1 entry the monitor drops into; the SPM side owns it. */
void wt_spm_entry(void) __attribute__((noreturn));

#endif /* WOLFTRUST_ARCH_AARCH64_EL3_H */
