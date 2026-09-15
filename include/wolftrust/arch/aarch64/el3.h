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

/* Register frame the vector table saves; layout is shared with vectors.S. */
typedef struct wt_el3_frame {
    uint64_t x[19];
    uint64_t x29;
    uint64_t x30;
    uint64_t elr;
    uint64_t spsr;
    uint64_t pad;
} wt_el3_frame_t;

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
/* The SPMC signalled initialization complete with FFA_MSG_WAIT. */
void wt_el3_spmc_ready(void) __attribute__((noreturn));
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
