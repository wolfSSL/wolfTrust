/* context.h
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

/* AArch64 bodies of the core's forward-declared context and trap frame. */

#ifndef WOLFTRUST_ARCH_AARCH64_CONTEXT_H
#define WOLFTRUST_ARCH_AARCH64_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

/* Lower-EL exception frame the S-EL1 vectors build: x0-x30, then the
 * banked state. Offsets are fixed for the assembly entry paths. */
struct wt_trap_frame {
    uint64_t x[31];
    uint64_t sp_el0;
    uint64_t elr;
    uint64_t spsr;
    uint64_t esr;
    uint64_t far;
};

typedef struct wt_trap_frame wt_trap_frame_t;

/* Non-secure endpoint context held by the neutral runtime; the NS gateway
 * fills it in when the Normal world arrives. */
struct wt_guest_context {
    uint64_t x[31];
    uint64_t sp_el0;
    uint64_t elr;
    uint64_t spsr;
    uintptr_t pc;
    bool frame_stacked;
};

typedef struct wt_guest_context wt_guest_context_t;

#define WT_TRAP_FRAME_SIZE 288u

#endif /* WOLFTRUST_ARCH_AARCH64_CONTEXT_H */
