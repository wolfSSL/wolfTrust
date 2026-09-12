/* ffa.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_H
#define WOLFTRUST_ARCH_AARCH64_FFA_H

#include <stdint.h>

/* One FF-A call: x0 = function id, x1-x7 parameters in, x0-x7 results out. */
typedef struct wt_ffa_regs {
    uint64_t x[8];
} wt_ffa_regs_t;

/* SMC conduit (S-EL1 -> EL3, NS EL1 -> EL3). x8-x17 are caller-saved. */
static inline void wt_ffa_smc(wt_ffa_regs_t* r)
{
    register uint64_t x0 __asm__("x0") = r->x[0];
    register uint64_t x1 __asm__("x1") = r->x[1];
    register uint64_t x2 __asm__("x2") = r->x[2];
    register uint64_t x3 __asm__("x3") = r->x[3];
    register uint64_t x4 __asm__("x4") = r->x[4];
    register uint64_t x5 __asm__("x5") = r->x[5];
    register uint64_t x6 __asm__("x6") = r->x[6];
    register uint64_t x7 __asm__("x7") = r->x[7];

    __asm__ volatile("smc #0"
                     : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3),
                       "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
                     :
                     : "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                       "x15", "x16", "x17", "memory");
    r->x[0] = x0;
    r->x[1] = x1;
    r->x[2] = x2;
    r->x[3] = x3;
    r->x[4] = x4;
    r->x[5] = x5;
    r->x[6] = x6;
    r->x[7] = x7;
}

/* EL3 (SPMD) handling of one FF-A call taken at the Secure physical
 * instance; fills r with the FFA_SUCCESS/FFA_ERROR reply. */
void wt_ffa_spmd_secure_call(wt_ffa_regs_t* r);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_H */
