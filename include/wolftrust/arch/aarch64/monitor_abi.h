/* monitor_abi.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_MONITOR_ABI_H
#define WOLFTRUST_ARCH_AARCH64_MONITOR_ABI_H

#include <stdint.h>

/* S-EL1 -> EL3 monitor calls: SMC64 OEM function ids, accepted only from
 * the Secure world; a Non-secure caller gets WT_MON_NOT_SUPPORTED. */
#define WT_MON_FID_RESUME_NS     0xC3800000u
#define WT_MON_FID_LAUNCH_NS     0xC3800001u
#define WT_MON_FID_PANIC         0xC3800002u
#define WT_MON_FID_SYSTEM_RESET  0xC3800003u
#define WT_MON_FID_EXIT          0xC3800004u
#define WT_MON_FID_SET_TICK_HZ   0xC3800005u

#define WT_MON_NOT_SUPPORTED     0xFFFFFFFFFFFFFFFFull

/* Exit immediates, kept from the Armv8-M BKPT convention the runners expect. */
#define WT_MON_EXIT_SUCCESS      0x7Fu
#define WT_MON_EXIT_PANIC        0x7Eu
#define WT_MON_EXIT_RESET        0x7Du

static inline uint64_t wt_mon_call(uint64_t fid, uint64_t arg)
{
    register uint64_t x0 __asm__("x0") = fid;
    register uint64_t x1 __asm__("x1") = arg;

    __asm__ volatile("smc #0"
                     : "+r"(x0)
                     : "r"(x1)
                     : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                       "x10", "x11", "x12", "x13", "x14", "x15", "x16",
                       "x17", "memory");
    return x0;
}

#endif /* WOLFTRUST_ARCH_AARCH64_MONITOR_ABI_H */
