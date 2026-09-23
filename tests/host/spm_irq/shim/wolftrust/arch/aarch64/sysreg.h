/* sysreg.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_SYSREG_H
#define WOLFTRUST_ARCH_AARCH64_SYSREG_H

#include <stdint.h>

/* Host stand-ins for the accessors spm_irq.c uses. */
extern uint64_t g_host_cntpct;
extern unsigned int g_host_fiq_masked;

static inline uint64_t wt_read_cntpct_el0(void)
{
    return g_host_cntpct++;
}

static inline uint64_t wt_read_cntfrq_el0(void)
{
    return 1000u;
}

static inline void wt_daif_clear_fiq(void)
{
    g_host_fiq_masked = 0u;
}

static inline void wt_daif_set_fiq(void)
{
    g_host_fiq_masked = 1u;
}

#endif /* WOLFTRUST_ARCH_AARCH64_SYSREG_H */
