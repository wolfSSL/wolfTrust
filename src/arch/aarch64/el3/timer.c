/* timer.c
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

/* Secure physical timer (CNTPS, PPI 29) as seen from EL3. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/sysreg.h"

WT_SYSREG_WRITE(cntps_ctl_el1, "CNTPS_CTL_EL1")
WT_SYSREG_WRITE(cntps_tval_el1, "CNTPS_TVAL_EL1")

#define CNTPS_CTL_ENABLE (1u << 0)

void wt_el3_timer_arm_ms(uint32_t ms)
{
    uint64_t ticks = (wt_read_cntfrq_el0() * ms) / 1000u;

    wt_write_cntps_tval_el1(ticks);
    wt_write_cntps_ctl_el1(CNTPS_CTL_ENABLE);
    wt_isb();
}

void wt_el3_timer_disable(void)
{
    wt_write_cntps_ctl_el1(0u);
    wt_isb();
}
