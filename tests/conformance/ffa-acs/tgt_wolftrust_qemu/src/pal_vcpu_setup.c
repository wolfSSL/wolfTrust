/* pal_vcpu_setup.c
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

/* One processing element: the boot core has affinity 0 on both machines and
 * the secondaries stay parked, so no core can be powered on or off. */

#include "pal_interfaces.h"
#include <pal_arch_helpers.h>

uint32_t pal_get_no_of_cpus(void)
{
    return PLATFORM_NO_OF_CPUS;
}

uint32_t pal_get_cpuid(uint64_t mpid)
{
    if ((mpid & MPIDR_AFFINITY_MASK) == 0u) {
        return 0u;
    }
    return PAL_INVALID_CPU_INFO;
}

uint64_t pal_get_mpid(uint32_t cpuid)
{
    if (cpuid == 0u) {
        return 0u;
    }
    return PAL_INVALID_CPU_INFO;
}

uint32_t pal_power_on_cpu(uint64_t mpid)
{
    (void)mpid;
    return PAL_ERROR;
}

uint32_t pal_power_off_cpu(void)
{
    return PAL_ERROR;
}
