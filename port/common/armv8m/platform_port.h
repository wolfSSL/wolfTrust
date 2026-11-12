/* platform_port.h
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

/* The hooks a port supplies in port/<soc>/platform_<soc>.c to the shared
 * Armv8-M platform (port/common/armv8m/platform_armv8m.c), which owns
 * wt_platform_init and every neutral wt_platform_* operation.
 *
 * wt_platform_init runs them in this order, with these guarantees:
 *   1. wt_port_boot_init: nothing else has run. The port brings up clocks,
 *      stages any RAM code band (copying it through the alias it is written
 *      by, with barriers, before anything executes from it) and sets the
 *      fabric rules its SAU and MPU tables assume. No guest RAM may be
 *      touched yet, since it may still hold the first loader's state.
 *   2. wt_port_fabric_init: the FF-M gateway and the Secure vector table are
 *      installed. The port programs the fabric filter it isolates guests
 *      with (GTZC on the STM32H5), reads the attribution back and returns
 *      nonzero if it did not take; the shared platform then panics.
 *   3. The SAU and the Secure MPU are loaded from wt_port_sau_regions and
 *      wt_port_mpu_s_regions, the arch layer is initialised, and every
 *      guest RAM window is cleared.
 *   4. wt_port_late_init: isolation is up and guest RAM is clean. The port
 *      enables what guests need (console clocks and pins), arms any fabric
 *      checking that must follow the clear, and runs its silicon checks;
 *      nonzero panics.
 *
 * wt_port_fabric_windows names the per-dispatch guest RAM backend: the
 * shared SAU backend (fabric_sau.h) for a port whose SAU is the isolation
 * layer, or the port's own (GTZC). The tables are const and immutable. */

#ifndef WOLFTRUST_PORT_ARMV8M_PLATFORM_PORT_H
#define WOLFTRUST_PORT_ARMV8M_PLATFORM_PORT_H

#include <stddef.h>

#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/fabric_windows.h"

void wt_port_boot_init(void);
int wt_port_fabric_init(void);
int wt_port_late_init(void);
const wt_armv8m_sau_region_t* wt_port_sau_regions(size_t* count);
const wt_armv8m_mpu_region_t* wt_port_mpu_s_regions(size_t* count);
const wt_fabric_windows_t* wt_port_fabric_windows(void);

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* wt_port_conf_irq_set raises (on != 0) or quiesces the PAL interrupt line
 * WT_CONF_IRQ from its peripheral; a port with no peripheral source pends it
 * with wt_platform_conf_irq_pend. The shared code disables the line after. */
void wt_port_conf_irq_set(int on);
void wt_platform_conf_irq_pend(void);
#endif

#endif /* WOLFTRUST_PORT_ARMV8M_PLATFORM_PORT_H */
