/* platform_caps.h
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

/* Immutable platform capabilities every Armv8-M port shares; mk/arch-armv8m.mk
 * passes the same values to the manifest generator, whose output asserts they
 * agree. */

#ifndef WOLFTRUST_ARMV8M_PLATFORM_CAPS_H
#define WOLFTRUST_ARMV8M_PLATFORM_CAPS_H

#include <stdint.h>

#include "wolftrust/partition.h"
#include "memory_map.h"

#define WT_PLATFORM_CAPABILITIES \
    (WT_CAPABILITY_SECURITY_STATE | WT_CAPABILITY_PRIVILEGE_STATE | \
     WT_CAPABILITY_ROT_ISOLATION | WT_CAPABILITY_DOMAIN_ISOLATION | \
     WT_CAPABILITY_MEMORY_PROTECTION | WT_CAPABILITY_INTERRUPT_ISOLATION | \
     WT_CAPABILITY_RESTART)
#define WT_PLATFORM_MAX_DOMAINS          11U
#define WT_PLATFORM_MAX_MEMORY_RESOURCES 3U
#define WT_PLATFORM_MAX_INTERRUPTS       1U

/* The build sets WT_PLATFORM_SP_IRQ (mk/layout.mk); this is its default. */
#ifndef WT_PLATFORM_SP_IRQ
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
#define WT_PLATFORM_SP_IRQ WT_CONF_IRQ
#else
#define WT_PLATFORM_SP_IRQ UINT32_MAX
#endif
#endif

/* Enforcement every Armv8-M port provides (WT-PORT-0008): the fabric filter
 * is the per-dispatch SAU window; a port that provides more or less defines
 * WT_PORT_CAPABILITIES in its memory_map.h. */
#ifndef WT_PORT_CAPABILITIES
#define WT_PORT_CAPABILITIES \
    (WT_PORT_CAPABILITY_VECTOR_READ_ALIAS | \
     WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING | \
     WT_PORT_CAPABILITY_TZ_FILTER)
#endif
#define WT_PLATFORM_PORT_CAPABILITIES WT_PORT_CAPABILITIES

#endif
