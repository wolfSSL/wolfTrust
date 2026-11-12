/* memory_map_check.h
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

/* Consistency of a port's memory_map.h, included last by every port's map.
 * Every rule here is one a port got wrong, or could, in a way the linker,
 * the manifest generator and the post-link check do not catch: the guest
 * windows against the Secure image and the stores, the stores against the
 * erase geometry, the guest RAM against the fabric filter's granule. */

#ifndef WOLFTRUST_PORT_ARMV8M_MEMORY_MAP_CHECK_H
#define WOLFTRUST_PORT_ARMV8M_MEMORY_MAP_CHECK_H

#if !defined(WT_FLASH_NS_BASE) || !defined(WT_FLASH_S_ALIAS_BASE) || \
    !defined(WT_FLASH_SIZE) || !defined(WT_FLASH_SECTOR_SIZE) || \
    !defined(WT_FLASH_PROGRAM_UNIT) || !defined(WT_FWU_TRAILER_SIZE)
#error "memory_map.h must define the flash aliases, size, sector size, program unit and FWU trailer"
#endif
#if !defined(WT_NSC_BASE) || !defined(WT_NSC_END) || \
    !defined(WT_L3_SPM_PERIPHERAL_BASE) || !defined(WT_GUEST_UART_BASE) || \
    !defined(WT_GUEST_UART_SIZE) || !defined(WT_BOOT_HANDOFF_ADDRESS)
#error "memory_map.h must define the NSC window, the SPM-only peripheral, the guest console and the boot handoff"
#endif

#ifndef WT_GUEST_WINDOW_GRANULE
#define WT_GUEST_WINDOW_GRANULE 32u
#endif

/* The Secure image and its NSC gateway. */
#if WT_SECURE_IMAGE_HEADER_SIZE >= WT_SECURE_FLASH_SIZE
#error "the Secure image header does not leave room for the image"
#endif
#if defined(WT_RAMFUNC_BASE)
#if WT_NSC_BASE < WT_RAMFUNC_BASE || WT_NSC_END >= WT_RAMFUNC_BASE + WT_RAMFUNC_SIZE
#error "the NSC window lies outside the RAM code band"
#endif
#else
#if WT_NSC_BASE < WT_FLASH_IMAGE_BASE || \
    WT_NSC_END >= WT_SECURE_FLASH_BASE + WT_SECURE_FLASH_SIZE
#error "the NSC window lies outside the Secure image"
#endif
#endif

/* Guest flash: ordered, past the Secure image, below the update partition
 * and both stores, all through the Non-secure alias. */
#define WT_SECURE_FLASH_END_NS \
    (WT_SECURE_FLASH_BASE + WT_SECURE_FLASH_SIZE - WT_FLASH_S_ALIAS_BASE + \
     WT_FLASH_NS_BASE)
#define WT_GUEST_FLASH_NS_END (WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE)
#if WT_GUEST0_FLASH_BASE + WT_GUEST0_FLASH_SIZE > WT_GUEST1_FLASH_BASE
#error "guest 0 flash overlaps guest 1 flash"
#endif
#if WT_GUEST0_FLASH_BASE < WT_SECURE_FLASH_END_NS
#error "guest flash overlaps the Secure image"
#endif
#if WT_GUEST_FLASH_NS_END > WT_FWU_UPDATE_FLASH_BASE_S - WT_FLASH_S_ALIAS_BASE + WT_FLASH_NS_BASE
#error "guest flash overlaps the update partition"
#endif
#if WT_GUEST_FLASH_NS_END > WT_HSM_NVM_FLASH_BASE_NS || \
    WT_GUEST_FLASH_NS_END > WT_CONF_NVM_FLASH_BASE_NS
#error "guest flash overlaps a Secure store"
#endif
#if WT_HSM_NVM_FLASH_BASE_NS + WT_HSM_NVM_FLASH_SIZE > WT_FLASH_NS_BASE + WT_FLASH_SIZE || \
    WT_CONF_NVM_FLASH_BASE_NS + WT_CONF_NVM_FLASH_SIZE > WT_FLASH_NS_BASE + WT_FLASH_SIZE
#error "a Secure store lies past the end of flash"
#endif
#if WT_HSM_NVM_FLASH_BASE_S != WT_HSM_NVM_FLASH_BASE_NS - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE || \
    WT_CONF_NVM_FLASH_BASE_S != WT_CONF_NVM_FLASH_BASE_NS - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE
#error "a Secure store's Secure and Non-secure aliases disagree"
#endif

/* The two stores and the update partition are disjoint and inside flash. */
#if (WT_HSM_NVM_FLASH_BASE_S < WT_CONF_NVM_FLASH_BASE_S + WT_CONF_NVM_FLASH_SIZE && \
     WT_CONF_NVM_FLASH_BASE_S < WT_HSM_NVM_FLASH_BASE_S + WT_HSM_NVM_FLASH_SIZE) || \
    (WT_FWU_UPDATE_FLASH_BASE_S < WT_HSM_NVM_FLASH_BASE_S + WT_HSM_NVM_FLASH_SIZE && \
     WT_HSM_NVM_FLASH_BASE_S < WT_FWU_UPDATE_FLASH_BASE_S + WT_FWU_UPDATE_FLASH_SIZE) || \
    (WT_FWU_UPDATE_FLASH_BASE_S < WT_CONF_NVM_FLASH_BASE_S + WT_CONF_NVM_FLASH_SIZE && \
     WT_CONF_NVM_FLASH_BASE_S < WT_FWU_UPDATE_FLASH_BASE_S + WT_FWU_UPDATE_FLASH_SIZE)
#error "the wolfHSM store, the conformance store and the update partition overlap"
#endif
#if WT_FWU_UPDATE_FLASH_BASE_S + WT_FWU_UPDATE_FLASH_SIZE > WT_FLASH_S_ALIAS_BASE + WT_FLASH_SIZE
#error "the update partition lies past the end of flash"
#endif

/* Erase geometry: every store and the update partition are whole sectors. */
#if (WT_HSM_NVM_FLASH_BASE_S % WT_FLASH_SECTOR_SIZE) != 0u || \
    (WT_HSM_NVM_FLASH_SIZE % WT_FLASH_SECTOR_SIZE) != 0u || \
    (WT_CONF_NVM_FLASH_BASE_S % WT_FLASH_SECTOR_SIZE) != 0u || \
    (WT_CONF_NVM_FLASH_SIZE % WT_FLASH_SECTOR_SIZE) != 0u || \
    (WT_FWU_UPDATE_FLASH_BASE_S % WT_FLASH_SECTOR_SIZE) != 0u || \
    (WT_FWU_UPDATE_FLASH_SIZE % WT_FLASH_SECTOR_SIZE) != 0u
#error "a Secure store or the update partition is not sector aligned"
#endif
#if WT_HSM_NVM_FLASH_SIZE < 2u * WT_FLASH_SECTOR_SIZE
#error "the wolfHSM store needs two mirrored sectors"
#endif
#if (WT_FLASH_SECTOR_SIZE % WT_FLASH_PROGRAM_UNIT) != 0u || \
    (WT_FWU_TRAILER_SIZE % WT_FLASH_SECTOR_SIZE) != 0u || \
    WT_FWU_TRAILER_SIZE >= WT_FWU_UPDATE_FLASH_SIZE
#error "the program unit must divide the sector and the FWU trailer be whole sectors"
#endif

/* Guest RAM: ordered, inside the guest stack window, on the filter's granule. */
#if WT_GUEST0_RAM_BASE + WT_GUEST0_RAM_SIZE > WT_GUEST1_RAM_BASE
#error "guest 0 RAM overlaps guest 1 RAM"
#endif
#if WT_GUEST0_RAM_BASE < WT_PLATFORM_GUEST_STACK_WINDOW_BASE || \
    WT_GUEST1_RAM_BASE + WT_GUEST1_RAM_SIZE > \
        WT_PLATFORM_GUEST_STACK_WINDOW_BASE + WT_PLATFORM_GUEST_STACK_WINDOW_SIZE
#error "guest RAM lies outside the guest stack window"
#endif
#if (WT_GUEST0_RAM_BASE % WT_GUEST_WINDOW_GRANULE) != 0u || \
    (WT_GUEST0_RAM_SIZE % WT_GUEST_WINDOW_GRANULE) != 0u || \
    (WT_GUEST1_RAM_BASE % WT_GUEST_WINDOW_GRANULE) != 0u || \
    (WT_GUEST1_RAM_SIZE % WT_GUEST_WINDOW_GRANULE) != 0u
#error "guest RAM is not on the fabric filter's attribution granule"
#endif

/* Secure RAM: the boot handoff record sits below the runtime window. */
#if WT_BOOT_HANDOFF_ADDRESS >= WT_RAM_S_BASE
#error "the boot handoff record lies inside Secure runtime RAM"
#endif

#endif
