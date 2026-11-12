/* memory_map.h
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

#ifndef WOLFTRUST_FW_STM32L562_MEMORY_MAP_H
#define WOLFTRUST_FW_STM32L562_MEMORY_MAP_H

/* STM32L562 in dual-bank mode (DBANK=1): two 256 KiB banks of 2 KiB pages at
 * 0x08000000 (NS) / 0x0C000000 (S); 256 KiB SRAM (SRAM1 192 KiB, SRAM2
 * 64 KiB) at 0x20000000 (NS) / 0x30000000 (S). The production layout keeps a
 * 128 KiB Secure slot and a matching update slot; the conformance image and
 * the Arm test guests need a 160 KiB slot and a 240 KiB guest0 window, which
 * leaves no room for an update slot (FWU is not in that manifest). */
#ifndef WT_SECURE_FLASH_BASE
#define WT_SECURE_FLASH_BASE     0x0C00C000u
#endif
#ifndef WT_SECURE_FLASH_SIZE
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
#define WT_SECURE_FLASH_SIZE     0x00028000u
#else
#define WT_SECURE_FLASH_SIZE     0x00020000u
#endif
#endif
#ifndef WT_SECURE_IMAGE_HEADER_SIZE
#define WT_SECURE_IMAGE_HEADER_SIZE 0x400u
#endif
#define WT_FLASH_S_BASE          WT_SECURE_FLASH_BASE
#define WT_FLASH_S_SIZE          WT_SECURE_FLASH_SIZE
#define WT_FLASH_IMAGE_BASE      (WT_FLASH_S_BASE + WT_SECURE_IMAGE_HEADER_SIZE)
#define WT_FLASH_NSC_BASE        (WT_FLASH_IMAGE_BASE + 0x00000400u)
#define WT_FLASH_NSC_END         (WT_FLASH_NSC_BASE + 0x000003FFu)

#define WT_FLASH_NS_BASE         0x08000000u
#define WT_FLASH_S_ALIAS_BASE    0x0C000000u
#define WT_FLASH_SIZE            0x00080000u
#define WT_FLASH_BANK_SIZE       0x00040000u
#define WT_FLASH_TO_S_ALIAS(address) \
    ((address) - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE)
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
#ifndef WT_GUEST0_FLASH_BASE
#define WT_GUEST0_FLASH_BASE     0x08040000u
#endif
#ifndef WT_GUEST1_FLASH_BASE
#define WT_GUEST1_FLASH_BASE     0x0807C000u
#endif
#ifndef WT_GUEST0_FLASH_SIZE
#define WT_GUEST0_FLASH_SIZE     0x0003C000u
#endif
#ifndef WT_GUEST1_FLASH_SIZE
/* Ends at wolfBoot's update trailer page (0x0807F800), which stays erased */
#define WT_GUEST1_FLASH_SIZE     0x00003800u
#endif
#else
#ifndef WT_GUEST0_FLASH_BASE
#define WT_GUEST0_FLASH_BASE     0x08060000u
#endif
#ifndef WT_GUEST1_FLASH_BASE
#define WT_GUEST1_FLASH_BASE     0x08070000u
#endif
#ifndef WT_GUEST0_FLASH_SIZE
#define WT_GUEST0_FLASH_SIZE     0x00010000u
#endif
#ifndef WT_GUEST1_FLASH_SIZE
#define WT_GUEST1_FLASH_SIZE     0x00010000u
#endif
#endif

/* The top of bank 1 holds the vault's two mirrored NVM partitions (one 8 KiB
 * "sector" of four 2 KiB pages each), the conformance NVM and wolfBoot's swap
 * page in both layouts; bank 2 holds the update slot and the guests. */
#define WT_FLASH_PAGE_SIZE         0x00000800u
#define WT_FLASH_SECTOR_SIZE       0x00002000u
#define WT_HSM_NVM_FLASH_BASE_NS   0x08038000u
#define WT_HSM_NVM_FLASH_BASE_S    0x0C038000u
#define WT_HSM_NVM_FLASH_SIZE      0x00004000u

#define WT_CONF_NVM_FLASH_BASE_NS  0x0803C000u
#define WT_CONF_NVM_FLASH_BASE_S   0x0C03C000u
#define WT_CONF_NVM_FLASH_SIZE     0x00002000u

/* Non-secure guest RAM: the top 96 KiB of SRAM (the last 32 KiB of SRAM1 and
 * all of SRAM2), two 48 KiB windows, or in conformance builds 80 KiB for the
 * Arm test guest and 16 KiB for the bare-metal peer. Their Secure alias holds
 * wolfBoot's RAM, dead after the jump, which wt_platform_init zeroes. */
#define WT_RAM_NS_BASE           0x20028000u
#define WT_PLATFORM_GUEST_STACK_WINDOW_BASE WT_RAM_NS_BASE
#define WT_PLATFORM_GUEST_STACK_WINDOW_SIZE 0x00018000u
#define WT_GUEST0_RAM_BASE       0x20028000u
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
#define WT_GUEST0_RAM_SIZE       0x00014000u
#define WT_GUEST1_RAM_BASE       0x2003C000u
#define WT_GUEST1_RAM_SIZE       0x00004000u
#else
#define WT_GUEST0_RAM_SIZE       0x0000C000u
#define WT_GUEST1_RAM_BASE       0x20034000u
#define WT_GUEST1_RAM_SIZE       0x0000C000u
#endif
/* The smaller window: the core treats a clear this large as a full reset. */
#define WT_GUEST_RAM_SIZE        WT_GUEST1_RAM_SIZE

/* Secure runtime RAM: the bottom 160 KiB of SRAM1, one 4 KiB page above the
 * wolfBoot handoff record (cleared once consumed). The SPM and crypto bands
 * are sized for the native engine; the wolfHSM server's do not fit. */
#define WT_BOOT_HANDOFF_ADDRESS  0x30000000u
#define WT_RAM_S_BASE            0x30001000u
#define WT_RAM_S_SIZE            0x00027000u
#define WT_L3_SPM_RAM_SIZE       0x0000A800u
#define WT_SP_HSM_DATA_SIZE      0x00000800u

#include "../common/armv8m/l3_layout.h"

/* wolfBoot update partition (Secure alias, bank 2). */
#define WT_FWU_UPDATE_FLASH_BASE_S 0x0C040000u
#define WT_FWU_UPDATE_FLASH_SIZE   0x00020000u

#define WT_SHARED_STATUS_ADDR    WT_GUEST0_RAM_BASE

#ifndef WT_PLATFORM_CORE_CLOCK_HZ
#define WT_PLATFORM_CORE_CLOCK_HZ 110000000u
#endif

#endif
