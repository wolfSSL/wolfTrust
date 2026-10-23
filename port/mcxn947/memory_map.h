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

#ifndef WOLFTRUST_FW_MCXN947_MEMORY_MAP_H
#define WOLFTRUST_FW_MCXN947_MEMORY_MAP_H

/* MCXN947 CPU0. Bit 28 of every address selects the Secure alias: the 2 MiB
 * internal flash is 0x00000000 (NS) / 0x10000000 (S), RAMA-H is 0x20000000
 * (NS) / 0x30000000 (S), peripherals 0x40000000 (NS) / 0x50000000 (S). */
#ifndef WT_SECURE_FLASH_BASE
#define WT_SECURE_FLASH_BASE     0x10040000u
#endif
#ifndef WT_SECURE_FLASH_SIZE
#define WT_SECURE_FLASH_SIZE     0x00040000u
#endif
#ifndef WT_SECURE_IMAGE_HEADER_SIZE
#define WT_SECURE_IMAGE_HEADER_SIZE 0x400u
#endif
#define WT_FLASH_S_BASE          WT_SECURE_FLASH_BASE
#define WT_FLASH_S_SIZE          WT_SECURE_FLASH_SIZE
#define WT_FLASH_IMAGE_BASE      (WT_FLASH_S_BASE + WT_SECURE_IMAGE_HEADER_SIZE)
/* The SG veneers sit in the image's second 1 KiB, as on the STM32H5: the
 * flash is in the Code region, where the IDAU honours an SAU NSC window. */
#define WT_NSC_BASE              (WT_FLASH_IMAGE_BASE + 0x00000400u)
#define WT_NSC_END               (WT_NSC_BASE + 0x000003FFu)

#define WT_FLASH_NS_BASE         0x00000000u
#define WT_FLASH_S_ALIAS_BASE    0x10000000u
#define WT_FLASH_SIZE            0x00200000u
#define WT_FLASH_TO_S_ALIAS(address) \
    ((address) - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE)
#ifndef WT_GUEST0_FLASH_BASE
#define WT_GUEST0_FLASH_BASE     0x00080000u
#endif
#ifndef WT_GUEST1_FLASH_BASE
#define WT_GUEST1_FLASH_BASE     0x00100000u
#endif
#ifndef WT_GUEST0_FLASH_SIZE
#define WT_GUEST0_FLASH_SIZE     0x00080000u
#endif
#ifndef WT_GUEST1_FLASH_SIZE
#define WT_GUEST1_FLASH_SIZE     0x00040000u
#endif

/* Flash geometry: 8 KiB erase sectors, 16-byte ECC phrases that are written
 * once per erase. Every store below the Secure image lives in bank 1, so the
 * image keeps executing from bank 0 while the ROM API programs them. */
#define WT_FLASH_SECTOR_SIZE       0x00002000u
#define WT_FLASH_PHRASE_SIZE       0x00000010u
#define WT_FLASH_BANK_SIZE         0x00100000u
#define WT_HSM_NVM_FLASH_BASE_NS   0x001E0000u
#define WT_HSM_NVM_FLASH_BASE_S    0x101E0000u
#define WT_HSM_NVM_FLASH_SIZE      0x00004000u

#define WT_CONF_NVM_FLASH_BASE_NS  0x001E4000u
#define WT_CONF_NVM_FLASH_BASE_S   0x101E4000u
#define WT_CONF_NVM_FLASH_SIZE     0x00002000u

/* Non-secure guest RAM: two 96 KiB windows at the bottom of RAMA-H. Their
 * Secure alias holds the first loader's RAM, dead after the jump, which
 * wt_platform_init zeroes before any guest runs. */
#define WT_RAM_NS_BASE           0x20000000u
#define WT_PLATFORM_GUEST_STACK_WINDOW_BASE WT_RAM_NS_BASE
#define WT_PLATFORM_GUEST_STACK_WINDOW_SIZE 0x00030000u
#define WT_GUEST0_RAM_BASE       0x20000000u
#define WT_GUEST1_RAM_BASE       0x20018000u
#define WT_GUEST_RAM_SIZE        0x00018000u

/* Secure runtime RAM: the top 220 KiB of RAMA-H through its Secure alias,
 * one 4 KiB page above the wolfBoot handoff record (56 bytes, the page is
 * cleared once consumed); the level 3 bands are offsets from this base. */
#define WT_RAM_S_BASE            0x30031000u
#define WT_RAM_S_SIZE            0x00037000u
#define WT_BOOT_HANDOFF_ADDRESS  0x30030000u
#define WT_L3_SPM_RAM_SIZE       0x00015800u
#define WT_SP_HSM_DATA_SIZE      0x00008000u

#include "../common/armv8m/l3_layout.h"

/* wolfBoot update partition (Secure alias, bank 1). */
#define WT_FWU_UPDATE_FLASH_BASE_S 0x10180000u
#define WT_FWU_UPDATE_FLASH_SIZE   0x00040000u

#define WT_SHARED_STATUS_ADDR    0x20000000u

#ifndef WT_PLATFORM_CORE_CLOCK_HZ
#define WT_PLATFORM_CORE_CLOCK_HZ 150000000u
#endif

#endif
