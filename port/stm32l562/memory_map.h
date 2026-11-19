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

/* 256 KiB of SRAM holds the native engine's level 3 bands beside two guests;
 * the wolfHSM server's bands do not fit. */
#ifdef WT_ENGINE_HSM
#error "TARGET=stm32l562 supports WT_ENGINE=native only"
#endif

/* Dual-bank mode (DBANK=1): two 256 KiB banks of 2 KiB pages. */
#ifndef WT_SECURE_FLASH_BASE
#define WT_SECURE_FLASH_BASE     0x0C00C000u
#endif
#ifndef WT_SECURE_FLASH_SIZE
#define WT_SECURE_FLASH_SIZE     0x00020000u
#endif
#ifndef WT_SECURE_IMAGE_HEADER_SIZE
#define WT_SECURE_IMAGE_HEADER_SIZE 0x400u
#endif
#define WT_FLASH_S_BASE          WT_SECURE_FLASH_BASE
#define WT_FLASH_S_SIZE          WT_SECURE_FLASH_SIZE
#define WT_FLASH_IMAGE_BASE      (WT_FLASH_S_BASE + WT_SECURE_IMAGE_HEADER_SIZE)
/* The SG veneers sit in the image's second 1 KiB. */
#define WT_NSC_BASE              (WT_FLASH_IMAGE_BASE + 0x00000400u)
#define WT_NSC_END               (WT_NSC_BASE + 0x000003FFu)

#define WT_FLASH_NS_BASE         0x08000000u
#define WT_FLASH_S_ALIAS_BASE    0x0C000000u
#define WT_FLASH_SIZE            0x00080000u
#define WT_FLASH_BANK_SIZE       0x00040000u
#define WT_FLASH_PAGE_SIZE       0x00000800u
#define WT_FLASH_TO_S_ALIAS(address) \
    ((address) - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE)
#ifndef WT_GUEST0_FLASH_BASE
#define WT_GUEST0_FLASH_BASE     0x0802C000u
#endif
#ifndef WT_GUEST1_FLASH_BASE
#define WT_GUEST1_FLASH_BASE     0x08040000u
#endif
#ifndef WT_GUEST0_FLASH_SIZE
#define WT_GUEST0_FLASH_SIZE     0x00014000u
#endif
#ifndef WT_GUEST1_FLASH_SIZE
#define WT_GUEST1_FLASH_SIZE     0x00010000u
#endif

/* A wolfHSM "sector" is four 2 KiB pages; double-word programs. */
#define WT_FLASH_SECTOR_SIZE       0x00002000u
#define WT_FLASH_PROGRAM_UNIT      0x00000008u
#define WT_FWU_TRAILER_SIZE        WT_FLASH_SECTOR_SIZE
/* Both stores sit at the top of bank 2 in every layout. */
#define WT_HSM_NVM_FLASH_BASE_NS   0x0807A000u
#define WT_HSM_NVM_FLASH_BASE_S    0x0C07A000u
#define WT_HSM_NVM_FLASH_SIZE      0x00004000u
#define WT_CONF_NVM_FLASH_BASE_NS  0x0807E000u
#define WT_CONF_NVM_FLASH_BASE_S   0x0C07E000u
#define WT_CONF_NVM_FLASH_SIZE     0x00002000u

/* The update partition follows guest 1 at the boot slot's size; the
 * conformance layout's guests leave only wolfBoot's swap, and that manifest
 * has no FWU. */
#if WT_GUEST1_FLASH_SIZE < 0x00008000u
#define WT_FWU_UPDATE_FLASH_BASE_S 0x0C074000u
#define WT_FWU_UPDATE_FLASH_SIZE   0x00006000u
#else
#define WT_FWU_UPDATE_FLASH_BASE_S 0x0C050000u
#define WT_FWU_UPDATE_FLASH_SIZE   0x00020000u
#endif

/* Guest RAM is the top 96 KiB of SRAM; the conformance layout (a guest 1
 * window under 32 KiB) gives the Arm val guest 80 KiB and its peer 16 KiB. */
#define WT_RAM_NS_BASE           0x20028000u
#define WT_PLATFORM_GUEST_STACK_WINDOW_BASE WT_RAM_NS_BASE
#define WT_PLATFORM_GUEST_STACK_WINDOW_SIZE 0x00018000u
#define WT_GUEST0_RAM_BASE       0x20028000u
#if WT_GUEST1_FLASH_SIZE < 0x00008000u
#define WT_GUEST0_RAM_SIZE       0x00014000u
#define WT_GUEST1_RAM_BASE       0x2003C000u
#define WT_GUEST1_RAM_SIZE       0x00004000u
#else
#define WT_GUEST0_RAM_SIZE       0x0000C000u
#define WT_GUEST1_RAM_BASE       0x20034000u
#define WT_GUEST1_RAM_SIZE       0x0000C000u
#endif
#define WT_GUEST_RAM_SIZE        WT_GUEST1_RAM_SIZE
/* GTZC MPCBB attribution is per 256-byte block. */
#define WT_GUEST_WINDOW_GRANULE  256u
/* USART1 on PA9/PA10, the DK's ST-LINK virtual COM port, for both guests. */
#define WT_GUEST_UART_BASE       0x40013800u
#define WT_GUEST_UART_SIZE       0x00000400u

/* wolfBoot writes its handoff record in the first 4 KiB of Secure SRAM; the
 * SPM band is sized for the native engine. */
#define WT_BOOT_HANDOFF_ADDRESS  0x30000000u
#define WT_RAM_S_BASE            0x30001000u
#define WT_RAM_S_SIZE            0x00027000u
#ifndef WT_L3_SPM_RAM_SIZE
#define WT_L3_SPM_RAM_SIZE       0x0000B800u
#endif

#include "../common/armv8m/l3_layout.h"

#define WT_SHARED_STATUS_ADDR    WT_GUEST0_RAM_BASE

#define WT_PLATFORM_CORE_CLOCK_HZ 110000000u

/* The RNG, which only the SPM drives; probed by the periphsp negative. */
#define WT_L3_SPM_PERIPHERAL_BASE 0x520C0800u

#include "../common/armv8m/memory_map_check.h"

#endif
