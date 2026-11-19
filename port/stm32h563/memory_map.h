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

#ifndef WOLFTRUST_FW_STM32H563_MEMORY_MAP_H
#define WOLFTRUST_FW_STM32H563_MEMORY_MAP_H

#ifndef WT_SECURE_FLASH_BASE
#define WT_SECURE_FLASH_BASE     0x0C000000u
#endif
#ifndef WT_SECURE_FLASH_SIZE
#define WT_SECURE_FLASH_SIZE     0x00020000u
#endif
#ifndef WT_SECURE_IMAGE_HEADER_SIZE
#define WT_SECURE_IMAGE_HEADER_SIZE 0u
#endif
#define WT_FLASH_S_BASE          WT_SECURE_FLASH_BASE
#define WT_FLASH_S_SIZE          WT_SECURE_FLASH_SIZE
#define WT_FLASH_IMAGE_BASE      (WT_FLASH_S_BASE + WT_SECURE_IMAGE_HEADER_SIZE)
/* The SG veneers sit in the image's second 1 KiB. */
#define WT_NSC_BASE              (WT_FLASH_IMAGE_BASE + 0x00000400u)
#define WT_NSC_END               (WT_NSC_BASE + 0x000003FFu)

#define WT_FLASH_NS_BASE         0x08000000u
#define WT_FLASH_S_ALIAS_BASE    0x0C000000u
/* 2 MiB of internal flash in two 1 MiB banks. */
#define WT_FLASH_SIZE            0x00200000u
#define WT_FLASH_BANK_SIZE       0x00100000u
#define WT_FLASH_TO_S_ALIAS(address) \
    ((address) - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE)
#ifndef WT_GUEST0_FLASH_BASE
#define WT_GUEST0_FLASH_BASE     0x080A0000u
#endif
#ifndef WT_GUEST1_FLASH_BASE
#define WT_GUEST1_FLASH_BASE     0x080E0000u
#endif
#ifndef WT_GUEST_FLASH_SIZE
#define WT_GUEST_FLASH_SIZE      0x00020000u
#endif
/* Per-guest window sizes; guest0 can grow past guest1's without moving it
 * across the bank-1/bank-2 watermark boundary. */
#ifndef WT_GUEST0_FLASH_SIZE
#define WT_GUEST0_FLASH_SIZE     0x00040000u
#endif
#ifndef WT_GUEST1_FLASH_SIZE
#define WT_GUEST1_FLASH_SIZE     WT_GUEST_FLASH_SIZE
#endif

/* Secure wolfHSM NVM store.
 *
 * Reserved at the end of internal flash bank 2. STM32H5 sectors are 8 KiB;
 * wolfHSM's flash backend reports one sector as the partition size, and
 * wh_nvm_flash uses two mirrored partitions, so reserve two sectors.
 */
#define WT_FLASH_SECTOR_SIZE       0x00002000u
/* Quad-word programs; wolfBoot keeps its trailer in the last sector. */
#define WT_FLASH_PROGRAM_UNIT      0x00000010u
#define WT_FWU_TRAILER_SIZE        WT_FLASH_SECTOR_SIZE
#define WT_HSM_NVM_FLASH_BASE_NS   0x081FC000u
#define WT_HSM_NVM_FLASH_BASE_S    0x0C1FC000u
#define WT_HSM_NVM_FLASH_SIZE      0x00004000u

/* Conformance-only survive-reset NVM (P5 K2): one reserved sector directly
 * below the wolfHSM NVM store, backing the Arm DRIVER partition's NVMEM so
 * val's boot flag survives an AIRCR.SYSRESETREQ reboot. */
#define WT_CONF_NVM_FLASH_BASE_NS  0x081FA000u
#define WT_CONF_NVM_FLASH_BASE_S   0x0C1FA000u
#define WT_CONF_NVM_FLASH_SIZE     0x00002000u
/* Conformance PAL device bases (Secure USART3 and IWDG); the PAL only
 * reports them, nothing is driven through them. */
#define WT_CONF_UART_BASE          0x44002400u
#define WT_CONF_WDG_BASE           0x40003000u

#define WT_RAM_NS_BASE           0x20000000u
/* Where a guest exception frame may legitimately be stacked. */
#define WT_PLATFORM_GUEST_STACK_WINDOW_BASE WT_RAM_NS_BASE
#define WT_PLATFORM_GUEST_STACK_WINDOW_SIZE 0x00020000u
#define WT_GUEST0_RAM_BASE       0x20000000u
#define WT_GUEST1_RAM_BASE       0x20010000u
#define WT_GUEST_RAM_SIZE        0x00010000u
#define WT_GUEST0_RAM_SIZE       WT_GUEST_RAM_SIZE
#define WT_GUEST1_RAM_SIZE       WT_GUEST_RAM_SIZE
/* GTZC MPCBB attribution is per 512-byte block, so guest windows own
 * whole blocks. */
#define WT_GUEST_WINDOW_GRANULE  512u
/* The guests' console window (USART3) in the manifest; WT_SHARED_UART
 * (3 by default) picks each guest's console: 1 and 2 put a guest on USART2. */
#define WT_GUEST_UART_BASE       0x40004800u
#define WT_GUEST_UART_SIZE       0x00000400u
#define WT_GUEST_CONSOLE_SIZE    WT_GUEST_UART_SIZE
#ifndef WT_SHARED_UART
#define WT_SHARED_UART           3
#endif
#if WT_SHARED_UART == 3
#define WT_GUEST0_CONSOLE_BASE   0x40004800u
#else
#define WT_GUEST0_CONSOLE_BASE   0x40004400u
#endif
#if WT_SHARED_UART == 1 || WT_SHARED_UART == 2
#define WT_GUEST1_CONSOLE_BASE   0x40004400u
#else
#define WT_GUEST1_CONSOLE_BASE   0x40004800u
#endif

#define WT_RAM_S_BASE            0x30028000u
#define WT_RAM_S_SIZE            0x00080000u
/* wolfBoot writes its measured-boot record here; the scratch up to
 * WT_RAM_S_BASE is cleared once the record is consumed. */
#define WT_BOOT_HANDOFF_ADDRESS  0x30020000u

#include "../common/armv8m/l3_layout.h"

/* wolfBoot update partition (WOLFBOOT_PARTITION_UPDATE_ADDRESS): the secure
 * flash window SERVICE_FWU stages a candidate image into (WT-FWU-0002). Secure
 * alias, inside the writable secure-alias MPU region. */
#define WT_FWU_UPDATE_FLASH_BASE_S 0x0C100000u
#define WT_FWU_UPDATE_FLASH_SIZE   0x00040000u

#define WT_SHARED_STATUS_ADDR    0x20000000u

#define WT_PLATFORM_CORE_CLOCK_HZ 240000000u

/* A Secure peripheral only the SPM drives (the RNG, WT_RNG_BASE_S), probed by
 * the periphsp negative. */
#define WT_L3_SPM_PERIPHERAL_BASE 0x520C0800u

#include "../common/armv8m/memory_map_check.h"

#endif
