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

#ifndef WOLFTRUST_FW_MIMXRT700_MEMORY_MAP_H
#define WOLFTRUST_FW_MIMXRT700_MEMORY_MAP_H

/* MIMXRT798S compute domain (cpu0). Bit 28 of every address selects the
 * Secure alias: XSPI0 NOR is 0x28000000 (NS) / 0x38000000 (S), SRAM data is
 * 0x20000000 (NS) / 0x30000000 (S), peripherals 0x40000000 (NS) /
 * 0x50000000 (S). */
#ifndef WT_SECURE_FLASH_BASE
#define WT_SECURE_FLASH_BASE     0x38040000u
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

#define WT_FLASH_NS_BASE         0x28000000u
#define WT_FLASH_S_ALIAS_BASE    0x38000000u
#define WT_FLASH_ALIAS_SIZE      0x04000000u
#define WT_FLASH_TO_S_ALIAS(address) \
    ((address) - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE)
#ifndef WT_GUEST0_FLASH_BASE
#define WT_GUEST0_FLASH_BASE     0x28080000u
#endif
#ifndef WT_GUEST1_FLASH_BASE
#define WT_GUEST1_FLASH_BASE     0x28100000u
#endif
#ifndef WT_GUEST0_FLASH_SIZE
#define WT_GUEST0_FLASH_SIZE     0x00080000u
#endif
#ifndef WT_GUEST1_FLASH_SIZE
#define WT_GUEST1_FLASH_SIZE     0x00040000u
#endif

/* Secure wolfHSM NVM store: two mirrored 4 KiB NOR sectors near the top of
 * the first 2 MiB of XSPI0, above the wolfBoot update and swap partitions. */
#define WT_FLASH_SECTOR_SIZE       0x00001000u
#define WT_FLASH_PAGE_SIZE         0x00000100u
#define WT_HSM_NVM_FLASH_BASE_NS   0x281E0000u
#define WT_HSM_NVM_FLASH_BASE_S    0x381E0000u
#define WT_HSM_NVM_FLASH_SIZE      0x00002000u

#define WT_CONF_NVM_FLASH_BASE_NS  0x281E8000u
#define WT_CONF_NVM_FLASH_BASE_S   0x381E8000u
#define WT_CONF_NVM_FLASH_SIZE     0x00001000u

/* Non-secure guest RAM: two 256 KiB windows inside the compute-domain SRAM
 * partitions (AHBSC rule granularity, not the 512 B GTZC blocks of the H5). */
#define WT_RAM_NS_BASE           0x20100000u
#define WT_PLATFORM_GUEST_STACK_WINDOW_BASE WT_RAM_NS_BASE
#define WT_PLATFORM_GUEST_STACK_WINDOW_SIZE 0x00080000u
#define WT_GUEST0_RAM_BASE       0x20100000u
#define WT_GUEST1_RAM_BASE       0x20140000u
#define WT_GUEST_RAM_SIZE        0x00040000u

/* Secure runtime RAM: the cpu0 application SRAM (sram0) through its Secure
 * alias. The band layout below mirrors the H5 port shifted to this base so
 * secure.ld and manifest.json stay in lockstep by one constant. */
#define WT_RAM_S_BASE            0x30188000u
#define WT_RAM_S_SIZE            0x00078000u
#define WT_BOOT_HANDOFF_ADDRESS  0x30180000u

#define WT_SP_SECURE_STACK_SIZE  0x00002000u
#define WT_SP_SECURE_STACK_COUNT 5u
#define WT_SP_SECURE_RAM_SIZE \
    (WT_SP_SECURE_STACK_SIZE * WT_SP_SECURE_STACK_COUNT)
#define WT_SP_SECURE_RAM_BASE    (WT_RAM_S_BASE + 0x0006E000u)  /* 0x301F6000 */
#define WT_SP_SECURE_RAM_END \
    (WT_SP_SECURE_RAM_BASE + WT_SP_SECURE_RAM_SIZE)             /* 0x30200000 */
#define WT_SP_CRYPTO_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 0u * WT_SP_SECURE_STACK_SIZE)
#define WT_SP_ATTEST_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 1u * WT_SP_SECURE_STACK_SIZE)
#define WT_SP_FF_SERVER_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 2u * WT_SP_SECURE_STACK_SIZE)
#define WT_SP_FF_DRIVER_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 3u * WT_SP_SECURE_STACK_SIZE)
#define WT_SP_FF_CLIENT_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 4u * WT_SP_SECURE_STACK_SIZE)

#define WT_CONF_SP_DATA_BASE     (WT_RAM_S_BASE + 0x0006B000u)  /* 0x301F3000 */
#define WT_CONF_SP_DATA_SIZE     0x00003000u

#define WT_SP_VAULT_STACK_BASE   (WT_RAM_S_BASE + 0x00067000u)  /* 0x301EF000 */
#define WT_SP_VAULT_STACK_SIZE   0x00004000u

#define WT_SP_ITS_STACK_BASE     (WT_RAM_S_BASE + 0x00065000u)  /* 0x301ED000 */
#define WT_SP_ITS_STACK_SIZE     WT_SP_SECURE_STACK_SIZE

#define WT_SP_PS_STACK_BASE      (WT_RAM_S_BASE + 0x00063000u)  /* 0x301EB000 */
#define WT_SP_PS_STACK_SIZE      WT_SP_SECURE_STACK_SIZE

#define WT_SP_FWU_STACK_BASE     (WT_RAM_S_BASE + 0x00061000u)  /* 0x301E9000 */
#define WT_SP_FWU_STACK_SIZE     WT_SP_SECURE_STACK_SIZE

#define WT_KEYSTORE_BASE         (WT_RAM_S_BASE + 0x0004D000u)  /* 0x301D5000 */
#define WT_KEYSTORE_SIZE         0x00014000u

#define WT_SP_VNET_STACK_BASE    (WT_RAM_S_BASE + 0x0006B000u)  /* 0x301F3000 */
#define WT_SP_VNET_STACK_SIZE    WT_SP_SECURE_STACK_SIZE

#define WT_VNET_DATA_BASE        (WT_RAM_S_BASE + 0x00048000u)  /* 0x301D0000 */
#define WT_VNET_DATA_SIZE        0x00005000u

/* wolfBoot update partition on XSPI0 (Secure alias). */
#define WT_FWU_UPDATE_FLASH_BASE_S 0x38180000u
#define WT_FWU_UPDATE_FLASH_SIZE   0x00040000u

#define WT_CONF_SERVER_MMIO_BASE (WT_CONF_SP_DATA_BASE + 0x00002C00u)
#define WT_CONF_SERVER_MMIO_SIZE 0x00000100u
#define WT_CONF_DRV_MMIO_BASE    (WT_CONF_SP_DATA_BASE + 0x00002E00u)
#define WT_CONF_DRV_MMIO_SIZE    0x00000100u

#define WT_SHARED_STATUS_ADDR    0x20100000u

/* RAM code band: the Non-secure-callable gateway (SG veneers and entry
 * bodies) and the XSPI0 NOR program/erase code. It executes through the
 * Secure Code-region alias of SRAM because the IDAU honours NSC only in the
 * Code region, and the NOR serves no XIP fetches while busy. The SRAM is
 * aliased at 0x0/0x1/0x2/0x3 (NS code / S code / NS data / S data) with the
 * same offset; the band is copied through the Secure data alias. */
#define WT_RAMFUNC_BASE          0x10200000u
#define WT_RAMFUNC_SIZE          0x00004000u
#define WT_SRAM_CODE_TO_DATA     0x20000000u
#define WT_NSC_BASE              WT_RAMFUNC_BASE
#define WT_NSC_END               (WT_NSC_BASE + 0x000003FFu)

#ifndef WT_PLATFORM_CORE_CLOCK_HZ
#define WT_PLATFORM_CORE_CLOCK_HZ 237500000u
#endif

#endif
