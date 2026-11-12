/* pal_config.h
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

/* Arm psa-arch-tests PAL target configuration for wolfTrust. Every address
 * comes from the port's memory_map.h, so the one PAL serves every port: the
 * device bases are reported only, the NVMEM window is the conformance flash
 * sector, the NSPE window is the top of guest0's RAM (reserved by the guest
 * linker scripts), and the partition MMIO holes are the level 3 layout's. */

#ifndef _PAL_CONFIG_H_
#define _PAL_CONFIG_H_

#include "memory_map.h"

#ifndef WT_GUEST0_RAM_SIZE
#define WT_GUEST0_RAM_SIZE WT_GUEST_RAM_SIZE
#endif

#define PLATFORM_PSA_ISOLATION_LEVEL 3

#define UART_NUM                               1
#define UART_0_BASE                            WT_CONF_UART_BASE
#define UART_0_SIZE                            0x3FF
#define UART_0_INTR_ID                         0xFF
#define UART_0_PERMISSION                      TYPE_READ_WRITE

#define WATCHDOG_NUM                           1
#define WATCHDOG_0_BASE                        WT_CONF_WDG_BASE
#define WATCHDOG_0_SIZE                        0x3FF
#define WATCHDOG_0_INTR_ID                     0xFF
#define WATCHDOG_0_PERMISSION                  TYPE_READ_WRITE
#define WATCHDOG_0_NUM_OF_TICK_PER_MICRO_SEC   0x3
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_LOW    0xF4240
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_MEDIUM 0x1E8480
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_HIGH   0x4C4B40
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_CRYPTO 0x1312D00

#define NVMEM_NUM                              1
#define NVMEM_0_START                          WT_CONF_NVM_FLASH_BASE_S
#define NVMEM_0_END                            (WT_CONF_NVM_FLASH_BASE_S + 0x3FFu)
#define NVMEM_0_PERMISSION                     TYPE_READ_WRITE

#define NSPE_MMIO_NUM                          1
#define NSPE_MMIO_0_START                      (WT_GUEST0_RAM_BASE + WT_GUEST0_RAM_SIZE - 0x20u)
#define NSPE_MMIO_0_END                        (WT_GUEST0_RAM_BASE + WT_GUEST0_RAM_SIZE - 0x1u)
#define NSPE_MMIO_0_PERMISSION                 TYPE_READ_WRITE

/* Per-partition pseudo-MMIO holes carved from the top of the shared CONFDATA
 * window, above the conformance .data/.bss fill (an #error cross-check in
 * conf_nvm_sync.c keeps them equal to the level 3 layout's). */
#define SERVER_PARTITION_MMIO_NUM              1
#define SERVER_PARTITION_MMIO_0_START          WT_CONF_SERVER_MMIO_BASE
#define SERVER_PARTITION_MMIO_0_END            (WT_CONF_SERVER_MMIO_BASE + WT_CONF_SERVER_MMIO_SIZE)
#define SERVER_PARTITION_MMIO_0_PERMISSION     TYPE_READ_WRITE

#define DRIVER_PARTITION_MMIO_NUM              1
#define DRIVER_PARTITION_MMIO_0_START          WT_CONF_DRV_MMIO_BASE
#define DRIVER_PARTITION_MMIO_0_END            (WT_CONF_DRV_MMIO_BASE + WT_CONF_DRV_MMIO_SIZE)
#define DRIVER_PARTITION_MMIO_0_PERMISSION     TYPE_READ_WRITE

#define PLATFORM_WD_BASE                        WATCHDOG_0_BASE
#define PLATFORM_WD_NUM_OF_TICK_PER_MICRO_SEC   WATCHDOG_0_NUM_OF_TICK_PER_MICRO_SEC
#define PLATFORM_WD_TIMEOUT_IN_MICRO_SEC_LOW    WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_LOW
#define PLATFORM_WD_TIMEOUT_IN_MICRO_SEC_MEDIUM WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_MEDIUM
#define PLATFORM_WD_TIMEOUT_IN_MICRO_SEC_HIGH   WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_HIGH
#define PLATFORM_WD_TIMEOUT_IN_MICRO_SEC_CRYPTO WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_CRYPTO

#define PLATFORM_NVM_BASE NVMEM_0_START

#define PLATFORM_NSPE_MMIO_START             NSPE_MMIO_0_START
#define PLATFORM_SERVER_PARTITION_MMIO_START SERVER_PARTITION_MMIO_0_START
#define PLATFORM_DRIVER_PARTITION_MMIO_START DRIVER_PARTITION_MMIO_0_START
#define PLATFORM_DRIVER_PARTITION_MMIO_END   DRIVER_PARTITION_MMIO_0_END

#ifdef IPC
#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "psa_manifest/pid.h"
#endif

/* dev_apis Storage (P4-S6): the val NSPE and test TUs reach the PSA storage
 * types and API version macros through this per-target config, mirroring the
 * upstream tgt_dev_apis targets. */
#if defined(STORAGE) || defined(INTERNAL_TRUSTED_STORAGE) || \
    defined(PROTECTED_STORAGE)
#include "psa/internal_trusted_storage.h"
#include "psa/protected_storage.h"
#define ARCH_TEST_STORAGE_UID_MAX_SIZE 512
#endif

/* dev_apis Crypto (P4-S6): wolfPSA is the guest's psa_* provider; the
 * algorithm surface the suite may exercise lives in pal_crypto_config.h. */
#if defined(CRYPTO)
#include "psa/crypto.h"
#include "pal_crypto_config.h"
#endif

#if defined(INITIAL_ATTESTATION)
#include "psa/crypto.h"
#include "psa/initial_attestation.h"
#include "pal_attestation_config.h"
#endif

#endif /* _PAL_CONFIG_H_ */
