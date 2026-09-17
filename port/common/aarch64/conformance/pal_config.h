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

/* Arm psa-arch-tests PAL target configuration for wolfTrust on the AArch64
 * QEMU virt / Versal targets. The DRIVER partition's NVMEM is a RAM shadow
 * written through the SVC gate into a .noinit band (survives the warm reset the
 * panic tests use); the UART/watchdog values name devices the driver plane
 * uses once VERBOSITY routing lands. The per-partition MMIO holes are unmapped
 * secure addresses the isolation tests probe expecting a fault. */

#ifndef _PAL_CONFIG_H_
#define _PAL_CONFIG_H_

#include "conf_nvm.h"

#define PLATFORM_PSA_ISOLATION_LEVEL 3

#define UART_NUM                               1
#define UART_0_BASE                            0x09000000
#define UART_0_SIZE                            0xFFF
#define UART_0_INTR_ID                         0xFF
#define UART_0_PERMISSION                      TYPE_READ_WRITE

#define WATCHDOG_NUM                           1
#define WATCHDOG_0_BASE                        0x0E3F0000
#define WATCHDOG_0_SIZE                        0x3FF
#define WATCHDOG_0_INTR_ID                     0xFF
#define WATCHDOG_0_PERMISSION                  TYPE_READ_WRITE
#define WATCHDOG_0_NUM_OF_TICK_PER_MICRO_SEC   0x3
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_LOW    0xF4240
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_MEDIUM 0x1E8480
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_HIGH   0x4C4B40
#define WATCHDOG_0_TIMEOUT_IN_MICRO_SEC_CRYPTO 0x1312D00

#define NVMEM_NUM                              1
#define NVMEM_0_START                          0x0E3F1000
#define NVMEM_0_END                            0x0E3F13FF
#define NVMEM_0_PERMISSION                     TYPE_READ_WRITE

#define NSPE_MMIO_NUM                          1
#define NSPE_MMIO_0_START                      0x44080000
#define NSPE_MMIO_0_END                        0x4408001F
#define NSPE_MMIO_0_PERMISSION                 TYPE_READ_WRITE

/* Per-partition pseudo-MMIO holes near the top of the shared conformance data
 * band, above its .data/.bss fill. The band is granted to the test partitions,
 * so a partition reaches its own hole; the L3 isolation tests carve each hole
 * out of every other partition's grant (a later slice) so a cross-partition
 * poke faults. WT_SPM_CONFDATA_PA is a -D on the secure conformance build. */
#define SERVER_PARTITION_MMIO_NUM              1
#define SERVER_PARTITION_MMIO_0_START          (WT_SPM_CONFDATA_PA + WT_CONF_SERVER_MMIO_OFFSET)
#define SERVER_PARTITION_MMIO_0_END            (SERVER_PARTITION_MMIO_0_START + 0x100u)
#define SERVER_PARTITION_MMIO_0_PERMISSION     TYPE_READ_WRITE

#define DRIVER_PARTITION_MMIO_NUM              1
#define DRIVER_PARTITION_MMIO_0_START          (WT_SPM_CONFDATA_PA + WT_CONF_DRIVER_MMIO_OFFSET)
#define DRIVER_PARTITION_MMIO_0_END            (DRIVER_PARTITION_MMIO_0_START + 0x100u)
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

/* dev_apis Storage: the val NSPE and test TUs reach the PSA storage types and
 * API version macros through this per-target config. */
#if defined(STORAGE) || defined(INTERNAL_TRUSTED_STORAGE) || \
    defined(PROTECTED_STORAGE)
#include "psa/internal_trusted_storage.h"
#include "psa/protected_storage.h"
#define ARCH_TEST_STORAGE_UID_MAX_SIZE 512
#endif

/* dev_apis Crypto: wolfPSA is the guest's psa_* provider; the algorithm
 * surface the suite may exercise lives in pal_crypto_config.h. */
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
