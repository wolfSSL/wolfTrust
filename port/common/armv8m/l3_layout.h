/* l3_layout.h
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

/* Isolation level 3 secure RAM layout shared by every Armv8-M port. A port's
 * memory_map.h defines WT_RAM_S_BASE and WT_RAM_S_SIZE, then includes this.
 * port/common/armv8m/secure_l3_memory.ld places the same bands. */

#ifndef WOLFTRUST_PORT_ARMV8M_L3_LAYOUT_H
#define WOLFTRUST_PORT_ARMV8M_L3_LAYOUT_H

#if defined(WT_ISOLATION_LEVEL) && (WT_ISOLATION_LEVEL != 3)
#error "l3_layout.h is the isolation level 3 layout; WT_ISOLATION_LEVEL is not 3"
#endif

#if !defined(WT_RAM_S_BASE) || !defined(WT_RAM_S_SIZE)
#error "define WT_RAM_S_BASE and WT_RAM_S_SIZE before including l3_layout.h"
#endif

/* Per-partition secure stacks at the top of the window; slots 2-4 host the
 * Arm conformance partitions (SERVER/DRIVER/CLIENT). */
#define WT_SP_SECURE_STACK_SIZE  0x00002000u
#define WT_SP_SECURE_STACK_COUNT 5u
#define WT_SP_SECURE_RAM_SIZE \
    (WT_SP_SECURE_STACK_SIZE * WT_SP_SECURE_STACK_COUNT)
#define WT_SP_SECURE_RAM_BASE    (WT_RAM_S_BASE + 0x0006E000u)
#define WT_SP_SECURE_RAM_END \
    (WT_SP_SECURE_RAM_BASE + WT_SP_SECURE_RAM_SIZE)
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

/* Conformance partition .data/.bss window, kept outside SPM RAM. */
#define WT_CONF_SP_DATA_BASE     (WT_RAM_S_BASE + 0x0006B000u)
#define WT_CONF_SP_DATA_SIZE     0x00003000u

/* 16 KiB: ECC verify's point table overflows an 8 KiB stack (PSPLIM STKOF). */
#define WT_SP_VAULT_STACK_BASE   (WT_RAM_S_BASE + 0x00067000u)
#define WT_SP_VAULT_STACK_SIZE   0x00004000u

#define WT_SP_ITS_STACK_BASE     (WT_RAM_S_BASE + 0x00065000u)
#define WT_SP_ITS_STACK_SIZE     WT_SP_SECURE_STACK_SIZE

#define WT_SP_PS_STACK_BASE      (WT_RAM_S_BASE + 0x00063000u)
#define WT_SP_PS_STACK_SIZE      WT_SP_SECURE_STACK_SIZE

#define WT_SP_FWU_STACK_BASE     (WT_RAM_S_BASE + 0x00061000u)
#define WT_SP_FWU_STACK_SIZE     WT_SP_SECURE_STACK_SIZE

/* Keystore envelope: the vault, attestation and crypto partitions each own
 * one private writable band, so no two partitions share a writable byte. */
#define WT_KEYSTORE_BASE         (WT_RAM_S_BASE + 0x0004D000u)
#define WT_KEYSTORE_SIZE         0x00014000u
#define WT_SP_VAULT_DATA_BASE    WT_KEYSTORE_BASE
#define WT_SP_VAULT_DATA_SIZE    0x00002000u
#define WT_SP_ATTEST_DATA_BASE \
    (WT_SP_VAULT_DATA_BASE + WT_SP_VAULT_DATA_SIZE)
#define WT_SP_ATTEST_DATA_SIZE   0x00000800u
#define WT_SP_HSM_DATA_BASE \
    (WT_SP_ATTEST_DATA_BASE + WT_SP_ATTEST_DATA_SIZE)
#define WT_SP_HSM_DATA_SIZE      0x00011800u

/* CONFIG_VNET and WT_CONFORMANCE are exclusive, so the VNET stack reuses the
 * conformance data window. */
#define WT_SP_VNET_STACK_BASE    WT_CONF_SP_DATA_BASE
#define WT_SP_VNET_STACK_SIZE    WT_SP_SECURE_STACK_SIZE

#define WT_VNET_DATA_BASE        (WT_RAM_S_BASE + 0x00048000u)
#define WT_VNET_DATA_SIZE        0x00005000u

/* Per-partition pseudo-MMIO holes at the top of the conformance window; must
 * match SERVER/DRIVER_PARTITION_MMIO_0_* in the port's pal_config.h. */
#define WT_CONF_SERVER_MMIO_BASE (WT_CONF_SP_DATA_BASE + 0x00002C00u)
#define WT_CONF_SERVER_MMIO_SIZE 0x00000100u
#define WT_CONF_DRV_MMIO_BASE    (WT_CONF_SP_DATA_BASE + 0x00002E00u)
#define WT_CONF_DRV_MMIO_SIZE    0x00000100u

#if (WT_SP_SECURE_RAM_END - WT_RAM_S_BASE) > WT_RAM_S_SIZE
#error "the level 3 secure RAM layout does not fit WT_RAM_S_SIZE"
#endif

#endif
