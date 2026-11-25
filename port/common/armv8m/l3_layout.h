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

/* From WT_RAM_S_BASE upward: SPM RAM (.data, .bss, then the main stack), the
 * VNET and crypto data bands, the keystore (vault and attestation data), the
 * partition stacks, the conformance window, and the update stack. Only bands
 * after the fixed partition stacks change with the build, so each manifest
 * names one stack address per partition. */
#ifndef WT_L3_SPM_RAM_SIZE
#define WT_L3_SPM_RAM_SIZE       0x0004D000u
#endif

/* Data bands, sized to their sections with headroom; a band its sections
 * outgrow fails the link (secure_l3_tail.ld). */
#ifndef WT_SP_VAULT_DATA_SIZE
#define WT_SP_VAULT_DATA_SIZE    0x00001000u
#endif
#ifndef WT_SP_ATTEST_DATA_SIZE
#define WT_SP_ATTEST_DATA_SIZE   0x00000200u
#endif
#ifndef WT_SP_HSM_DATA_SIZE
#if defined(WT_ENGINE_HSM) && (defined(CONFIG_TPM) || defined(CONFIG_PKCS11))
/* The interface provider holds its own wolfHSM server context. */
#define WT_SP_HSM_DATA_SIZE      0x00006800u
#elif defined(WT_ENGINE_HSM)
#define WT_SP_HSM_DATA_SIZE      0x00006000u
#else
#define WT_SP_HSM_DATA_SIZE      0x00000600u
#endif
#endif
/* Interface data and stack: measured peak plus headroom (docs/Footprint.md). */
#if defined(CONFIG_TPM)
#define WT_INTERFACE_DATA_SIZE   0x00007000u
#define WT_INTERFACE_STACK_SIZE  0x00002400u
#elif defined(CONFIG_PKCS11)
#define WT_INTERFACE_DATA_SIZE   0x0000B000u
#define WT_INTERFACE_STACK_SIZE  0x00002000u
#else
#define WT_INTERFACE_DATA_SIZE   0x00000000u
#define WT_INTERFACE_STACK_SIZE  0x00000000u
#endif
#if defined(CONFIG_TPM) || defined(CONFIG_PKCS11)
/* CONFIG_TPM and CONFIG_PKCS11 exclude CONFIG_VNET and reuse its band. */
#define WT_VNET_DATA_SIZE \
    (WT_INTERFACE_DATA_SIZE + WT_INTERFACE_STACK_SIZE)
#elif defined(CONFIG_VNET)
#define WT_VNET_DATA_SIZE        0x00005000u
#else
#define WT_VNET_DATA_SIZE        0x00000000u
#endif

/* Partition stacks, from the high-water marks measured on M33MU with
 * headroom; PSPLIM_S faults a partition that overruns its own. */
#ifndef WT_SP_PS_STACK_SIZE
#define WT_SP_PS_STACK_SIZE      0x00000C00u
#endif
#ifndef WT_SP_ITS_STACK_SIZE
#define WT_SP_ITS_STACK_SIZE     0x00000C00u
#endif
#ifndef WT_SP_VAULT_STACK_SIZE
#define WT_SP_VAULT_STACK_SIZE   0x00001400u
#endif
/* The wolfHSM server runs on the crypto partition's stack (4,856 bytes
 * measured); a native-wire verify peaks at 4,416, and mk/layout.mk sizes
 * the Cortex-M assembly's 7,240. */
#ifndef WT_SP_CRYPTO_STACK_SIZE
#if defined(WT_ENGINE_HSM)
#define WT_SP_CRYPTO_STACK_SIZE  0x00001800u
#else
#define WT_SP_CRYPTO_STACK_SIZE  0x00001400u
#endif
#endif
#ifndef WT_SP_ATTEST_STACK_SIZE
#define WT_SP_ATTEST_STACK_SIZE  0x00001400u
#endif
#ifndef WT_SP_FWU_STACK_SIZE_RESERVED
#define WT_SP_FWU_STACK_SIZE_RESERVED 0x00001000u
#endif

/* The VNET band and the engine-sized crypto stack and data band sit just
 * below the keystore, so their sizes move no other partition's stack. */
#if defined(CONFIG_TPM) || defined(CONFIG_PKCS11)
/* The interface band sits above the SPM's private RAM, not carved from it. */
#define WT_KEYSTORE_BASE \
    (WT_RAM_S_BASE + WT_L3_SPM_RAM_SIZE + WT_VNET_DATA_SIZE)
#else
#define WT_KEYSTORE_BASE         (WT_RAM_S_BASE + WT_L3_SPM_RAM_SIZE)
#endif
#define WT_SP_HSM_DATA_BASE      (WT_KEYSTORE_BASE - WT_SP_HSM_DATA_SIZE)
#define WT_SP_CRYPTO_STACK_BASE  (WT_SP_HSM_DATA_BASE - WT_SP_CRYPTO_STACK_SIZE)
#define WT_VNET_DATA_BASE        (WT_SP_CRYPTO_STACK_BASE - WT_VNET_DATA_SIZE)
/* The lowest partition-writable byte; SPM-private RAM ends here. */
#define WT_L3_BANDS_BASE         WT_VNET_DATA_BASE

/* Keystore envelope: the vault and attestation partitions each own one
 * private writable band, so no two partitions share a writable byte. */
#define WT_KEYSTORE_SIZE         (WT_SP_VAULT_DATA_SIZE + WT_SP_ATTEST_DATA_SIZE)
#define WT_SP_VAULT_DATA_BASE    WT_KEYSTORE_BASE
#define WT_SP_ATTEST_DATA_BASE \
    (WT_SP_VAULT_DATA_BASE + WT_SP_VAULT_DATA_SIZE)

#define WT_SP_PS_STACK_BASE      (WT_KEYSTORE_BASE + WT_KEYSTORE_SIZE)
#define WT_SP_ITS_STACK_BASE     (WT_SP_PS_STACK_BASE + WT_SP_PS_STACK_SIZE)
#define WT_SP_VAULT_STACK_BASE   (WT_SP_ITS_STACK_BASE + WT_SP_ITS_STACK_SIZE)

/* The attestation and (conformance builds) Arm suite partitions' stacks
 * form one region. */
#define WT_SP_SECURE_RAM_BASE \
    (WT_SP_VAULT_STACK_BASE + WT_SP_VAULT_STACK_SIZE)
#define WT_SP_ATTEST_STACK_BASE  WT_SP_SECURE_RAM_BASE
#define WT_SP_FF_STACK_SIZE      0x00002000u
/* The Arm suite partitions' stack slot, named by the conformance manifest. */
#define WT_SP_SECURE_STACK_SIZE  WT_SP_FF_STACK_SIZE
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
#define WT_SP_FF_STACK_COUNT     3u
#else
#define WT_SP_FF_STACK_COUNT     0u
#endif
#define WT_SP_FF_SERVER_STACK_BASE \
    (WT_SP_ATTEST_STACK_BASE + WT_SP_ATTEST_STACK_SIZE)
#define WT_SP_FF_DRIVER_STACK_BASE \
    (WT_SP_FF_SERVER_STACK_BASE + WT_SP_FF_STACK_SIZE)
#define WT_SP_FF_CLIENT_STACK_BASE \
    (WT_SP_FF_DRIVER_STACK_BASE + WT_SP_FF_STACK_SIZE)
#define WT_SP_SECURE_RAM_END \
    (WT_SP_FF_SERVER_STACK_BASE + WT_SP_FF_STACK_COUNT * WT_SP_FF_STACK_SIZE)
#define WT_SP_SECURE_RAM_SIZE \
    (WT_SP_SECURE_RAM_END - WT_SP_SECURE_RAM_BASE)

/* Conformance partition .data/.bss window; CONFIG_VNET and WT_CONFORMANCE
 * are exclusive, so the VNET stack reuses it. Empty in production builds. */
#define WT_CONF_SP_DATA_BASE     WT_SP_SECURE_RAM_END
#if (defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)) || defined(CONFIG_VNET)
#define WT_CONF_SP_DATA_SIZE     0x00003000u
#else
#define WT_CONF_SP_DATA_SIZE     0x00000000u
#endif
#define WT_SP_VNET_STACK_BASE    WT_CONF_SP_DATA_BASE
#define WT_SP_VNET_STACK_SIZE    WT_CONF_SP_DATA_SIZE

/* Nominal code slot of each Secure Partition in the manifest: 4 KiB per
 * partition from 64 KiB into the Secure image. */
#define WT_SP_CODE_BASE          (WT_SECURE_FLASH_BASE + 0x00010000u)
#define WT_SP_CODE_SLOT_SIZE     0x00001000u

/* Interface state and stack share the auxiliary window, disjoint MPU grants. */
#define WT_INTERFACE_DATA_BASE     WT_VNET_DATA_BASE
#define WT_SP_INTERFACE_STACK_BASE \
    (WT_INTERFACE_DATA_BASE + WT_INTERFACE_DATA_SIZE)
#define WT_SP_INTERFACE_STACK_SIZE WT_INTERFACE_STACK_SIZE

/* Per-partition pseudo-MMIO holes at the top of the conformance window; must
 * match SERVER/DRIVER_PARTITION_MMIO_0_* in tests/conformance/pal/pal_config.h. */
#define WT_CONF_SERVER_MMIO_BASE (WT_CONF_SP_DATA_BASE + 0x00002C00u)
#define WT_CONF_SERVER_MMIO_SIZE 0x00000100u
#define WT_CONF_DRV_MMIO_BASE    (WT_CONF_SP_DATA_BASE + 0x00002E00u)
#define WT_CONF_DRV_MMIO_SIZE    0x00000100u

/* The update partition's stack tops the layout, so dropping it (WT_FWU=0)
 * frees its band without moving any other partition's stack. */
#define WT_SP_FWU_STACK_BASE     (WT_CONF_SP_DATA_BASE + WT_CONF_SP_DATA_SIZE)
#if defined(WT_FWU)
#define WT_SP_FWU_STACK_SIZE     WT_SP_FWU_STACK_SIZE_RESERVED
#else
#define WT_SP_FWU_STACK_SIZE     0x00000000u
#endif
#define WT_L3_RAM_END            (WT_SP_FWU_STACK_BASE + WT_SP_FWU_STACK_SIZE)

#if (WT_L3_RAM_END - WT_RAM_S_BASE) > WT_RAM_S_SIZE
#error "the level 3 secure RAM layout does not fit WT_RAM_S_SIZE"
#endif
#if ((WT_SP_VAULT_DATA_SIZE | WT_SP_ATTEST_DATA_SIZE | WT_SP_HSM_DATA_SIZE | \
      WT_SP_PS_STACK_SIZE | WT_SP_ITS_STACK_SIZE | WT_SP_VAULT_STACK_SIZE | \
      WT_SP_CRYPTO_STACK_SIZE | WT_SP_ATTEST_STACK_SIZE | \
      WT_SP_FWU_STACK_SIZE_RESERVED) & 0x1Fu) != 0u
#error "level 3 band and stack sizes must be 32-byte multiples (MPU granule)"
#endif

#endif
