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

/* Isolation level 3 Secure band layout shared by every AArch64 port. A port's
 * memory_map.h defines WT_L3_BAND_BASE (1 MiB aligned) and WT_RAM_S_BASE,
 * then includes this; tools/aarch64_l3_layout.py hands the build the same
 * values. */

#ifndef WOLFTRUST_PORT_AARCH64_L3_LAYOUT_H
#define WOLFTRUST_PORT_AARCH64_L3_LAYOUT_H

/* Guests and host tests include the port map without the build's level. */
#if defined(WT_ISOLATION_LEVEL) && (WT_ISOLATION_LEVEL != 3)
#error "the shared AArch64 layout implements isolation level 3 only"
#endif
#if !defined(WT_L3_BAND_BASE) || !defined(WT_RAM_S_BASE)
#error "define WT_L3_BAND_BASE and WT_RAM_S_BASE before including l3_layout.h"
#endif

/* The FF-A boot information page opens Secure RAM; the table pool follows. */
#ifndef WT_SPM_BOOT_INFO_PA
#define WT_SPM_BOOT_INFO_PA   WT_RAM_S_BASE
#endif
#ifndef WT_SPM_TABLE_POOL_PA
#define WT_SPM_TABLE_POOL_PA  (WT_RAM_S_BASE + 0x00001000u)
#endif
#ifndef WT_SPM_IMAGE_PA
#define WT_SPM_IMAGE_PA       (WT_L3_BAND_BASE + 0x00100000u)
#endif
#ifndef WT_SPM_IMAGE_SIZE
#define WT_SPM_IMAGE_SIZE     0x00100000u
#endif
#ifndef WT_SPM_RAM_PA
#define WT_SPM_RAM_PA         (WT_L3_BAND_BASE + 0x00200000u)
#endif
#ifndef WT_SPM_RAM_SIZE
#define WT_SPM_RAM_SIZE       0x00040000u
#endif
/* Where a boot loader leaves its handoff record (the emulator synthesizes it). */
#define WT_L3_HANDOFF_PA      (WT_L3_BAND_BASE + 0x00240000u)
#ifndef WT_SPM_CONFDATA_PA
#define WT_SPM_CONFDATA_PA    (WT_L3_BAND_BASE + 0x002C0000u)
#endif
#ifndef WT_SPM_CONFDATA_SIZE
#define WT_SPM_CONFDATA_SIZE  0x00020000u
#endif

/* Keystore window: the vault, attestation and crypto partitions each own one
 * private band in it, and the port manifests grant exactly these. */
#ifndef WT_SPM_KEYSTORE_PA
#define WT_SPM_KEYSTORE_PA    (WT_L3_BAND_BASE + 0x00300000u)
#endif
#ifndef WT_SPM_KEYSTORE_SIZE
#define WT_SPM_KEYSTORE_SIZE  0x00040000u
#endif
#define WT_SPM_VAULT_PA       WT_SPM_KEYSTORE_PA
#define WT_SPM_VAULT_SIZE     0x00024000u
#define WT_SPM_ATTEST_PA      (WT_SPM_VAULT_PA + WT_SPM_VAULT_SIZE)
#define WT_SPM_ATTEST_SIZE    0x00001000u
#define WT_SPM_HSMDATA_PA     (WT_SPM_ATTEST_PA + WT_SPM_ATTEST_SIZE)
#define WT_SPM_HSMDATA_SIZE   0x0001B000u

#ifndef WT_SPM_RXTX_PA
#define WT_SPM_RXTX_PA        (WT_L3_BAND_BASE + 0x00340000u)
#endif
#ifndef WT_SPM_RXTX_SIZE
#define WT_SPM_RXTX_SIZE      0x00002000u
#endif
/* One page the SPMC shares to a partition through FFA_MEM_SHARE at boot. */
#ifndef WT_SPM_SHARE_PA
#define WT_SPM_SHARE_PA       (WT_L3_BAND_BASE + 0x00342000u)
#endif
#ifndef WT_SPM_SHARE_SIZE
#define WT_SPM_SHARE_SIZE     0x00001000u
#endif
/* Arm FF-A ACS conformance images: SP1..SP4 load into 1 MB bands from here. */
#define WT_L3_FFA_ACS_PA      (WT_L3_BAND_BASE + 0x00400000u)

#if (WT_SPM_HSMDATA_PA + WT_SPM_HSMDATA_SIZE) != \
    (WT_SPM_KEYSTORE_PA + WT_SPM_KEYSTORE_SIZE)
#error "the keystore bands must tile the keystore window exactly"
#endif
#if (WT_SPM_KEYSTORE_PA + WT_SPM_KEYSTORE_SIZE) > WT_SPM_RXTX_PA
#error "the keystore window overlaps the RX/TX band"
#endif

/* A band moved on the command line must stay in Secure RAM. */
#define WT_L3_IN_RAM_S(pa, size) (((pa) >= WT_RAM_S_BASE) && \
    ((size) <= WT_RAM_S_SIZE) && \
    (((pa) - WT_RAM_S_BASE) <= (WT_RAM_S_SIZE - (size))))
#if !WT_L3_IN_RAM_S(WT_SPM_BOOT_INFO_PA, 0x1000u) || \
    !WT_L3_IN_RAM_S(WT_SPM_TABLE_POOL_PA, 0x1000u) || \
    !WT_L3_IN_RAM_S(WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE) || \
    !WT_L3_IN_RAM_S(WT_SPM_RAM_PA, WT_SPM_RAM_SIZE) || \
    !WT_L3_IN_RAM_S(WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE) || \
    !WT_L3_IN_RAM_S(WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE) || \
    !WT_L3_IN_RAM_S(WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE) || \
    !WT_L3_IN_RAM_S(WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE)
#error "a level 3 band lies outside the port's Secure RAM"
#endif
#if defined(WT_SPM_TABLE_POOL_PAGES) && \
    ((WT_SPM_TABLE_POOL_PAGES > (WT_RAM_S_SIZE / 0x1000u)) || \
     !WT_L3_IN_RAM_S(WT_SPM_TABLE_POOL_PA, WT_SPM_TABLE_POOL_PAGES * 0x1000u))
#error "the table pool lies outside the port's Secure RAM"
#endif

#if defined(WT_SPM_TABLE_POOL_PAGES)
#define WT_L3_POOL_SIZE (WT_SPM_TABLE_POOL_PAGES * 0x1000u)
#else
#define WT_L3_POOL_SIZE 0x1000u
#endif
#define WT_L3_APART(a, as, b, bs) \
    ((((a) + (as)) <= (b)) || (((b) + (bs)) <= (a)))
#if ((WT_SPM_BOOT_INFO_PA | WT_SPM_TABLE_POOL_PA | WT_SPM_IMAGE_PA | \
      WT_SPM_IMAGE_SIZE | WT_SPM_RAM_PA | WT_SPM_RAM_SIZE | \
      WT_SPM_CONFDATA_PA | WT_SPM_CONFDATA_SIZE | WT_SPM_KEYSTORE_PA | \
      WT_SPM_KEYSTORE_SIZE | WT_SPM_RXTX_PA | WT_SPM_RXTX_SIZE | \
      WT_SPM_SHARE_PA | WT_SPM_SHARE_SIZE) & 0xFFFu) != 0u
#error "a level 3 band is not page aligned"
#endif
#if !WT_L3_APART(WT_SPM_BOOT_INFO_PA, 0x1000u, WT_SPM_TABLE_POOL_PA, WT_L3_POOL_SIZE) || \
    !WT_L3_APART(WT_SPM_BOOT_INFO_PA, 0x1000u, WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE) || \
    !WT_L3_APART(WT_SPM_BOOT_INFO_PA, 0x1000u, WT_SPM_RAM_PA, WT_SPM_RAM_SIZE) || \
    !WT_L3_APART(WT_SPM_BOOT_INFO_PA, 0x1000u, WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE) || \
    !WT_L3_APART(WT_SPM_BOOT_INFO_PA, 0x1000u, WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE) || \
    !WT_L3_APART(WT_SPM_BOOT_INFO_PA, 0x1000u, WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE) || \
    !WT_L3_APART(WT_SPM_BOOT_INFO_PA, 0x1000u, WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE) || \
    !WT_L3_APART(WT_SPM_TABLE_POOL_PA, WT_L3_POOL_SIZE, WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE) || \
    !WT_L3_APART(WT_SPM_TABLE_POOL_PA, WT_L3_POOL_SIZE, WT_SPM_RAM_PA, WT_SPM_RAM_SIZE) || \
    !WT_L3_APART(WT_SPM_TABLE_POOL_PA, WT_L3_POOL_SIZE, WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE) || \
    !WT_L3_APART(WT_SPM_TABLE_POOL_PA, WT_L3_POOL_SIZE, WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE) || \
    !WT_L3_APART(WT_SPM_TABLE_POOL_PA, WT_L3_POOL_SIZE, WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE) || \
    !WT_L3_APART(WT_SPM_TABLE_POOL_PA, WT_L3_POOL_SIZE, WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE) || \
    !WT_L3_APART(WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE, WT_SPM_RAM_PA, WT_SPM_RAM_SIZE) || \
    !WT_L3_APART(WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE, WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE) || \
    !WT_L3_APART(WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE, WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE) || \
    !WT_L3_APART(WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE, WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE) || \
    !WT_L3_APART(WT_SPM_IMAGE_PA, WT_SPM_IMAGE_SIZE, WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE) || \
    !WT_L3_APART(WT_SPM_RAM_PA, WT_SPM_RAM_SIZE, WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE) || \
    !WT_L3_APART(WT_SPM_RAM_PA, WT_SPM_RAM_SIZE, WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE) || \
    !WT_L3_APART(WT_SPM_RAM_PA, WT_SPM_RAM_SIZE, WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE) || \
    !WT_L3_APART(WT_SPM_RAM_PA, WT_SPM_RAM_SIZE, WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE) || \
    !WT_L3_APART(WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE, WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE) || \
    !WT_L3_APART(WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE, WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE) || \
    !WT_L3_APART(WT_SPM_CONFDATA_PA, WT_SPM_CONFDATA_SIZE, WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE) || \
    !WT_L3_APART(WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE, WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE) || \
    !WT_L3_APART(WT_SPM_KEYSTORE_PA, WT_SPM_KEYSTORE_SIZE, WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE) || \
    !WT_L3_APART(WT_SPM_RXTX_PA, WT_SPM_RXTX_SIZE, WT_SPM_SHARE_PA, WT_SPM_SHARE_SIZE)
#error "two level 3 bands overlap"
#endif

#endif /* WOLFTRUST_PORT_AARCH64_L3_LAYOUT_H */
