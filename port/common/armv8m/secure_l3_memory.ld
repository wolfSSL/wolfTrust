/* secure_l3_memory.ld
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

/* Isolation level 3 secure RAM regions, INCLUDEd inside a port's MEMORY
 * block. WT_RAM_S_ORIGIN is WT_RAM_S_BASE from the port's memory_map.h;
 * every offset mirrors port/common/armv8m/l3_layout.h. */

  /* General SPM RAM up to the keystore bands, less the VNET band when built. */
  RAM   (rwx): ORIGIN = WT_RAM_S_ORIGIN, LENGTH = 308K - WT_VNET_DATA_LENGTH
  /* SERVICE_VNET data band; zero length outside CONFIG_VNET builds. */
  VNETDATA (rw): ORIGIN = WT_RAM_S_ORIGIN + 308K - WT_VNET_DATA_LENGTH,
                 LENGTH = WT_VNET_DATA_LENGTH
  /* Keystore bands: the vault, attestation and crypto partitions each own one. */
  VAULTDATA (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x4D000, LENGTH = 8K
  ATTESTDATA (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x4F000, LENGTH = 2K
  HSMDATA (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x4F800, LENGTH = 70K
  /* Partition execution stacks, each also the partition's MPU RW resource. */
  FWUSTACK (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x61000, LENGTH = 8K
  PSSTACK (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x63000, LENGTH = 8K
  ITSSTACK (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x65000, LENGTH = 8K
  VAULTSTACK (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x67000, LENGTH = 16K
  /* Conformance partition data; CONFIG_VNET builds use it as the VNET stack. */
  CONFDATA (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x6B000, LENGTH = 12K
  SPSTACKS (rw): ORIGIN = WT_RAM_S_ORIGIN + 0x6E000, LENGTH = 40K
