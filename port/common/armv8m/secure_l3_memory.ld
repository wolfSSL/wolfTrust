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
 * block. WT_RAM_S_ORIGIN and the WT_L3_* symbols come from the port's
 * memory_map.h through port/common/armv8m/l3_layout.h. */

  /* General SPM RAM up to the keystore bands, less the VNET band when built. */
  RAM   (rwx): ORIGIN = WT_RAM_S_ORIGIN,
               LENGTH = WT_L3_KEYSTORE_ORIGIN - WT_RAM_S_ORIGIN - WT_VNET_DATA_LENGTH
  /* SERVICE_VNET data band; zero length outside CONFIG_VNET builds. */
  VNETDATA (rw): ORIGIN = WT_L3_KEYSTORE_ORIGIN - WT_VNET_DATA_LENGTH,
                 LENGTH = WT_VNET_DATA_LENGTH
  /* Keystore bands: the vault, attestation and crypto partitions each own one. */
  VAULTDATA (rw): ORIGIN = WT_L3_KEYSTORE_ORIGIN, LENGTH = 8K
  ATTESTDATA (rw): ORIGIN = WT_L3_KEYSTORE_ORIGIN + 8K, LENGTH = 2K
  HSMDATA (rw): ORIGIN = WT_L3_KEYSTORE_ORIGIN + 10K,
                LENGTH = WT_L3_HSM_DATA_LENGTH
  /* Partition execution stacks, each also the partition's MPU RW resource. */
  PSSTACK (rw): ORIGIN = WT_L3_STACKS_ORIGIN, LENGTH = 8K
  ITSSTACK (rw): ORIGIN = WT_L3_STACKS_ORIGIN + 8K, LENGTH = 8K
  VAULTSTACK (rw): ORIGIN = WT_L3_STACKS_ORIGIN + 16K, LENGTH = 16K
  /* Conformance partition data; CONFIG_VNET builds use it as the VNET stack. */
  CONFDATA (rw): ORIGIN = WT_L3_STACKS_ORIGIN + 32K, LENGTH = 12K
  SPSTACKS (rw): ORIGIN = WT_L3_STACKS_ORIGIN + 44K, LENGTH = 40K
  /* SERVICE_FWU stack, last so no other stack depends on it. */
  FWUSTACK (rw): ORIGIN = WT_L3_STACKS_ORIGIN + 84K, LENGTH = 8K
