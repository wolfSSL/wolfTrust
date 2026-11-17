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

  /* General SPM RAM: .data, .bss and the SPM main stack, up to the bands. */
  RAM   (rwx): ORIGIN = WT_RAM_S_ORIGIN, LENGTH = WT_L3_RAM_LENGTH
  /* SERVICE_VNET data band; zero length outside CONFIG_VNET builds. */
  VNETDATA (rw): ORIGIN = WT_L3_VNET_ORIGIN, LENGTH = WT_L3_VNET_LENGTH
  /* Crypto partition stack and data band, sized per engine, below the
   * keystore. */
  CRYPTOSTACK (rw): ORIGIN = WT_L3_CRYPTOSTACK_ORIGIN,
                    LENGTH = WT_L3_CRYPTOSTACK_LENGTH
  HSMDATA (rw): ORIGIN = WT_L3_HSM_ORIGIN, LENGTH = WT_L3_HSM_LENGTH
  /* Keystore bands: the vault and attestation partitions each own one. */
  VAULTDATA (rw): ORIGIN = WT_L3_VAULT_ORIGIN, LENGTH = WT_L3_VAULT_LENGTH
  ATTESTDATA (rw): ORIGIN = WT_L3_ATTEST_ORIGIN, LENGTH = WT_L3_ATTEST_LENGTH
  /* Partition execution stacks, each also the partition's MPU RW resource. */
  PSSTACK (rw): ORIGIN = WT_L3_PSSTACK_ORIGIN, LENGTH = WT_L3_PSSTACK_LENGTH
  ITSSTACK (rw): ORIGIN = WT_L3_ITSSTACK_ORIGIN, LENGTH = WT_L3_ITSSTACK_LENGTH
  VAULTSTACK (rw): ORIGIN = WT_L3_VAULTSTACK_ORIGIN,
                   LENGTH = WT_L3_VAULTSTACK_LENGTH
  /* The attestation stack, then the Arm suite partitions' stacks in
   * conformance builds. */
  SPSTACKS (rw): ORIGIN = WT_L3_SPSTACKS_ORIGIN, LENGTH = WT_L3_SPSTACKS_LENGTH
  /* Conformance partition data, or the VNET stack; zero length otherwise. */
  CONFDATA (rw): ORIGIN = WT_L3_CONF_ORIGIN, LENGTH = WT_L3_CONF_LENGTH
  /* SERVICE_FWU stack, last so dropping it moves nothing; zero length
   * outside WT_FWU builds. */
  FWUSTACK (rw): ORIGIN = WT_L3_FWUSTACK_ORIGIN, LENGTH = WT_L3_FWUSTACK_LENGTH
