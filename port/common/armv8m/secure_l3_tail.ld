/* secure_l3_tail.ld
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

/* Secure stacks and the level 3 layout invariants, INCLUDEd inside SECTIONS
 * after .bss. */

  .sp_stacks (NOLOAD) : {
    KEEP(*(.sp_stacks*))
  } > SPSTACKS

  ASSERT(ORIGIN(VNETDATA) == (ORIGIN(RAM) + LENGTH(RAM)),
         "vnet data band must sit directly above the secure RAM window")
  ASSERT(ORIGIN(CRYPTOSTACK) == (ORIGIN(VNETDATA) + LENGTH(VNETDATA)),
         "crypto stack must sit directly above the vnet data band")
  ASSERT(ORIGIN(HSMDATA) == (ORIGIN(CRYPTOSTACK) + LENGTH(CRYPTOSTACK)),
         "crypto data band must sit directly above the crypto stack")
  ASSERT(ORIGIN(VAULTDATA) == (ORIGIN(HSMDATA) + LENGTH(HSMDATA)),
         "vault data band must sit directly above the crypto data band")
  ASSERT(_e_vnet <= (ORIGIN(VNETDATA) + LENGTH(VNETDATA)),
         "vnet data band overflow")
  ASSERT(ORIGIN(ATTESTDATA) == (ORIGIN(VAULTDATA) + LENGTH(VAULTDATA)),
         "attestation data band must sit directly above the vault data band")
  ASSERT(ORIGIN(PSSTACK) == (ORIGIN(ATTESTDATA) + LENGTH(ATTESTDATA)),
         "PS stack must sit directly above the attestation data band")
  /* Full band extents: Reset_Handler clears each band end to end before
   * loading it, so no retained byte outlives a warm reset or a layout change. */
  _wt_band_vault_base = ORIGIN(VAULTDATA);
  _wt_band_vault_limit = ORIGIN(VAULTDATA) + LENGTH(VAULTDATA);
  _wt_band_attest_base = ORIGIN(ATTESTDATA);
  _wt_band_attest_limit = ORIGIN(ATTESTDATA) + LENGTH(ATTESTDATA);
  _wt_band_hsm_base = ORIGIN(HSMDATA);
  _wt_band_hsm_limit = ORIGIN(HSMDATA) + LENGTH(HSMDATA);
  _wt_band_vnet_base = ORIGIN(VNETDATA);
  _wt_band_vnet_limit = ORIGIN(VNETDATA) + LENGTH(VNETDATA);

  ASSERT(_e_vault <= (ORIGIN(VAULTDATA) + LENGTH(VAULTDATA)),
         "vault data band overflow")
  ASSERT(_e_attest <= (ORIGIN(ATTESTDATA) + LENGTH(ATTESTDATA)),
         "attestation data band overflow")
  ASSERT(_e_hsm <= (ORIGIN(HSMDATA) + LENGTH(HSMDATA)),
         "crypto data band overflow")
  ASSERT(ORIGIN(ITSSTACK) == (ORIGIN(PSSTACK) + LENGTH(PSSTACK)),
         "ITS stack must sit directly above the PS stack")
  ASSERT(ORIGIN(VAULTSTACK) == (ORIGIN(ITSSTACK) + LENGTH(ITSSTACK)),
         "vault stack must sit directly above the ITS stack")
  ASSERT(ORIGIN(SPSTACKS) == (ORIGIN(VAULTSTACK) + LENGTH(VAULTSTACK)),
         "SP secure stacks must sit directly above the vault stack")
  ASSERT(ORIGIN(CONFDATA) == (ORIGIN(SPSTACKS) + LENGTH(SPSTACKS)),
         "conformance SP data must sit directly above the SP secure stacks")
  /* The top 1 KiB of CONFDATA holds the per-partition pseudo-MMIO holes
   * (WT_CONF_SERVER/DRV_MMIO in memory_map.h); real data crossing into them
   * would be carved out of other partitions' domains and fault at runtime. */
  ASSERT((LENGTH(CONFDATA) == 0) || (_econfbss <= (ORIGIN(CONFDATA) + 0x2C00)),
         "conformance data/bss overflows into the reserved MMIO holes")
  ASSERT(ORIGIN(FWUSTACK) == (ORIGIN(CONFDATA) + LENGTH(CONFDATA)),
         "FWU stack must sit directly above the conformance data window")
  ASSERT(_ebss <= _sstack,
         "secure .bss reaches the SPM main stack (WT_SPM_STACK_SIZE)")
