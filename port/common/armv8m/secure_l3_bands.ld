/* secure_l3_bands.ld
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

/* Per-partition band sections, INCLUDEd in SECTIONS after the read-only
 * image. Objects named here build without LTO so each claim holds, and
 * tools/check_secure_layout.py checks every claim against the owner map. */

  .vault_data : {
    . = ALIGN(32);
    _s_vault = .;
    _s_keystore = .;
    *nvm_store.o(.data .data.*)
    *wt_hsm_vault.o(.data .data.*)
    *wt_hsm_seal.o(.data .data.*)
    *wt_hsm_lock.o(.data .data.*)
    *vault_service.o(.data .data.*)
    *hsm_flash_ctx.o(.data .data.*)
    *wh_sec_wh_nvm.o(.data .data.*)
    *wh_sec_wh_nvm_flash.o(.data .data.*)
    *wh_sec_wh_flash_unit.o(.data .data.*)
    *wh_sec_wh_lock.o(.data .data.*)
    . = ALIGN(4);
    _e_vault_data = .;
  } > VAULTDATA AT > FLASH
  _si_vault = LOADADDR(.vault_data);

  .vault_bss (NOLOAD) : {
    _s_vault_bss = .;
    *nvm_store.o(.bss .bss.* COMMON)
    *wt_hsm_vault.o(.bss .bss.* COMMON)
    *wt_hsm_seal.o(.bss .bss.* COMMON)
    *wt_hsm_lock.o(.bss .bss.* COMMON)
    *vault_service.o(.bss .bss.* COMMON)
    *hsm_flash_ctx.o(.bss .bss.* COMMON)
    *wh_sec_wh_nvm.o(.bss .bss.* COMMON)
    *wh_sec_wh_nvm_flash.o(.bss .bss.* COMMON)
    *wh_sec_wh_flash_unit.o(.bss .bss.* COMMON)
    *wh_sec_wh_lock.o(.bss .bss.* COMMON)
    . = ALIGN(32);
    _e_vault = .;
  } > VAULTDATA

  .attest_data : {
    . = ALIGN(32);
    _s_attest = .;
    *attestation_service.o(.data .data.*)
    *initial_attestation.o(.data .data.*)
    *attestation_cose.o(.data .data.*)
    *wolfcose*.o(.data .data.*)
    . = ALIGN(4);
    _e_attest_data = .;
  } > ATTESTDATA AT > FLASH
  _si_attest = LOADADDR(.attest_data);

  .attest_bss (NOLOAD) : {
    _s_attest_bss = .;
    *attestation_service.o(.bss .bss.* COMMON)
    *initial_attestation.o(.bss .bss.* COMMON)
    *attestation_cose.o(.bss .bss.* COMMON)
    *wolfcose*.o(.bss .bss.* COMMON)
    . = ALIGN(32);
    _e_attest = .;
  } > ATTESTDATA

  .hsm_data : {
    . = ALIGN(32);
    _s_hsm = .;
    *wt_hsm.o(.data .data.*)
    *hsm_relay_service.o(.data .data.*)
    *nvm_client.o(.data .data.*)
    *crypto_native.o(.data .data.*)
    *keyvault.o(.data .data.*)
    *native_wire.o(.data .data.*)
    *wh_sec_*.o(.data .data.*)
    *wc_sec_cryptocb.o(.data .data.*)
    . = ALIGN(4);
    _e_hsm_data = .;
  } > HSMDATA AT > FLASH
  _si_hsm = LOADADDR(.hsm_data);

  .hsm_bss (NOLOAD) : {
    _s_hsm_bss = .;
    *wt_hsm.o(.bss .bss.* COMMON)
    *hsm_relay_service.o(.bss .bss.* COMMON)
    *nvm_client.o(.bss .bss.* COMMON)
    *crypto_native.o(.bss .bss.* COMMON)
    *keyvault.o(.bss .bss.* COMMON)
    *native_wire.o(.bss .bss.* COMMON)
    *wh_sec_*.o(.bss .bss.* COMMON)
    *wc_sec_cryptocb.o(.bss .bss.* COMMON)
    . = ALIGN(32);
    _e_hsm = .;
    _e_keystore = .;
  } > HSMDATA

  /* SERVICE_VNET data band: the vnet objects' RAM, claimed out of SPM
   * .data/.bss so the partition's MPU grant covers exactly its own state.
   * Zero length outside CONFIG_VNET builds. */
  .vnet_data : {
    . = ALIGN(32);
    _s_vnet = .;
    *wt_sec_vnet_*.o(.data .data.*)
    . = ALIGN(4);
    _e_vnet_data = .;
  } > VNETDATA AT > FLASH
  _si_vnet = LOADADDR(.vnet_data);

  .vnet_bss (NOLOAD) : {
    _s_vnet_bss = .;
    *wt_sec_vnet_*.o(.bss .bss.* COMMON)
    . = ALIGN(32);
    _e_vnet = .;
  } > VNETDATA
