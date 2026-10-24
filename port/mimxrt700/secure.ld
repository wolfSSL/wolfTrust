/* secure.ld
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

ENTRY(Reset_Handler)

MEMORY {
  FLASH (rx) : ORIGIN = (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE),
               LENGTH = (WT_SECURE_FLASH_SIZE - WT_SECURE_IMAGE_HEADER_SIZE)
  /* cpu0 application SRAM through its Secure alias (WT_RAM_S_BASE in
   * port/mimxrt700/memory_map.h); the guests live below it in their own
   * SRAM partitions through the 0x20000000 Non-secure alias. */
  RAM   (rwx): ORIGIN = 0x30188000, LENGTH = 308K - WT_VNET_DATA_LENGTH
  /* SERVICE_VNET data band (WT-FFM-0011/0056): the switch state and relay
   * scratch the confined vnet partition touches in-thread, carved from the
   * RAM tail only in CONFIG_VNET builds (WT_VNET_DATA_LENGTH is 0 otherwise).
   * Mirrors WT_VNET_DATA_* in port/mimxrt700/memory_map.h. */
  VNETDATA (rw): ORIGIN = 0x30188000 + 308K - WT_VNET_DATA_LENGTH,
                 LENGTH = WT_VNET_DATA_LENGTH
  /* Per-partition keystore data bands (WT-FFM-0011 Level 3): the vault,
   * attestation, and crypto partitions each own one private writable band
   * (WT_SP_*_DATA_* in memory_map.h). Top of the general window. */
  VAULTDATA (rw): ORIGIN = 0x301D5000, LENGTH = 8K
  ATTESTDATA (rw): ORIGIN = 0x301D7000, LENGTH = 2K
  HSMDATA (rw): ORIGIN = 0x301D7800, LENGTH = 70K
  /* FWU partition stack: the PSA Firmware Update SP's execution stack
   * (WT_SP_FWU_STACK_* in memory_map.h). Privileged coroutine that programs
   * the wolfBoot update partition flash. Lowest SP band. */
  FWUSTACK (rw): ORIGIN = 0x301E9000, LENGTH = 8K
  /* PS partition stack: the sealed-storage SP's execution stack and
   * MPU-domain RW resource (WT_SP_PS_STACK_* in memory_map.h). */
  PSSTACK (rw): ORIGIN = 0x301EB000, LENGTH = 8K
  /* ITS partition stack: the unprivileged storage SP's execution stack and
   * MPU-domain RW resource (WT_SP_ITS_STACK_* in memory_map.h). */
  ITSSTACK (rw): ORIGIN = 0x301ED000, LENGTH = 8K
  /* Vault partition stack (WT-FFM-0047): the privileged vault coroutine's
   * manifest-declared execution stack (WT_SP_VAULT_STACK_* in memory_map.h).
   * 16K: ECC verify's point-table frame overflows 8K (PSPLIM STKOF). */
  VAULTSTACK (rw): ORIGIN = 0x301EF000, LENGTH = 16K
  /* Conformance Secure-Partition .data/.bss (P3a). Arm's partition sources hold
   * their val_api/psa_api tables in .data; a hosted SP must reach its own data
   * but not the SPM's, so it lives in this 8 KiB window (WT_CONF_SP_DATA_* in
   * memory_map.h) that the SP MPU domain grants while SPM RAM at 0x30188000
   * stays denied. Empty in non-conformance builds; CONFIG_VNET builds reuse
   * the first 8 KiB as the SERVICE_VNET partition stack (WT_SP_VNET_STACK_*,
   * manifest-vnet.json domain) - the two builds are mutually exclusive. */
  CONFDATA (rw): ORIGIN = 0x301F3000, LENGTH = 12K
  /* SERVICE_TPM mailbox band (WT-FFM-0011 Level 3): the one in-flight TPM
   * command and response slot the confined TPM relay owns, carved from the
   * CONFDATA window tail only in CONFIG_TPM builds. Mirrors WT_TPM_DATA_ in
   * memory_map.h. */
  TPMDATA (rw): ORIGIN = 0x301F5000, LENGTH = 2K
  /* Secure per-partition stacks (WT-FFM-0011). The top 40 KiB of the secure
   * RAM window, reserved so each Secure Partition runs on its own secure
   * stack the MPU can confine. Mirrors WT_SP_SECURE_RAM_* in memory_map.h. */
  SPSTACKS (rw): ORIGIN = 0x301F6000, LENGTH = 40K
  /* RAM code band through the Secure Code-region alias of SRAM partition 12
   * (WT_RAMFUNC_* in memory_map.h): the NSC gateway, because the IDAU honours
   * NSC only in the Code region, and the XSPI0 NOR program/erase code, which
   * must not fetch from XIP flash while the NOR is busy. Copied from flash by
   * wt_platform_init before the MPU maps it privileged read-execute. */
  RAMFUNC (rx): ORIGIN = 0x10200000, LENGTH = 16K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
/* Secure main stack: MSPLIM_S is set to _sstack at reset. */
_sstack = _estack - WT_SPM_STACK_SIZE;
_wt_part_stacks_base = ORIGIN(FWUSTACK);
_wt_part_stacks_limit = ORIGIN(VAULTSTACK) + LENGTH(VAULTSTACK);
_wt_sp_stacks_base = ORIGIN(SPSTACKS);
_wt_sp_stacks_limit = ORIGIN(SPSTACKS) + LENGTH(SPSTACKS);
_wt_tpm_stack_base = ORIGIN(CONFDATA);
_wt_tpm_stack_limit = ORIGIN(TPMDATA);
_wt_pkcs11_stack_base = ORIGIN(CONFDATA);
_wt_pkcs11_stack_limit = ORIGIN(TPMDATA);
_sidata = LOADADDR(.data);

SECTIONS {
  .vectors (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE) : {
    KEEP(*(.vectors))
  } > FLASH

  .text (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE + 0x800) : {
    _s_secure_text = .;
    *(EXCLUDE_FILE(*wt_sec_ffm_nsc.o) .text*)
    *(.glue_7)
    *(.glue_7t)
    . = ALIGN(32);
    _e_secure_text = .;
  } > FLASH

  /* Constant data is readable, never executable (WT-FFM-0010): the SP thread
   * MPU tables grant [flash, _e_secure_text) RX and the rest of the image
   * window read-only XN, so no partition can execute from constant data. */
  .rodata (READONLY) : {
    . = ALIGN(4);
    KEEP(*(.wt_guest_meas))
    /* wolfCrypt globals that are never written after link stay read-only so
     * the crypto partition sees them without owning writable state. */
    *(.data.always_prefetch* .bss.always_prefetch*)
    *(.data.sha256DrbgDisabled* .bss.sha256DrbgDisabled*)
    *(.rodata*)
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    *(.eh_frame)
  } > FLASH

  ASSERT(WT_SECURE_IMAGE_HEADER_SIZE < WT_SECURE_FLASH_SIZE,
         "secure image header consumes secure flash region")
  ASSERT(. <= (WT_SECURE_FLASH_ORIGIN + WT_SECURE_FLASH_SIZE),
         "secure image overflows secure flash region")

  /* Claim the conformance partitions' .data/.bss before the general rules so
   * they land in CONFDATA, not shared SPM RAM. Loaded from flash and copied by
   * Reset_Handler alongside .data; empty (zero size) in non-conformance builds. */
  /* Per-partition private data bands (Arm i080/i084 SP data isolation): the
   * server partition's test data and the driver partition's data each get a
   * 32-byte-aligned band the SVC gate denies to every other partition. Their
   * .bss lands in the loaded section so each band stays one contiguous MPU
   * carve; the flash cost is a few zero words. */
  .conf_data : {
    . = ALIGN(4);
    _sconfdata = .;
    EXCLUDE_FILE(*conf_sec_test_supp_*.o *conf_sec_driver_partition.o *conf_sec_pal_driver_intf.o) *conf_sec_*.o(.data .data.*)
    . = ALIGN(32);
    _s_conf_server_data = .;
    *conf_sec_test_supp_*.o(.data .data.* .bss .bss.* COMMON)
    . = ALIGN(32);
    _e_conf_server_data = .;
    _s_conf_driver_data = .;
    *conf_sec_driver_partition.o(.data .data.* .bss .bss.* COMMON)
    *conf_sec_pal_driver_intf.o(.data .data.* .bss .bss.* COMMON)
    . = ALIGN(32);
    _e_conf_driver_data = .;
    _econfdata = .;
  } > CONFDATA AT > FLASH
  _siconfdata = LOADADDR(.conf_data);

  .conf_bss (NOLOAD) : {
    . = ALIGN(4);
    _sconfbss = .;
    EXCLUDE_FILE(*conf_sec_test_supp_*.o *conf_sec_driver_partition.o *conf_sec_pal_driver_intf.o) *conf_sec_*.o(.bss .bss.* COMMON)
    . = ALIGN(4);
    _econfbss = .;
  } > CONFDATA

  /* Per-partition keystore state (WT-FFM-0011 Level 3). Every RAM object a
   * keystore partition writes in-thread is claimed by its owning band before
   * the general .data/.bss rules run: the vault's NVM store, flash context,
   * directory, sealer, and RNG; the attestation partition's token state; the
   * crypto partition's engine state and the wolfHSM/wolfCrypt library state
   * it alone drives at runtime. Every object named here is built without LTO
   * so its claim holds, and tools/check_secure_layout.py checks each claim
   * against the owner map. Each band spans loaded data and zero-init bss so
   * one MPU region covers the whole trust unit. */
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

  /* SERVICE_VNET data band: first-claim the vnet dataplane, service, and
   * relay objects' RAM out of shared SPM .data/.bss so the unprivileged
   * partition's MPU grant covers exactly its own state. Empty (zero-length
   * region) outside CONFIG_VNET builds. */
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

  .pkcs11_data : {
    . = ALIGN(32);
    _s_pkcs11 = .;
    *wt_sec_pkcs11_relay_service.o(.data .data.*)
    . = ALIGN(4);
    _e_pkcs11_data = .;
  } > VNETDATA AT > FLASH
  _si_pkcs11 = LOADADDR(.pkcs11_data);

  .pkcs11_bss (NOLOAD) : {
    _s_pkcs11_bss = .;
    *wt_sec_pkcs11_relay_service.o(.bss .bss.* COMMON)
    . = ALIGN(32);
    _e_pkcs11 = .;
  } > VNETDATA

  /* SERVICE_TPM relay data and bss pulled out of shared SPM .data/.bss so its
   * MPU grant covers exactly its own state (isolation level 3). Empty outside
   * CONFIG_TPM builds. */
  .tpm_data : {
    . = ALIGN(32);
    _s_tpm = .;
    *wt_sec_tpm_relay_service.o(.data .data.*)
    . = ALIGN(4);
    _e_tpm_data = .;
  } > TPMDATA AT > FLASH
  _si_tpm = LOADADDR(.tpm_data);

  .tpm_bss (NOLOAD) : {
    _s_tpm_bss = .;
    *wt_sec_tpm_relay_service.o(.bss .bss.* COMMON)
    . = ALIGN(32);
    _e_tpm = .;
  } > TPMDATA

  /* Linker-synthesized SG veneers (--cmse-implib) open the RAM code band: the
   * first 1 KiB is the SAU NSC window (WT_NSC_* in memory_map.h), padded so
   * nothing but veneers is Non-secure callable. The dot assignment keeps the
   * section address assigned even when no input object carries .gnu.sgstubs
   * content ("no address assigned to the veneers output section"). */
  .gnu.sgstubs ORIGIN(RAMFUNC) : {
    *(.gnu.sgstubs)
    *(.gnu.sgstubs*)
    . = ALIGN(32);
  } > RAMFUNC AT > FLASH

  /* Load addresses chain off the veneers so one copy stages the whole band. */
  .nsc (ADDR(.gnu.sgstubs) + SIZEOF(.gnu.sgstubs)) :
      AT(LOADADDR(.gnu.sgstubs) + SIZEOF(.gnu.sgstubs)) {
    KEEP(*(.nsc*))
    . = 0x400 - SIZEOF(.gnu.sgstubs);
  } > RAMFUNC

  /* The cmse_nonsecure_entry bodies sit beside their veneers so the SG
   * veneer's B.W reaches them; then the NOR program/erase code. */
  .ramfunc (ADDR(.nsc) + SIZEOF(.nsc)) : AT(LOADADDR(.nsc) + SIZEOF(.nsc)) {
    *wt_sec_ffm_nsc.o(.text .text.*)
    *(.ramfunc .ramfunc.*)
    . = ALIGN(4);
  } > RAMFUNC
  _siramfunc = LOADADDR(.gnu.sgstubs);
  _sramfunc = ADDR(.gnu.sgstubs);
  _eramfunc = ADDR(.ramfunc) + SIZEOF(.ramfunc);

  ASSERT(SIZEOF(.gnu.sgstubs) + SIZEOF(.nsc) == 0x400, "NSC window overflow")
  ASSERT(LOADADDR(.ramfunc) - LOADADDR(.gnu.sgstubs) ==
         ADDR(.ramfunc) - ADDR(.gnu.sgstubs),
         "RAM code band load and execution layouts differ")

  .data : AT(LOADADDR(.ramfunc) + SIZEOF(.ramfunc)) {
    _sdata = .;
    *(.data*)
    _edata = .;
  } > RAM
  ASSERT(LOADADDR(.data) + SIZEOF(.data) <=
         (WT_SECURE_FLASH_ORIGIN + WT_SECURE_FLASH_SIZE),
         "secure image load image overflows secure flash region")

  .bss (NOLOAD) : {
    _sbss = .;
    *(.bss*)
    *(COMMON)
    _ebss = .;
  } > RAM

  .sp_stacks (NOLOAD) : {
    KEEP(*(.sp_stacks*))
  } > SPSTACKS

  ASSERT(ORIGIN(VNETDATA) == (ORIGIN(RAM) + LENGTH(RAM)),
         "vnet data band must sit directly above the secure RAM window")
  ASSERT(ORIGIN(VAULTDATA) == (ORIGIN(VNETDATA) + LENGTH(VNETDATA)),
         "vault data band must sit directly above the vnet data band")
  ASSERT(_e_vnet <= (ORIGIN(VNETDATA) + LENGTH(VNETDATA)),
         "vnet data band overflow")
  ASSERT(_e_pkcs11 <= (ORIGIN(VNETDATA) + LENGTH(VNETDATA)),
         "pkcs11 data band overflow")
  ASSERT(ORIGIN(ATTESTDATA) == (ORIGIN(VAULTDATA) + LENGTH(VAULTDATA)),
         "attestation data band must sit directly above the vault data band")
  ASSERT(ORIGIN(HSMDATA) == (ORIGIN(ATTESTDATA) + LENGTH(ATTESTDATA)),
         "crypto data band must sit directly above the attestation data band")
  ASSERT(ORIGIN(FWUSTACK) == (ORIGIN(HSMDATA) + LENGTH(HSMDATA)),
         "FWU stack must sit directly above the crypto data band")
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
  _wt_band_pkcs11_base = ORIGIN(VNETDATA);
  _wt_band_pkcs11_limit = ORIGIN(VNETDATA) + LENGTH(VNETDATA);
  _wt_band_tpm_base = ORIGIN(TPMDATA);
  _wt_band_tpm_limit = ORIGIN(TPMDATA) + LENGTH(TPMDATA);

  ASSERT(_e_vault <= (ORIGIN(VAULTDATA) + LENGTH(VAULTDATA)),
         "vault data band overflow")
  ASSERT(_e_attest <= (ORIGIN(ATTESTDATA) + LENGTH(ATTESTDATA)),
         "attestation data band overflow")
  ASSERT(_e_hsm <= (ORIGIN(HSMDATA) + LENGTH(HSMDATA)),
         "crypto data band overflow")
  ASSERT(ORIGIN(PSSTACK) == (ORIGIN(FWUSTACK) + LENGTH(FWUSTACK)),
         "PS stack must sit directly above the FWU stack")
  ASSERT(ORIGIN(ITSSTACK) == (ORIGIN(PSSTACK) + LENGTH(PSSTACK)),
         "ITS stack must sit directly above the PS stack")
  ASSERT(ORIGIN(VAULTSTACK) == (ORIGIN(ITSSTACK) + LENGTH(ITSSTACK)),
         "vault stack must sit directly above the ITS stack")
  ASSERT(ORIGIN(CONFDATA) == (ORIGIN(VAULTSTACK) + LENGTH(VAULTSTACK)),
         "conformance SP data must sit directly above the vault stack")
  /* The top 1 KiB of CONFDATA holds the per-partition pseudo-MMIO holes
   * (WT_CONF_SERVER/DRV_MMIO in memory_map.h); real data crossing into them
   * would be carved out of other partitions' domains and fault at runtime. */
  ASSERT(_econfbss <= (ORIGIN(CONFDATA) + 0x2C00),
         "conformance data/bss overflows into the reserved MMIO holes")
  ASSERT(ORIGIN(SPSTACKS) == (ORIGIN(CONFDATA) + LENGTH(CONFDATA)),
         "SP secure stacks must sit directly above the conformance data window")
  ASSERT(_ebss <= _sstack,
         "secure .bss reaches the SPM main stack (WT_SPM_STACK_SIZE)")
}
