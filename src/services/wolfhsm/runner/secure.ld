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
  /* SRAM1 has Secure and Non-secure aliases to the same physical memory.
   * The first 32 KiB are assigned to the two guests through the 0x20000000
   * Non-secure alias, so keep secure .data/.bss above that physical window. */
  RAM   (rwx): ORIGIN = 0x30028000, LENGTH = 308K - WT_VNET_DATA_LENGTH
  /* SERVICE_VNET data band (WT-FFM-0011/0056): the switch state and relay
   * scratch the confined vnet partition touches in-thread, carved from the
   * RAM tail only in CONFIG_VNET builds (WT_VNET_DATA_LENGTH is 0 otherwise).
   * Mirrors WT_VNET_DATA_* in port/stm32h563/memory_map.h. */
  VNETDATA (rw): ORIGIN = 0x30028000 + 308K - WT_VNET_DATA_LENGTH,
                 LENGTH = WT_VNET_DATA_LENGTH
  /* wolfHSM keystore trust band (WT-FFM-0011 Level 3): the shared wolfHSM
   * server, NVM, lock, and per-guest tasklet state, relocated out of general
   * SPM RAM into one MPU-alignable region so the keystore partitions can be
   * granted exactly it while running unprivileged. Top of the general window. */
  KEYSTORE (rw): ORIGIN = 0x30075000, LENGTH = 80K
  /* FWU partition stack: the PSA Firmware Update SP's execution stack
   * (WT_SP_FWU_STACK_* in memory_map.h). Privileged coroutine that programs
   * the wolfBoot update partition flash. Lowest SP band. */
  FWUSTACK (rw): ORIGIN = 0x30089000, LENGTH = 8K
  /* PS partition stack: the sealed-storage SP's execution stack and
   * MPU-domain RW resource (WT_SP_PS_STACK_* in memory_map.h). */
  PSSTACK (rw): ORIGIN = 0x3008B000, LENGTH = 8K
  /* ITS partition stack: the unprivileged storage SP's execution stack and
   * MPU-domain RW resource (WT_SP_ITS_STACK_* in memory_map.h). */
  ITSSTACK (rw): ORIGIN = 0x3008D000, LENGTH = 8K
  /* Vault partition stack (WT-FFM-0047): the privileged vault coroutine's
   * manifest-declared execution stack (WT_SP_VAULT_STACK_* in memory_map.h).
   * 16K: ECC verify's point-table frame overflows 8K (PSPLIM STKOF). */
  VAULTSTACK (rw): ORIGIN = 0x3008F000, LENGTH = 16K
  /* Conformance Secure-Partition .data/.bss (P3a). Arm's partition sources hold
   * their val_api/psa_api tables in .data; a hosted SP must reach its own data
   * but not the SPM's, so it lives in this 8 KiB window (WT_CONF_SP_DATA_* in
   * memory_map.h) that the SP MPU domain grants while SPM RAM at 0x30028000
   * stays denied. Empty in non-conformance builds; CONFIG_VNET builds reuse
   * the first 8 KiB as the SERVICE_VNET partition stack (WT_SP_VNET_STACK_*,
   * manifest-vnet.json domain) - the two builds are mutually exclusive. */
  CONFDATA (rw): ORIGIN = 0x30093000, LENGTH = 12K
  /* Secure per-partition stacks (WT-FFM-0011). The top 40 KiB of the secure
   * RAM window, reserved so each Secure Partition runs on its own secure
   * stack the MPU can confine. Mirrors WT_SP_SECURE_RAM_* in memory_map.h. */
  SPSTACKS (rw): ORIGIN = 0x30096000, LENGTH = 40K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

SECTIONS {
  .vectors (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE) : {
    KEEP(*(.vectors))
  } > FLASH

  /* Linker-synthesized SG veneers land here (--cmse-implib); veneer bodies
   * live in .text. The dot assignment keeps the section address assigned even
   * when no input object carries .gnu.sgstubs content, or ld cannot size the
   * synthesized stubs ("no address assigned to the veneers output section"). */
  .gnu.sgstubs (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE + 0x400) : {
    *(.gnu.sgstubs)
    *(.gnu.sgstubs*)
    . = ALIGN(32);
  } > FLASH

  .nsc ALIGN(32) : {
    KEEP(*(.nsc*))
  } > FLASH

  .text (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE + 0x800) : {
    *(.text*)
    *(.glue_7)
    *(.glue_7t)
    . = ALIGN(32);
    _e_secure_text = .;
  } > FLASH

  /* Constant data is readable, never executable (WT-FFM-0010): the SP thread
   * MPU tables grant [flash, _e_secure_text) RX and the rest of the image
   * window read-only XN, so no partition can execute from constant data. */
  .rodata : {
    . = ALIGN(4);
    KEEP(*(.wt_guest_meas))
    *(.rodata*)
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    *(.eh_frame)
  } > FLASH

  ASSERT(WT_SECURE_IMAGE_HEADER_SIZE < WT_SECURE_FLASH_SIZE,
         "secure image header consumes secure flash region")
  ASSERT(. <= (WT_SECURE_FLASH_ORIGIN + WT_SECURE_FLASH_SIZE),
         "secure image overflows secure flash region")
  ASSERT(SIZEOF(.gnu.sgstubs) + SIZEOF(.nsc) <= 0x400, "NSC window overflow")

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
    EXCLUDE_FILE(*conf_sec_test_supp_*.o *conf_sec_driver_partition.o) *conf_sec_*.o(.data .data.*)
    . = ALIGN(32);
    _s_conf_server_data = .;
    *conf_sec_test_supp_*.o(.data .data.* .bss .bss.* COMMON)
    . = ALIGN(32);
    _e_conf_server_data = .;
    _s_conf_driver_data = .;
    *conf_sec_driver_partition.o(.data .data.* .bss .bss.* COMMON)
    . = ALIGN(32);
    _e_conf_driver_data = .;
    _econfdata = .;
  } > CONFDATA AT > FLASH
  _siconfdata = LOADADDR(.conf_data);

  .conf_bss (NOLOAD) : {
    . = ALIGN(4);
    _sconfbss = .;
    EXCLUDE_FILE(*conf_sec_test_supp_*.o *conf_sec_driver_partition.o) *conf_sec_*.o(.bss .bss.* COMMON)
    . = ALIGN(4);
    _econfbss = .;
  } > CONFDATA

  /* wolfHSM keystore state (WT-FFM-0011): every RAM object the keystore
   * partitions (attest, relay, vault) write in-thread — the wt_hsm core, its
   * service faces, the wolfCOSE signer, and the wolfHSM/wolfCrypt library
   * state — pulled out of shared SPM RAM into one contiguous MPU-grantable
   * band. These claims precede .data/.bss, so first-claim ordering keeps the
   * general sections clean. _s_keystore.._e_keystore span loaded data and
   * zero-init bss so a single MPU region covers the whole trust unit. */
  .keystore_data : {
    . = ALIGN(32);
    _s_keystore = .;
    *wt_hsm.o(.data .data.*)
    *nvm_store.o(.data .data.*)
    *crypto_native.o(.data .data.*)
    *keyvault.o(.data .data.*)
    *wt_hsm_lock.o(.data .data.*)
    *wt_hsm_seal.o(.data .data.*)
    *wt_hsm_vault.o(.data .data.*)
    *hsm_relay_service.o(.data .data.*)
    *vault_service.o(.data .data.*)
    *attestation_service.o(.data .data.*)
    *initial_attestation.o(.data .data.*)
    *attestation_cose.o(.data .data.*)
    *hsm_flash.o(.data .data.*)
    *wolfcose.o(.data .data.*)
    *wolfcose_cbor.o(.data .data.*)
    *wh_sec_*.o(.data .data.*)
    *wc_sec_*.o(.data .data.*)
    . = ALIGN(4);
    _e_keystore_data = .;
  } > KEYSTORE AT > FLASH
  _si_keystore = LOADADDR(.keystore_data);

  .keystore_bss (NOLOAD) : {
    _s_keystore_bss = .;
    *wt_hsm.o(.bss .bss.* COMMON)
    *nvm_store.o(.bss .bss.* COMMON)
    *crypto_native.o(.bss .bss.* COMMON)
    *keyvault.o(.bss .bss.* COMMON)
    *wt_hsm_lock.o(.bss .bss.* COMMON)
    *wt_hsm_seal.o(.bss .bss.* COMMON)
    *wt_hsm_vault.o(.bss .bss.* COMMON)
    *hsm_relay_service.o(.bss .bss.* COMMON)
    *vault_service.o(.bss .bss.* COMMON)
    *attestation_service.o(.bss .bss.* COMMON)
    *initial_attestation.o(.bss .bss.* COMMON)
    *attestation_cose.o(.bss .bss.* COMMON)
    *hsm_flash.o(.bss .bss.* COMMON)
    *wolfcose.o(.bss .bss.* COMMON)
    *wolfcose_cbor.o(.bss .bss.* COMMON)
    *wh_sec_*.o(.bss .bss.* COMMON)
    *wc_sec_*.o(.bss .bss.* COMMON)
    . = ALIGN(32);
    _e_keystore = .;
  } > KEYSTORE

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

  .data : {
    _sdata = .;
    *(.data*)
    _edata = .;
  } > RAM AT > FLASH

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
  ASSERT(ORIGIN(KEYSTORE) == (ORIGIN(VNETDATA) + LENGTH(VNETDATA)),
         "keystore band must sit directly above the vnet data band")
  ASSERT(_e_vnet <= (ORIGIN(VNETDATA) + LENGTH(VNETDATA)),
         "vnet data band overflow")
  ASSERT(ORIGIN(FWUSTACK) == (ORIGIN(KEYSTORE) + LENGTH(KEYSTORE)),
         "FWU stack must sit directly above the keystore band")
  ASSERT(_e_keystore <= (ORIGIN(KEYSTORE) + LENGTH(KEYSTORE)),
         "keystore band overflow")
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
}
