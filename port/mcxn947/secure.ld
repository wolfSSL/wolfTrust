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
  INCLUDE secure_l3_memory.ld
}

INCLUDE secure_l3_symbols.ld
_sidata = LOADADDR(.data);

SECTIONS {
  .vectors (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE) : {
    KEEP(*(.vectors))
  } > FLASH

  /* Linker-synthesized SG veneers land here (--cmse-implib) in the image's
   * second 1 KiB, the SAU NSC window (WT_NSC_* in memory_map.h); the veneer
   * bodies live in .text. The dot assignment keeps the section address
   * assigned even when no input object carries .gnu.sgstubs content. */
  .gnu.sgstubs (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE + 0x400) : {
    *(.gnu.sgstubs)
    *(.gnu.sgstubs*)
    . = ALIGN(32);
  } > FLASH

  .nsc ALIGN(32) : {
    KEEP(*(.nsc*))
  } > FLASH

  .text (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE + 0x800) : {
    _s_secure_text = .;
    *(.text*)
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
  ASSERT(SIZEOF(.gnu.sgstubs) + SIZEOF(.nsc) <= 0x400, "NSC window overflow")

  /* Claim the conformance partitions' .data/.bss before the general rules so
   * they land in CONFDATA, not shared SPM RAM. Loaded from flash and copied by
   * Reset_Handler alongside .data; empty (zero size) in non-conformance builds.
   * The server and driver partitions each get a 32-byte-aligned private band
   * the SVC gate denies to every other partition; their .bss lands in the
   * loaded section so each band stays one contiguous MPU carve. */
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

  INCLUDE secure_l3_bands.ld

  .data : {
    _sdata = .;
    *(.data*)
    _edata = .;
  } > RAM AT > FLASH
  ASSERT(LOADADDR(.data) + SIZEOF(.data) <=
         (WT_SECURE_FLASH_ORIGIN + WT_SECURE_FLASH_SIZE),
         "secure image load image overflows secure flash region")

  .bss (NOLOAD) : {
    _sbss = .;
    *(.bss*)
    *(COMMON)
    _ebss = .;
  } > RAM

  INCLUDE secure_l3_tail.ld
}
