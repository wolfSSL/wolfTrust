ENTRY(Reset_Handler)

MEMORY {
  FLASH (rx) : ORIGIN = GUEST_FLASH_ORIGIN, LENGTH = GUEST_FLASH_LENGTH
  RAM   (rwx): ORIGIN = GUEST_RAM_ORIGIN,   LENGTH = GUEST_RAM_LENGTH
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

SECTIONS {
  .vectors GUEST_FLASH_ORIGIN : {
    KEEP(*(.vectors))
  } > FLASH

  .reset : {
    KEEP(*(.reset))
  } > FLASH

  .text : {
    *(.text*)
    *(.rodata*)
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
  } > FLASH

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
}
