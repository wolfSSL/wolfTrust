ENTRY(Reset_Handler)
MEMORY {
  FLASH (rx) : ORIGIN = 0x28004000, LENGTH = 64K
  RAM (rwx)  : ORIGIN = 0x20190000, LENGTH = 64K
}
_estack = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS {
  .vectors : { KEEP(*(.vectors)) } > FLASH
  .text : { *(.text*) *(.rodata*) } > FLASH
  .data : { *(.data*) } > RAM AT > FLASH
  .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
}
