/* The Normal-world payload runs from NS DRAM (WT_NS_BASE from the Makefile).
 * The loaded image (code, rodata, the .data initializers) stays pristine in
 * IMG; .data is copied into RAM at every entry, so a warm reset that re-enters
 * the payload without reloading it starts from the initial values. */
ENTRY(_start)

MEMORY
{
    IMG (rx) : ORIGIN = WT_NS_BASE, LENGTH = WT_NS_IMG_SIZE
    RAM (rw) : ORIGIN = WT_NS_BASE + WT_NS_IMG_SIZE, LENGTH = WT_NS_RAM_SIZE
}

SECTIONS
{
    .text : {
        KEEP(*(.text.entry))
        *(.text*)
    } > IMG
    .rodata : {
        *(.rodata*)
        . = ALIGN(16);
    } > IMG
    .data : ALIGN(16) {
        __data_start = .;
        *(.data*)
        . = ALIGN(16);
        __data_end = .;
    } > RAM AT > IMG
    __data_load = LOADADDR(.data);
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } > RAM
    .stack (NOLOAD) : {
        . = ALIGN(16);
        . += WT_NS_STACK_SIZE;
        __stack_top = .;
    } > RAM

    /DISCARD/ : {
        *(.note*)
        *(.comment)
        *(.eh_frame*)
    }
}
