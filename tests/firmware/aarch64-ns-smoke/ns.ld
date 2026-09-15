/* The Normal-world payload runs from NS DRAM (WT_NS_BASE from the Makefile);
 * code, rodata, data, bss, and stack are all in writable DRAM. */
ENTRY(_start)

SECTIONS
{
    . = WT_NS_BASE;
    .text : {
        KEEP(*(.text.entry))
        *(.text*)
    }
    .rodata : {
        *(.rodata*)
    }
    .data : {
        *(.data*)
    }
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(16);
    . += 0x4000;
    __stack_top = .;

    /DISCARD/ : {
        *(.note*)
        *(.comment)
        *(.eh_frame*)
    }
}
