/* Code at WT_SMOKE_BASE (flash on virt, OCM on versal-virt), bss and the
 * stack at WT_SMOKE_RAM; both come from the Makefile as --defsym values. */
ENTRY(_start)

SECTIONS
{
    . = WT_SMOKE_BASE;
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

    . = WT_SMOKE_RAM;
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

/* .data would sit in read-only flash on virt; the smoke keeps state in .bss. */
ASSERT(SIZEOF(.data) == 0, "aarch64-smoke must not use .data")
