/* EL3 monitor image: code and read-only data at WT_EL3_TEXT_BASE (flash on
 * QEMU virt, OCM on Versal), data, bss, and stacks at WT_EL3_RAM_BASE. Both
 * addresses arrive as --defsym values from mk/target-<soc>.mk. */
ENTRY(wt_el3_start)

SECTIONS
{
    . = WT_EL3_TEXT_BASE;
    .el3.text : {
        KEEP(*(.el3.text.entry))
        KEEP(*(.el3.vectors))
        *(.el3.text .el3.text.*)
        *libwt_el3.a:*(.text .text.*)
    }
    .text : {
        *(.text .text.*)
    }
    .rodata : {
        *(.rodata .rodata.*)
        . = ALIGN(16);
    }
    __data_lma = .;

    . = WT_EL3_RAM_BASE;
    .data : AT(__data_lma) {
        __data_start = .;
        *(.data .data.*)
        . = ALIGN(16);
        __data_end = .;
    }
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(16);
    . += 0x4000;
    __el3_stack_top = .;
    /* Survives a warm reset: placed past the stack, outside the .bss clear
     * range and not loaded from flash, so a re-entry through wt_el3_start
     * preserves it (the boot counter that gates PSCI SYSTEM_RESET). */
    .noinit (NOLOAD) : {
        *(.noinit .noinit.*)
        . = ALIGN(16);
    }
    __el3_ram_end = .;

    /DISCARD/ : {
        *(.note*)
        *(.comment)
        *(.eh_frame*)
    }
}

ASSERT((wt_el3_vectors & 0x7FF) == 0, "EL3 vector table must be 2 KiB aligned")
ASSERT(__el3_ram_end <= WT_EL3_RAM_BASE + WT_EL3_RAM_SIZE, "EL3 RAM band overflow")
