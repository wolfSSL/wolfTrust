/* S-EL1 SPMC image: code and constant data in the SPM image band (loaded by
 * the monitor on QEMU virt, by the loader on Versal), data, bss, and the
 * bootstrap stack in the SPM RAM band, the wolfHSM keystore state in its own
 * band so the keystore partitions can be granted exactly it. Band addresses
 * arrive as --defsym values from mk/target-<soc>.mk. */
ENTRY(wt_spm_entry)

MEMORY
{
    IMAGE (rx) : ORIGIN = WT_SPM_IMAGE_PA, LENGTH = WT_SPM_IMAGE_SIZE
    RAM (rw) : ORIGIN = WT_SPM_RAM_PA, LENGTH = WT_SPM_RAM_SIZE
    KEYSTORE (rw) : ORIGIN = WT_SPM_KEYSTORE_PA, LENGTH = WT_SPM_KEYSTORE_SIZE
    CONFDATA (rw) : ORIGIN = WT_SPM_CONFDATA_PA, LENGTH = WT_SPM_CONFDATA_SIZE
}

SECTIONS
{
    .text : {
        KEEP(*(.text.wt_spm_entry))
        *(.text .text.*)
        . = ALIGN(4096);
        _e_secure_text = .;
    } > IMAGE
    .rodata : {
        KEEP(*(.wt_guest_meas))
        *(.rodata .rodata.*)
        . = ALIGN(4096);
        _e_secure_rodata = .;
    } > IMAGE

    .keystore_data : {
        . = ALIGN(16);
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
        *hsm_nvm.o(.data .data.*)
        *wolfcose.o(.data .data.*)
        *wolfcose_cbor.o(.data .data.*)
        *wh_sec_*.o(.data .data.*)
        *wc_sec_*.o(.data .data.*)
        . = ALIGN(16);
        _e_keystore_data = .;
    } > KEYSTORE AT > IMAGE
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
        *hsm_nvm.o(.bss .bss.* COMMON)
        *wolfcose.o(.bss .bss.* COMMON)
        *wolfcose_cbor.o(.bss .bss.* COMMON)
        *wh_sec_*.o(.bss .bss.* COMMON)
        *wc_sec_*.o(.bss .bss.* COMMON)
        . = ALIGN(16);
        _e_keystore = .;
    } > KEYSTORE

    /* The Arm conformance partitions run at S-EL0 and keep their writable
     * state in this band while SPM RAM stays EL1-only: one page-aligned
     * segment per partition, each granted to its owner alone
     * (wt_platform_conf_sp_grants). Empty in non-conformance builds. */
    .conf_data : {
        _s_conf_data = .;
        _s_conf_server_data = .;
        *conf_sec_server_partition.o(.data .data.* .bss .bss.* COMMON)
        *conf_sec_test_supp_*.o(.data .data.* .bss .bss.* COMMON)
        . = ALIGN(4096);
        _e_conf_server_data = .;
        _s_conf_client_data = .;
        *conf_sec_client_partition.o(.data .data.* .bss .bss.* COMMON)
        *conf_sec_test_i*.o(.data .data.* .bss .bss.* COMMON)
        . = ALIGN(4096);
        _e_conf_client_data = .;
        _s_conf_driver_data = .;
        *conf_sec_driver_partition.o(.data .data.* .bss .bss.* COMMON)
        *conf_sec_val_driver_service_apis.o(.data .data.* .bss .bss.* COMMON)
        *conf_sec_val_log.o(.data .data.* .bss .bss.* COMMON)
        *conf_sec_pal_driver_intf.o(.data .data.* .bss .bss.* COMMON)
        *conf_sec_conf_nvm_sync.o(.data .data.* .bss .bss.* COMMON)
        . = ALIGN(4096);
        _e_conf_driver_data = .;
        _s_conf_unowned = .;
        *conf_sec_*.o(.data .data.*)
        _e_conf_unowned = .;
        . = ALIGN(16);
        _e_conf_data_data = .;
    } > CONFDATA AT > IMAGE
    _si_conf_data = LOADADDR(.conf_data);
    .conf_bss (NOLOAD) : {
        _s_conf_bss = .;
        *conf_sec_*.o(.bss .bss.* COMMON)
        . = ALIGN(16);
        _e_conf_bss = .;
    } > CONFDATA
    _e_conf_data = .;

    .data : {
        . = ALIGN(16);
        __data_start = .;
        *(.data .data.*)
        . = ALIGN(16);
        __data_end = .;
    } > RAM AT > IMAGE
    __data_lma = LOADADDR(.data);
    __image_end = __data_lma + SIZEOF(.data);
    .bss (NOLOAD) : {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } > RAM
    .stack (NOLOAD) : {
        . = ALIGN(16);
        . += 0x4000;
        __spm_stack_top = .;
    } > RAM
    /* Outside the bss-clear range and NOLOAD, so the conformance NVM shadow
     * survives the EL3 warm reset the panic tests use (QEMU keeps RAM across a
     * warm reset). Empty in non-conformance builds. */
    .noinit (NOLOAD) : {
        . = ALIGN(16);
        *(.noinit .noinit.*)
        . = ALIGN(16);
    } > RAM
    __spm_ram_end = .;

    /DISCARD/ : {
        *(.note*)
        *(.comment)
        *(.eh_frame*)
    }
}

ASSERT((wt_spm_vectors & 0x7FF) == 0, "S-EL1 vector table must be 2 KiB aligned")
ASSERT(__image_end <= WT_SPM_IMAGE_PA + WT_SPM_IMAGE_SIZE, "SPM image band overflow")
ASSERT(_e_keystore <= WT_SPM_KEYSTORE_PA + WT_SPM_KEYSTORE_SIZE, "keystore band overflow")
ASSERT(_e_conf_data <= WT_SPM_CONFDATA_PA + WT_SPM_CONFDATA_SIZE, "conformance data band overflow")
ASSERT(_e_conf_bss <= WT_SPM_CONFDATA_PA + 0x1C000, "conformance data reaches the pseudo-MMIO pages")
ASSERT((_s_conf_data & 0xFFF) == 0, "conformance partition segments must be page aligned")
ASSERT((_e_conf_unowned == _s_conf_unowned) && (_e_conf_bss == _s_conf_bss),
       "a conformance object has writable data no partition owns")
