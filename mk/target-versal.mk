# AMD Versal target inputs for the AArch64 build. Included first, before
# mk/arch-<arch>.mk and mk/common.mk; repository paths come from the Makefile.
# WT_VERSAL_VIRT=1 selects the QEMU xlnx-versal-virt variant of the port.
WT_CPU ?= cortex-a72
WT_GIC_VERSION := 3
WT_PORT_BOOT_CPUS ?= 2
WT_VERSAL_VIRT ?= 1
ifneq ($(WT_VERSAL_VIRT),1)
$(error the Versal silicon paths land with the port bring-up; build with WT_VERSAL_VIRT=1)
endif
PORT_DIR := $(ROOT)/port/versal
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
TARGET_CONF_DIR := $(PORT_DIR)/conformance
MANIFEST_INPUT := $(PORT_DIR)/manifest.json

WT_EL3_TEXT_BASE ?= 0xFFFC0000
WT_EL3_RAM_BASE ?= 0xFFFE0000
WT_EL3_RAM_SIZE ?= 0x00020000
# First page of the SPM band carries the FF-A boot information blob, the
# translation-table pool follows it.
WT_SPM_BOOT_INFO_PA ?= 0x7F000000
WT_SPM_TABLE_POOL_PA ?= 0x7F001000
WT_SPM_TABLE_POOL_PAGES ?= 16
# S-EL1 SPMC image band (placed by the loader), its RAM band, and the
# wolfHSM keystore band.
WT_SPM_IMAGE_PA ?= 0x7F100000
WT_SPM_IMAGE_SIZE ?= 0x00100000
WT_SPM_RAM_PA ?= 0x7F200000
WT_SPM_RAM_SIZE ?= 0x00040000
WT_SPM_KEYSTORE_PA ?= 0x7F300000
WT_SPM_KEYSTORE_SIZE ?= 0x00040000
WT_QEMU_TEST_ENTROPY ?= $(WT_VERSAL_VIRT)
# The PLM configures the PS UARTs and CNTFRQ_EL0 before EL3 runs.
WT_UART_SKIP_INIT ?= 1
WT_PORT_CNTFRQ_KEEP ?= 1

TARGET_CFLAGS := \
    -DWT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE)u \
    -DWT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE)u \
    -DWT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)u \
    -DWT_SPM_BOOT_INFO_PA=$(WT_SPM_BOOT_INFO_PA)u \
    -DWT_SPM_TABLE_POOL_PA=$(WT_SPM_TABLE_POOL_PA)u \
    -DWT_SPM_TABLE_POOL_PAGES=$(WT_SPM_TABLE_POOL_PAGES)u \
    -DWT_PORT_BOOT_CPUS=$(WT_PORT_BOOT_CPUS)u \
    -DWT_UART_SKIP_INIT=$(WT_UART_SKIP_INIT) \
    -DWT_PORT_CNTFRQ_KEEP=$(WT_PORT_CNTFRQ_KEEP) \
    -DWT_VERSAL_VIRT=$(WT_VERSAL_VIRT) \
    -DWT_SPM_IMAGE_PA=$(WT_SPM_IMAGE_PA)u \
    -DWT_SPM_IMAGE_SIZE=$(WT_SPM_IMAGE_SIZE)u \
    -DWT_SPM_RAM_PA=$(WT_SPM_RAM_PA)u \
    -DWT_SPM_RAM_SIZE=$(WT_SPM_RAM_SIZE)u \
    -DWT_SPM_KEYSTORE_PA=$(WT_SPM_KEYSTORE_PA)u \
    -DWT_SPM_KEYSTORE_SIZE=$(WT_SPM_KEYSTORE_SIZE)u \
    -DWT_QEMU_TEST_ENTROPY=$(WT_QEMU_TEST_ENTROPY)
TARGET_LDFLAGS := \
    -Wl,--defsym=WT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE) \
    -Wl,--defsym=WT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE) \
    -Wl,--defsym=WT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE) \
    -Wl,--defsym=WT_SPM_IMAGE_PA=$(WT_SPM_IMAGE_PA) \
    -Wl,--defsym=WT_SPM_IMAGE_SIZE=$(WT_SPM_IMAGE_SIZE) \
    -Wl,--defsym=WT_SPM_RAM_PA=$(WT_SPM_RAM_PA) \
    -Wl,--defsym=WT_SPM_RAM_SIZE=$(WT_SPM_RAM_SIZE) \
    -Wl,--defsym=WT_SPM_KEYSTORE_PA=$(WT_SPM_KEYSTORE_PA) \
    -Wl,--defsym=WT_SPM_KEYSTORE_SIZE=$(WT_SPM_KEYSTORE_SIZE)
SECURE_LD := $(ROOT)/src/arch/aarch64/spm/wolftrust.ld

PORT_COMMON_DIR := $(ROOT)/port/common/aarch64
TARGET_PLATFORM_SRC := $(PORT_COMMON_DIR)/platform_qemu.c
TARGET_PARTITIONS_SRC := $(PORT_COMMON_DIR)/partitions.c
TARGET_EXTRA_SRCS := $(PORT_COMMON_DIR)/hsm_nvm.c $(PORT_COMMON_DIR)/rng_entropy.c
EL3_PORT_SRCS := $(PORT_DIR)/el3_board.c $(PORT_DIR)/uart.c
