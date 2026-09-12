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
    -DWT_VERSAL_VIRT=$(WT_VERSAL_VIRT)
TARGET_LDFLAGS := \
    -Wl,--defsym=WT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE) \
    -Wl,--defsym=WT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE) \
    -Wl,--defsym=WT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)
SECURE_LD :=

TARGET_PLATFORM_SRC :=
TARGET_PARTITIONS_SRC :=
TARGET_EXTRA_SRCS :=
EL3_PORT_SRCS := $(PORT_DIR)/el3_board.c $(PORT_DIR)/uart.c
