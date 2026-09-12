# QEMU virt (secure=on) target inputs for the AArch64 build. Included first,
# before mk/arch-<arch>.mk and mk/common.mk; repository paths come from the
# Makefile. GICv2 or GICv3 and the CPU model are runner-selected.
WT_CPU ?= cortex-a72
WT_GIC_VERSION ?= 3
WT_PORT_BOOT_CPUS ?= 2
PORT_DIR := $(ROOT)/port/qemuvirt
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
TARGET_CONF_DIR := $(PORT_DIR)/conformance
MANIFEST_INPUT := $(PORT_DIR)/manifest.json

WT_EL3_TEXT_BASE ?= 0x00000000
WT_EL3_RAM_BASE ?= 0x0E000000
WT_EL3_RAM_SIZE ?= 0x00040000
WT_UART_SKIP_INIT ?= 0
# QEMU presets CNTFRQ_EL0; leave it alone like a boot ROM would.
WT_PORT_CNTFRQ_KEEP ?= 1

TARGET_CFLAGS := \
    -DWT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE)u \
    -DWT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE)u \
    -DWT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)u \
    -DWT_PORT_BOOT_CPUS=$(WT_PORT_BOOT_CPUS)u \
    -DWT_UART_SKIP_INIT=$(WT_UART_SKIP_INIT) \
    -DWT_PORT_CNTFRQ_KEEP=$(WT_PORT_CNTFRQ_KEEP)
TARGET_LDFLAGS := \
    -Wl,--defsym=WT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE) \
    -Wl,--defsym=WT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE) \
    -Wl,--defsym=WT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)
SECURE_LD :=

TARGET_PLATFORM_SRC :=
TARGET_PARTITIONS_SRC :=
TARGET_EXTRA_SRCS :=
EL3_PORT_SRCS := $(PORT_DIR)/el3_board.c $(PORT_DIR)/uart.c
