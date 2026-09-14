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
# First page of the SPM band carries the FF-A boot information blob, the
# translation-table pool follows it.
WT_SPM_BOOT_INFO_PA ?= 0x0E040000
WT_SPM_TABLE_POOL_PA ?= 0x0E041000
WT_SPM_TABLE_POOL_PAGES ?= 64
# S-EL1 SPMC image band (code + constant data, copied from flash by EL3),
# its RAM band, and the wolfHSM keystore band; the flash offset is where the
# runner places wolftrust.bin inside the pflash image behind the monitor.
WT_SPM_IMAGE_PA ?= 0x0E100000
WT_SPM_IMAGE_SIZE ?= 0x00100000
WT_SPM_RAM_PA ?= 0x0E200000
WT_SPM_RAM_SIZE ?= 0x00040000
WT_SPM_KEYSTORE_PA ?= 0x0E300000
WT_SPM_KEYSTORE_SIZE ?= 0x00040000
WT_SPM_FLASH_OFFSET ?= 0x00100000
WT_QEMU_TEST_ENTROPY ?= 1
WT_UART_SKIP_INIT ?= 0
# QEMU presets CNTFRQ_EL0; leave it alone like a boot ROM would.
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
    -DWT_SPM_IMAGE_PA=$(WT_SPM_IMAGE_PA)u \
    -DWT_SPM_IMAGE_SIZE=$(WT_SPM_IMAGE_SIZE)u \
    -DWT_SPM_RAM_PA=$(WT_SPM_RAM_PA)u \
    -DWT_SPM_RAM_SIZE=$(WT_SPM_RAM_SIZE)u \
    -DWT_SPM_KEYSTORE_PA=$(WT_SPM_KEYSTORE_PA)u \
    -DWT_SPM_KEYSTORE_SIZE=$(WT_SPM_KEYSTORE_SIZE)u \
    -DWT_SPM_FLASH_OFFSET=$(WT_SPM_FLASH_OFFSET)u \
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
