# AMD Versal target inputs for the AArch64 build. Included first, before
# mk/arch-<arch>.mk and mk/common.mk; repository paths come from the Makefile.
# WT_VERSAL_VIRT=1 selects the QEMU xlnx-versal-virt variant of the port.
WT_CPU ?= cortex-a72
WT_GIC_VERSION := 3
# xlnx-versal-virt keeps APU core 1 powered off: only the boot core comes up.
WT_PORT_BOOT_CPUS ?= 1
WT_VERSAL_VIRT ?= 1
ifneq ($(WT_VERSAL_VIRT),1)
$(error the Versal silicon paths land with the port bring-up; build with WT_VERSAL_VIRT=1)
endif
PORT_DIR := $(ROOT)/port/versal
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
# The conformance PAL is shared by the AArch64 targets; WT_CONFORMANCE=1 swaps
# in the manifest that also hosts Arm's test partitions.
TARGET_CONF_DIR := $(ROOT)/port/common/aarch64/conformance
ifeq ($(WT_CONFORMANCE),1)
MANIFEST_INPUT := $(PORT_DIR)/manifest-conformance.json
else
MANIFEST_INPUT := $(PORT_DIR)/manifest.json
endif

WT_EL3_TEXT_BASE ?= 0xFFFC0000
WT_EL3_RAM_BASE ?= 0xFFFE0000
WT_EL3_RAM_SIZE ?= 0x00020000
WT_NS_IMAGE_PA ?= 0x44000000
WT_PSA_NS_WINDOW_SIZE ?= 0x00100000
WT_QEMU_TEST_ENTROPY ?= $(WT_VERSAL_VIRT)
# The PLM configures the PS UARTs and CNTFRQ_EL0 before EL3 runs.
WT_UART_SKIP_INIT ?= 1
WT_PORT_CNTFRQ_KEEP ?= 1

TARGET_CFLAGS := \
    -DWT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE)u \
    -DWT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE)u \
    -DWT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)u \
    -DWT_PORT_BOOT_CPUS=$(WT_PORT_BOOT_CPUS)u \
    -DWT_UART_SKIP_INIT=$(WT_UART_SKIP_INIT) \
    -DWT_PORT_CNTFRQ_KEEP=$(WT_PORT_CNTFRQ_KEEP) \
    -DWT_VERSAL_VIRT=$(WT_VERSAL_VIRT) \
    -DWT_NS_IMAGE_PA=$(WT_NS_IMAGE_PA)u \
    -DWT_PSA_NS_WINDOW_SIZE=$(WT_PSA_NS_WINDOW_SIZE)u \
    -DWT_QEMU_TEST_ENTROPY=$(WT_QEMU_TEST_ENTROPY)
# No boot loader runs ahead of the monitor under QEMU: synthesize the boot
# handoff record it would leave (emulator tests only, never production).
WT_EL3_TEST_HANDOFF ?= 0
ifeq ($(WT_EL3_TEST_HANDOFF),1)
TARGET_CFLAGS += -DWT_EL3_TEST_HANDOFF=1 -DWT_PORT_HANDOFF_SIZE=64u
endif
# Arm FF-A ACS conformance image (its band base comes from the shared layout).
WT_FFA_ACS ?= 0
ifeq ($(WT_FFA_ACS),1)
TARGET_CFLAGS += -DWT_FFA_ACS=1
endif
TARGET_LDFLAGS := \
    -Wl,--defsym=WT_EL3_LOAD_LIMIT=$(WT_EL3_RAM_BASE) \
    -Wl,--defsym=WT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE) \
    -Wl,--defsym=WT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE) \
    -Wl,--defsym=WT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)
SECURE_LD := $(ROOT)/src/arch/aarch64/spm/wolftrust.ld

PORT_COMMON_DIR := $(ROOT)/port/common/aarch64
TARGET_PLATFORM_SRC := $(PORT_COMMON_DIR)/platform_qemu.c
TARGET_PARTITIONS_SRC := $(PORT_COMMON_DIR)/partitions.c
TARGET_EXTRA_SRCS := $(PORT_COMMON_DIR)/hsm_nvm.c $(PORT_COMMON_DIR)/rng_entropy.c
EL3_PORT_SRCS := $(PORT_DIR)/el3_board.c $(PORT_DIR)/uart.c
