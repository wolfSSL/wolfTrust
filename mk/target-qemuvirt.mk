# QEMU virt (secure=on) target inputs for the AArch64 build. Included first,
# before mk/arch-<arch>.mk and mk/common.mk; repository paths come from the
# Makefile. GICv2 or GICv3 and the CPU model are runner-selected.
WT_CPU ?= cortex-a72
WT_GIC_VERSION ?= 3
WT_PORT_BOOT_CPUS ?= 2
PORT_DIR := $(ROOT)/port/qemuvirt
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
# The conformance PAL is shared by the AArch64 targets; WT_CONFORMANCE=1 swaps
# in the manifest that also hosts Arm's test partitions.
TARGET_CONF_DIR := $(ROOT)/port/common/aarch64/conformance
ifeq ($(WT_CONFORMANCE),1)
MANIFEST_INPUT := $(PORT_DIR)/manifest-conformance.json
else
MANIFEST_INPUT := $(PORT_DIR)/manifest.json
endif

WT_EL3_TEXT_BASE ?= 0x00000000
WT_EL3_RAM_BASE ?= 0x0E000000
WT_EL3_RAM_SIZE ?= 0x00040000
WT_NS_IMAGE_PA ?= 0x44000000
WT_PSA_NS_WINDOW_SIZE ?= 0x00100000
WT_SPM_FLASH_OFFSET ?= 0x00100000
WT_QEMU_TEST_ENTROPY ?= 1
# A system reset reboots the machine through its Secure GPIO, bounded so a test
# run ends (the conformance suite resets on every panic test).
ifeq ($(WT_CONFORMANCE),1)
WT_EL3_RESET_LIMIT ?= 256
else
WT_EL3_RESET_LIMIT ?= 1
endif
WT_UART_SKIP_INIT ?= 0
# QEMU presets CNTFRQ_EL0; leave it alone like a boot ROM would.
WT_PORT_CNTFRQ_KEEP ?= 1

TARGET_CFLAGS := \
    -DWT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE)u \
    -DWT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE)u \
    -DWT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)u \
    -DWT_PORT_BOOT_CPUS=$(WT_PORT_BOOT_CPUS)u \
    -DWT_UART_SKIP_INIT=$(WT_UART_SKIP_INIT) \
    -DWT_PORT_CNTFRQ_KEEP=$(WT_PORT_CNTFRQ_KEEP) \
    -DWT_NS_IMAGE_PA=$(WT_NS_IMAGE_PA)u \
    -DWT_PSA_NS_WINDOW_SIZE=$(WT_PSA_NS_WINDOW_SIZE)u \
    -DWT_SPM_FLASH_OFFSET=$(WT_SPM_FLASH_OFFSET)u \
    -DWT_QEMU_TEST_ENTROPY=$(WT_QEMU_TEST_ENTROPY) \
    -DWT_EL3_RESET_LIMIT=$(WT_EL3_RESET_LIMIT)u \
    -DWT_PORT_EMULATED=1
# No boot loader runs ahead of the monitor under QEMU: synthesize the boot
# handoff record it would leave (emulator tests only, never production).
WT_EL3_TEST_HANDOFF ?= 0
ifeq ($(WT_EL3_TEST_HANDOFF),1)
TARGET_CFLAGS += -DWT_EL3_TEST_HANDOFF=1 -DWT_PORT_HANDOFF_SIZE=64u
endif
# Arm FF-A ACS conformance image (its band base comes from the shared layout).
WT_FFA_ACS ?= 0
# The runner places the partition images and the test NVM here in the pflash
# image; the monitor copies them into Secure RAM.
WT_FFA_ACS_FLASH_OFFSET ?= 0x00200000
WT_FFA_ACS_FLASH_SIZE ?= 0x00410000
# The test NVM rides at this offset within the ACS band, behind the four 1 MB
# SP images; it must survive a reset (the suite records progress in it).
WT_FFA_ACS_NVM_OFFSET ?= 0x00400000
ifeq ($(WT_FFA_ACS),1)
TARGET_CFLAGS += -DWT_FFA_ACS=1 \
    -DWT_FFA_ACS_FLASH_OFFSET=$(WT_FFA_ACS_FLASH_OFFSET)u \
    -DWT_FFA_ACS_FLASH_SIZE=$(WT_FFA_ACS_FLASH_SIZE)u \
    -DWT_FFA_ACS_NVM_OFFSET=$(WT_FFA_ACS_NVM_OFFSET)u
endif
# The monitor's load image must end before the SPMC image packed behind it in
# the one pflash file (run_qemu_a_scenario.sh truncates to this offset).
TARGET_LDFLAGS := \
    -Wl,--defsym=WT_EL3_LOAD_LIMIT=$(WT_EL3_TEXT_BASE)+$(WT_SPM_FLASH_OFFSET) \
    -Wl,--defsym=WT_EL3_TEXT_BASE=$(WT_EL3_TEXT_BASE) \
    -Wl,--defsym=WT_EL3_RAM_BASE=$(WT_EL3_RAM_BASE) \
    -Wl,--defsym=WT_EL3_RAM_SIZE=$(WT_EL3_RAM_SIZE)
SECURE_LD := $(ROOT)/src/arch/aarch64/spm/wolftrust.ld

PORT_COMMON_DIR := $(ROOT)/port/common/aarch64
TARGET_PLATFORM_SRC := $(PORT_COMMON_DIR)/platform_qemu.c
TARGET_PARTITIONS_SRC := $(PORT_COMMON_DIR)/partitions.c
TARGET_EXTRA_SRCS := $(PORT_COMMON_DIR)/hsm_nvm.c $(PORT_COMMON_DIR)/rng_entropy.c
EL3_PORT_SRCS := $(PORT_DIR)/el3_board.c $(PORT_DIR)/uart.c
