# STM32H563 target inputs for the secure image build. Included first, before
# mk/arch-<arch>.mk and mk/common.mk; repository paths come from the Makefile.
WT_CPU ?= cortex-m33
PORT_DIR := $(ROOT)/port/stm32h563
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
TARGET_CONF_DIR := $(PORT_DIR)/conformance

# WT_CONFORMANCE=1 swaps in the manifest that also hosts Arm's test partitions;
# CONFIG_VNET=y swaps in the variant that adds the SERVICE_VNET partition so
# the default image carries no virtual network service at all
ifeq ($(WT_CONFORMANCE),1)
MANIFEST_INPUT := $(PORT_DIR)/manifest-conformance.json
else ifeq ($(CONFIG_VNET),y)
MANIFEST_INPUT := $(PORT_DIR)/manifest-vnet.json
else
MANIFEST_INPUT := $(PORT_DIR)/manifest.json
endif

WT_SHARED_UART ?= 3
WT_GUEST_CORE_CLOCK_HZ ?= 240000000
WT_GUEST_UART_CLOCK_HZ ?= 120000000
# The conformance PAL interrupt source: LPUART1's NVIC line and handler.
WT_CONF_IRQ ?= 63
WT_CONF_IRQ_HANDLER ?= LPUART1_IRQHandler
WT_WOLFCRYPT_STM32_HASH ?= 0

# wolfHSM resumes SHA-256 operations from the portable digest and length
# fields carried by its wire protocol. STM32 HASH uses opaque peripheral CSR
# state instead, so enabling it here would remove the wolfHSM SHA handler and
# make a client fallback operate on a partially modified context.
ifneq ($(WT_WOLFCRYPT_STM32_HASH),0)
$(error WT_WOLFCRYPT_STM32_HASH is incompatible with the wolfHSM SHA service)
endif

# Secure runtime placement. The default preserves the standalone image;
# the wolfBoot handoff build relocates it to 0x0C020000.
WT_SECURE_FLASH_BASE ?= 0x0C000000
WT_SECURE_FLASH_SIZE ?= 0x00020000
WT_SECURE_IMAGE_HEADER_SIZE ?= 0
WT_GUEST0_FLASH_BASE ?= 0x08020000
WT_GUEST1_FLASH_BASE ?= 0x08040000
WT_GUEST0_FLASH_SIZE ?= 0x00020000
WT_GUEST1_FLASH_SIZE ?= 0x00020000

TARGET_CFLAGS := \
    -DWT_SHARED_UART=$(WT_SHARED_UART) \
    -DWT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ) \
    -DWT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ) \
    -DWT_CONF_IRQ=$(WT_CONF_IRQ)u \
    -DWT_CONF_IRQ_HANDLER=$(WT_CONF_IRQ_HANDLER) \
    -DWT_SECURE_FLASH_BASE=$(WT_SECURE_FLASH_BASE) \
    -DWT_SECURE_FLASH_SIZE=$(WT_SECURE_FLASH_SIZE) \
    -DWT_SECURE_IMAGE_HEADER_SIZE=$(WT_SECURE_IMAGE_HEADER_SIZE) \
    -DWT_GUEST0_FLASH_BASE=$(WT_GUEST0_FLASH_BASE) \
    -DWT_GUEST1_FLASH_BASE=$(WT_GUEST1_FLASH_BASE) \
    -DWT_GUEST0_FLASH_SIZE=$(WT_GUEST0_FLASH_SIZE) \
    -DWT_GUEST1_FLASH_SIZE=$(WT_GUEST1_FLASH_SIZE) \
    -DWHAL_CFG_STM32H5_RNG_DIRECT_API_MAPPING
TARGET_LDFLAGS := \
    -Wl,--defsym=WT_SECURE_FLASH_ORIGIN=$(WT_SECURE_FLASH_BASE) \
    -Wl,--defsym=WT_SECURE_FLASH_SIZE=$(WT_SECURE_FLASH_SIZE) \
    -Wl,--defsym=WT_SECURE_IMAGE_HEADER_SIZE=$(WT_SECURE_IMAGE_HEADER_SIZE)
SECURE_LD := $(WOLFHSM_RUNNER_DIR)/secure.ld

TARGET_PLATFORM_SRC := $(PORT_DIR)/platform_stm32h563.c
TARGET_PARTITIONS_SRC := $(PORT_DIR)/partitions.c
TARGET_EXTRA_SRCS := \
    $(wildcard $(PORT_DIR)/rng_entropy.c) \
    $(wildcard $(PORT_DIR)/hsm_flash.c) \
    $(WOLFHAL_DIR)/src/reg.c \
    $(WOLFHAL_DIR)/src/rng/stm32h5_rng.c
