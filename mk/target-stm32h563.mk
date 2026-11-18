# STM32H563 target inputs for the secure image build. Included first, before
# mk/arch-<arch>.mk and mk/common.mk; repository paths come from the Makefile.
WT_CPU ?= cortex-m33
PORT_DIR := $(ROOT)/port/stm32h563
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)

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
# The Arm suite overflows the 128 KiB standalone slot. Refused at the link
# only, so the host manifest suites still render its manifest.
ifeq ($(WT_CONFORMANCE)/$(filter 0x00020000 0x20000,$(WT_SECURE_FLASH_SIZE)),1/$(WT_SECURE_FLASH_SIZE))
WT_SECURE_LINK_REFUSE := WT_CONFORMANCE=1 needs the 256 KiB Secure slot on the STM32H563; build it in the M33MU layout (port_layout_env in tests/target/ports/stm32h563/m33mu.sh)
endif
WT_GUEST0_FLASH_BASE ?= 0x08020000
WT_GUEST1_FLASH_BASE ?= 0x08040000
WT_GUEST0_FLASH_SIZE ?= 0x00020000
WT_GUEST1_FLASH_SIZE ?= 0x00020000

TARGET_CFLAGS := -DWHAL_CFG_STM32H5_RNG_DIRECT_API_MAPPING

TARGET_PLATFORM_SRC := $(PORT_DIR)/platform_stm32h563.c
TARGET_EXTRA_SRCS := \
    $(PORT_DIR)/silicon_rev.c \
    $(PORT_DIR)/silicon_guard.c \
    $(WOLFHAL_DIR)/src/reg.c \
    $(WOLFHAL_DIR)/src/rng/stm32h5_rng.c
