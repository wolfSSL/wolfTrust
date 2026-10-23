# NXP MCXN947 (FRDM-MCXN947, Cortex-M33 CPU0) target inputs for the secure
# image build. Included first, before mk/arch-<arch>.mk and mk/common.mk;
# repository paths come from the Makefile.
WT_CPU ?= cortex-m33
PORT_DIR := $(ROOT)/port/mcxn947
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
TARGET_CONF_DIR := $(PORT_DIR)/conformance

# WT_CONFORMANCE=1 swaps in the manifest that also hosts Arm's test partitions.
ifeq ($(CONFIG_VNET),y)
$(error TARGET=mcxn947 has no SERVICE_VNET manifest; build with CONFIG_VNET=n)
endif
ifeq ($(WT_CONFORMANCE),1)
MANIFEST_INPUT := $(PORT_DIR)/manifest-conformance.json
else
MANIFEST_INPUT := $(PORT_DIR)/manifest.json
endif

# Guests share LPUART4 (LP_FLEXCOMM4), the FRDM board's MCU-Link VCOM console.
WT_SHARED_UART ?= 0
# Clocks left as the first loader configured them (PLL150M core, FRO12M on
# FLEXCOMM4); verify against the RM before a guest derives a baud divider.
WT_GUEST_CORE_CLOCK_HZ ?= 150000000
WT_GUEST_UART_CLOCK_HZ ?= 12000000
# The conformance PAL interrupt source: LP_FLEXCOMM1's NVIC line, raised by
# software so no peripheral needs bringing up for it.
WT_CONF_IRQ ?= 36
WT_CONF_IRQ_HANDLER ?= LP_FLEXCOMM1_IRQHandler

# Internal flash through its Secure alias. The default is the wolfBoot
# mcxn-tz-wolftrust layout (wolfBoot at flash+0, BOOT at 0x40000).
WT_SECURE_FLASH_BASE ?= 0x10040000
WT_SECURE_FLASH_SIZE ?= 0x00040000
# wolfBoot's MCXN image header (IMAGE_HEADER_SIZE=1024) precedes the vectors.
WT_SECURE_IMAGE_HEADER_SIZE ?= 0x400
WT_GUEST0_FLASH_BASE ?= 0x00080000
WT_GUEST1_FLASH_BASE ?= 0x00100000
WT_GUEST0_FLASH_SIZE ?= 0x00080000
WT_GUEST1_FLASH_SIZE ?= 0x00040000

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
    -DWT_GUEST1_FLASH_SIZE=$(WT_GUEST1_FLASH_SIZE)
TARGET_LDFLAGS := \
    -Wl,--defsym=WT_SECURE_FLASH_ORIGIN=$(WT_SECURE_FLASH_BASE) \
    -Wl,--defsym=WT_SECURE_FLASH_SIZE=$(WT_SECURE_FLASH_SIZE) \
    -Wl,--defsym=WT_SECURE_IMAGE_HEADER_SIZE=$(WT_SECURE_IMAGE_HEADER_SIZE)
SECURE_LD := $(PORT_DIR)/secure.ld
# This port links no wolfHAL, so the post-link check expects no wolfHAL state.
WT_SECURE_LAYOUT_EXTRA_ARGS := --no-wolfhal

TARGET_PLATFORM_SRC := $(PORT_DIR)/platform_mcxn947.c
TARGET_PARTITIONS_SRC := $(PORT_DIR)/partitions.c
TARGET_EXTRA_SRCS := \
    $(wildcard $(PORT_DIR)/rng_entropy.c) \
    $(wildcard $(PORT_DIR)/rom_flash.c) \
    $(wildcard $(PORT_DIR)/hsm_flash.c) \
    $(wildcard $(PORT_DIR)/hsm_flash_ctx.c)
