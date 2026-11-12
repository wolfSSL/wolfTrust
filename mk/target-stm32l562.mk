# ST STM32L562 (STM32L562E-DK, Cortex-M33) target inputs for the secure image
# build. Included first, before mk/arch-<arch>.mk and mk/common.mk; repository
# paths come from the Makefile.
WT_CPU ?= cortex-m33
PORT_DIR := $(ROOT)/port/stm32l562
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
TARGET_CONF_DIR := $(PORT_DIR)/conformance

ifeq ($(CONFIG_VNET),y)
$(error TARGET=stm32l562 has no SERVICE_VNET manifest; build with CONFIG_VNET=n)
endif
# 256 KiB of SRAM holds the native engine's level 3 bands beside two guests;
# the wolfHSM server's per-guest bands and stacks do not fit.
ifneq ($(filter hsm,$(WT_ENGINE))$(filter 1,$(WT_ENGINE_HSM)),)
$(error TARGET=stm32l562 supports WT_ENGINE=native only; the wolfHSM engine's bands do not fit 256 KiB of SRAM)
endif
ifeq ($(WT_CONFORMANCE),1)
MANIFEST_INPUT := $(PORT_DIR)/manifest-conformance.json
else
MANIFEST_INPUT := $(PORT_DIR)/manifest.json
endif

# Guests share USART1 (PA9/PA10), the DK's ST-LINK virtual COM port, clocked
# from PCLK2 at the 110 MHz wolfBoot leaves running.
WT_SHARED_UART ?= 1
WT_GUEST_CORE_CLOCK_HZ ?= 110000000
WT_GUEST_UART_CLOCK_HZ ?= 110000000
# The conformance PAL interrupt source: USART3's NVIC line (unused on the DK),
# pended by software so no peripheral needs bringing up for it.
WT_CONF_IRQ ?= 63
WT_CONF_IRQ_HANDLER ?= USART3_IRQHandler

# The wolfBoot stm32l5-tz-wolftrust layout: wolfBoot at flash+0 (48 KiB), the
# Secure image slot at 0x0C00C000. Conformance builds use the larger slot and
# guest0 window documented in port/stm32l562/memory_map.h.
WT_SECURE_FLASH_BASE ?= 0x0C00C000
WT_SECURE_IMAGE_HEADER_SIZE ?= 0x400
ifeq ($(WT_CONFORMANCE),1)
WT_SECURE_FLASH_SIZE ?= 0x00028000
WT_GUEST0_FLASH_BASE ?= 0x08040000
WT_GUEST1_FLASH_BASE ?= 0x0807C000
WT_GUEST0_FLASH_SIZE ?= 0x0003C000
WT_GUEST1_FLASH_SIZE ?= 0x00003800
else
WT_SECURE_FLASH_SIZE ?= 0x00020000
WT_GUEST0_FLASH_BASE ?= 0x08060000
WT_GUEST1_FLASH_BASE ?= 0x08070000
WT_GUEST0_FLASH_SIZE ?= 0x00010000
WT_GUEST1_FLASH_SIZE ?= 0x00010000
endif

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

TARGET_PLATFORM_SRC := $(PORT_DIR)/platform_stm32l562.c
TARGET_PARTITIONS_SRC := $(PORT_DIR)/partitions.c
TARGET_EXTRA_SRCS := \
    $(PORT_DIR)/gtzc.c \
    $(PORT_DIR)/guest_wrp.c \
    $(PORT_DIR)/rng_entropy.c \
    $(PORT_DIR)/hsm_flash.c \
    $(PORT_DIR)/hsm_flash_ctx.c
