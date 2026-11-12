# NXP MIMXRT700 (MIMXRT798S compute Cortex-M33, cpu0) target inputs for the
# secure image build. Included first, before mk/arch-<arch>.mk and
# mk/common.mk; repository paths come from the Makefile.
WT_CPU ?= cortex-m33
PORT_DIR := $(ROOT)/port/mimxrt700
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)

# Guests share LPUART0 (LP_FLEXCOMM0), the EVK MCU-Link VCOM console.
WT_SHARED_UART ?= 0
# Clocks left as the first loader configured them; verify against the RM
# before a guest derives a baud divider from these.
WT_GUEST_CORE_CLOCK_HZ ?= 237500000
WT_GUEST_UART_CLOCK_HZ ?= 24000000
# The conformance PAL interrupt source: LP_FLEXCOMM1's NVIC line, raised by
# software so no peripheral needs bringing up for it.
WT_CONF_IRQ ?= 8
WT_CONF_IRQ_HANDLER ?= LP_FLEXCOMM1_IRQHandler

# XSPI0 NOR through its Secure alias. The default is the wolfBoot handoff
# layout (wolfBoot at flash+0 owns the FCB and boot header).
WT_SECURE_FLASH_BASE ?= 0x38040000
WT_SECURE_FLASH_SIZE ?= 0x00040000
# wolfBoot's RT700 image header (IMAGE_HEADER_SIZE=1024) precedes the vectors.
WT_SECURE_IMAGE_HEADER_SIZE ?= 0x400
WT_GUEST0_FLASH_BASE ?= 0x28080000
WT_GUEST1_FLASH_BASE ?= 0x28100000
WT_GUEST0_FLASH_SIZE ?= 0x00080000
WT_GUEST1_FLASH_SIZE ?= 0x00040000

# XIP from XSPI NOR: the gateway and the NOR program/erase code run from the
# RAM code band (WT_RAMFUNC_* in memory_map.h).
WT_LD_RAM_CODE_BAND := 1
# This port links no wolfHAL, so the post-link check expects no wolfHAL state.
WT_SECURE_LAYOUT_EXTRA_ARGS := --no-wolfhal

TARGET_PLATFORM_SRC := $(PORT_DIR)/platform_mimxrt700.c
TARGET_EXTRA_SRCS := \
    $(wildcard $(PORT_DIR)/rng_entropy.c) \
    $(wildcard $(PORT_DIR)/hsm_flash.c) \
    $(wildcard $(PORT_DIR)/hsm_flash_ctx.c) \
    $(wildcard $(PORT_DIR)/xspi_nor.c)
