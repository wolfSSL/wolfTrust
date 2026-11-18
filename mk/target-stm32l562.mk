# ST STM32L562 (STM32L562E-DK, Cortex-M33) target inputs for the secure image
# build. Included first, before mk/arch-<arch>.mk and mk/common.mk; repository
# paths come from the Makefile.
WT_CPU ?= cortex-m33
PORT_DIR := $(ROOT)/port/stm32l562
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)

ifeq ($(CONFIG_VNET),y)
$(error TARGET=stm32l562 has no wolfIP network guests; build with CONFIG_VNET=n)
endif

# The native bands leave little of the 256 KiB SRAM; PSA crypto stays in the guests.
WT_SECURE_PSA ?= 0

# Under TZEN wolfBoot reports RDP level 0 as PSA_ROT_PROVISIONING, never the
# emulator runner's development default, so the PSA guest's verify pins 0x2000.
ifeq ($(origin WT_EXPECTED_LIFECYCLE)/$(WT_EXPECTED_LIFECYCLE),command line/0x1000u)
override WT_EXPECTED_LIFECYCLE := 0x2000u
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

# wolfBoot at flash+0 (48 KiB) and the Secure boot slot at 0x0C00C000. The
# production layout puts guest 0 at the top of bank 1 and guest 1, the update
# slot and the stores in bank 2; the conformance, TPM 2.0 and PKCS#11 images
# need a 160 KiB slot and a 240 KiB guest 0 that spans the banks.
WT_SECURE_FLASH_BASE ?= 0x0C00C000
WT_SECURE_IMAGE_HEADER_SIZE ?= 0x400
ifneq ($(filter 1,$(WT_CONFORMANCE))$(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),)
WT_SECURE_FLASH_SIZE ?= 0x00028000
WT_GUEST0_FLASH_BASE ?= 0x08034000
WT_GUEST1_FLASH_BASE ?= 0x08070000
WT_GUEST0_FLASH_SIZE ?= 0x0003C000
WT_GUEST1_FLASH_SIZE ?= 0x00004000
else
WT_SECURE_FLASH_SIZE ?= 0x00020000
WT_GUEST0_FLASH_BASE ?= 0x0802C000
WT_GUEST1_FLASH_BASE ?= 0x08040000
WT_GUEST0_FLASH_SIZE ?= 0x00014000
WT_GUEST1_FLASH_SIZE ?= 0x00010000
endif

# This port links no wolfHAL, so the post-link check expects no wolfHAL state.
WT_SECURE_LAYOUT_EXTRA_ARGS := --no-wolfhal

TARGET_PLATFORM_SRC := $(PORT_DIR)/platform_stm32l562.c
TARGET_EXTRA_SRCS := \
    $(PORT_DIR)/gtzc.c \
    $(PORT_DIR)/guest_wrp.c
