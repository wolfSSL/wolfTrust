# NXP MIMXRT700 (MIMXRT798S compute Cortex-M33, cpu0) target inputs for the
# secure image build. Included first, before mk/arch-<arch>.mk and
# mk/common.mk; repository paths come from the Makefile.
WT_CPU ?= cortex-m33
PORT_DIR := $(ROOT)/port/mimxrt700
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)
TARGET_CONF_DIR := $(PORT_DIR)/conformance

# WT_CONFORMANCE=1 swaps in the manifest that also hosts Arm's test partitions.
ifeq ($(CONFIG_VNET),y)
$(error TARGET=mimxrt700 has no SERVICE_VNET manifest; build with CONFIG_VNET=n)
endif
ifeq ($(WT_CONFORMANCE),1)
MANIFEST_INPUT := $(PORT_DIR)/manifest-conformance.json
else
MANIFEST_INPUT := $(PORT_DIR)/manifest.json
endif

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
# Post-link placement check: the keystore and conformance bands from
# memory_map.h (WT_KEYSTORE_BASE, WT_CONF_SP_DATA_BASE up to the MMIO windows);
# this port uses no wolfHAL.
WT_SECURE_LAYOUT_ARGS := --keystore 0x301D5000:0x301E9000 \
    --confdata 0x301F3000:0x301F5C00 --no-wolfhal

TARGET_PLATFORM_SRC := $(PORT_DIR)/platform_mimxrt700.c
TARGET_PARTITIONS_SRC := $(PORT_DIR)/partitions.c
TARGET_EXTRA_SRCS := \
    $(wildcard $(PORT_DIR)/rng_entropy.c) \
    $(wildcard $(PORT_DIR)/hsm_flash.c) \
    $(wildcard $(PORT_DIR)/xspi_nor.c)
