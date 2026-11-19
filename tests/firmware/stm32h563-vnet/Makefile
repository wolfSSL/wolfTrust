# Makefile — stm32h563-vnet end-to-end ping test.
#
# Two baremetal NS guests + wolfIP, talking over the secure-monitor
# virtual Ethernet switch. guest0 pings guest1, prints the reply, the
# runner asserts on it.
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

TOOLPREFIX ?= arm-none-eabi-
CC         := $(TOOLPREFIX)gcc
OBJCOPY    := $(TOOLPREFIX)objcopy
SIZE       := $(TOOLPREFIX)size
M33MU      ?= m33mu

ROOT       := ../../..
PORT_DIR   := $(ROOT)/port/stm32h563
WOLFIP_DIR := $(ROOT)/lib/wolfIP

CONFIG_VNET ?= y
EMU_TIMEOUT ?= 60
WT_TIMESLICE_MS ?= 2
WT_MAX_GUESTS ?= 2

# Guest flash/RAM map matches the existing baremetal test target.
WT_GUEST0_FLASH_ORIGIN ?= 0x08020000
WT_GUEST1_FLASH_ORIGIN ?= 0x08040000
WT_GUEST_FLASH_SIZE    ?= 0x00020000
WT_GUEST0_RAM_BASE     := 0x20000000
WT_GUEST1_RAM_BASE     := 0x20008000
WT_GUEST_RAM_SIZE      := 0x00008000

# Emulator load offsets — m33mu lays out NS images at fixed offsets in its
# own image array and the secure side knows the partitions from
# memory_map.h. Match the values used by run-stm32h563-uarts.
WT_GUEST0_EMU_OFFSET ?= 0x20000
WT_GUEST1_EMU_OFFSET ?= 0x40000

WT_GUEST_CORE_CLOCK_HZ ?= 240000000
WT_GUEST_UART_CLOCK_HZ ?= 120000000

CPU_FLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only

# Guest CFLAGS. -I order matters: our wolfip_config/ overrides
# lib/wolfIP/config.h. wolfIP itself needs the lib/wolfIP root for
# `#include "wolfip.h"`-from-its-own-srcs.
GUEST_CFLAGS := $(CPU_FLAGS) -std=c99 -ffreestanding -fno-builtin -nostdlib -O2 -g \
    -Wall -Wextra -mno-unaligned-access \
    -ffunction-sections -fdata-sections \
    -I$(ROOT)/include \
    -I$(PORT_DIR) \
    -Inonsecure/wolfip_config \
    -I$(WOLFIP_DIR) \
    -Wno-unused-function \
    -Wno-unused-variable \
    -DWT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ) \
    -DWT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ) \
    -DWT_GUEST0_FLASH_BASE=$(WT_GUEST0_FLASH_ORIGIN)u \
    -DWT_GUEST1_FLASH_BASE=$(WT_GUEST1_FLASH_ORIGIN)u
GUEST_CFLAGS += $(GUEST_EXTRA_CFLAGS)

BUILD_DIR     := build
TOP_BUILD_DIR := $(ROOT)/build
SECURE_BIN    := $(TOP_BUILD_DIR)/wolftrust.bin
SECURE_CMSE_IMPLIB := $(TOP_BUILD_DIR)/secure_cmse_implib.o

GUEST0_ELF := $(BUILD_DIR)/guest0.elf
GUEST0_BIN := $(BUILD_DIR)/guest0.bin
GUEST1_ELF := $(BUILD_DIR)/guest1.elf
GUEST1_BIN := $(BUILD_DIR)/guest1.bin

GUEST_SRCS := \
    nonsecure/guest.c \
    nonsecure/libc_stubs.c \
    $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/client/vnet_psa_transport.c \
    $(WOLFIP_DIR)/src/wolfip.c

.PHONY: all secure clean run run-uarts

all: secure $(GUEST0_BIN) $(GUEST1_BIN)
	@$(SIZE) $(GUEST0_ELF) $(GUEST1_ELF)
	@for elf in $(GUEST0_ELF) $(GUEST1_ELF); do \
		NM_OUT=$$($(TOOLPREFIX)nm $$elf) || \
			{ echo "FAIL: nm on $$elf failed" >&2; exit 1; }; \
		if printf '%s\n' "$$NM_OUT" | grep -q 'WolfTrust_VNet_'; then \
			echo "FAIL: retired raw vnet veneer referenced by $$elf (WT-FFM-0057)" >&2; \
			exit 1; \
		fi; \
		printf '%s\n' "$$NM_OUT" | grep -q 'wt_vnet_psa_tx' || \
			{ echo "FAIL: mediated vnet transport missing from $$elf" >&2; exit 1; }; \
	done

secure:
	rm -rf $(TOP_BUILD_DIR)
	CONFIG_VNET=$(CONFIG_VNET) WT_MAX_GUESTS=$(WT_MAX_GUESTS) \
	    $(MAKE) -C $(ROOT) build/wolftrust.bin build/secure_cmse_implib.o

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Per-guest ELF rule. The two binaries are byte-different only at link
# time: guest0 lives at FLASH/RAM 0x08020000 / 0x20000000, guest1 at
# 0x08040000 / 0x20008000. _estack lands at top of RAM and guest.c
# selects its role from that value.
define GUEST_LINK
$(BUILD_DIR)/$(1).elf: $(GUEST_SRCS) nonsecure/guest.ld | $(BUILD_DIR)
	$(CC) $(GUEST_CFLAGS) \
	    -Wl,-Tnonsecure/guest.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(2) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_SIZE) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(3) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(WT_GUEST_RAM_SIZE) \
	    -Wl,--gc-sections \
	    -o $$@ $(GUEST_SRCS) $(SECURE_CMSE_IMPLIB) -lgcc
endef

$(eval $(call GUEST_LINK,guest0,$(WT_GUEST0_FLASH_ORIGIN),$(WT_GUEST0_RAM_BASE)))
$(eval $(call GUEST_LINK,guest1,$(WT_GUEST1_FLASH_ORIGIN),$(WT_GUEST1_RAM_BASE)))

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	$(OBJCOPY) -O binary $< $@

run: all
	EMU_TIMEOUT="$(EMU_TIMEOUT)" M33MU="$(M33MU)" \
	    SECURE_BIN="$(SECURE_BIN)" \
	    GUEST0_BIN="$(GUEST0_BIN)" GUEST1_BIN="$(GUEST1_BIN)" \
	    WT_GUEST0_EMU_OFFSET="$(WT_GUEST0_EMU_OFFSET)" \
	    WT_GUEST1_EMU_OFFSET="$(WT_GUEST1_EMU_OFFSET)" \
	    ./run_vnet_test.sh

run-uarts: run

clean:
	rm -rf $(BUILD_DIR)
