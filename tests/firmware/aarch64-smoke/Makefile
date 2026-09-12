# Makefile
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

# EL3 smoke image for tests/target/run_qemu_a_scenario.sh. MACHINE picks the
# load address, the RAM band, and the console the emulated machine exposes.
TOOLPREFIX ?= aarch64-none-elf-
MACHINE ?= virt
BUILD_DIR ?= build/$(MACHINE)

CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy

ifeq ($(MACHINE),virt)
BASE := 0x00000000
RAM := 0x0E000000
UART := 0x09040000
else ifeq ($(MACHINE),versal-virt)
BASE := 0xFFFC0000
RAM := 0xFFFE0000
UART := 0xFF000000
else
$(error unsupported MACHINE=$(MACHINE) (virt or versal-virt))
endif

CFLAGS := -mcpu=generic -mgeneral-regs-only -mstrict-align -ffreestanding \
    -fno-builtin -fno-pic -fno-stack-protector -nostdlib -O2 -g \
    -Wall -Wextra -Werror \
    -DWT_SMOKE_UART=$(UART)u -DWT_SMOKE_MACHINE=\"$(MACHINE)\"
LDFLAGS := -nostartfiles -Wl,--build-id=none -T smoke.ld \
    -Wl,--defsym=WT_SMOKE_BASE=$(BASE) -Wl,--defsym=WT_SMOKE_RAM=$(RAM)

SRCS := smoke.S smoke.c
ELF := $(BUILD_DIR)/smoke.elf
BIN := $(BUILD_DIR)/smoke.bin

.PHONY: all clean

all: $(ELF) $(BIN)

$(BUILD_DIR):
	mkdir -p $@

$(ELF): $(SRCS) smoke.ld | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

$(BIN): $(ELF)
	$(OBJCOPY) -O binary $< $@

clean:
	rm -rf build
