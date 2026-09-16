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

# Normal-world payload for tests/target/run_qemu_a_scenario.sh (ns-smoke).
# MACHINE picks the NS console; the run address is NS DRAM (WT_NS_BASE).
ROOT ?= ../../..
TOOLPREFIX ?= aarch64-none-elf-
MACHINE ?= virt
WT_NS_BASE ?= 0x40000000
BUILD_DIR ?= build/$(MACHINE)

CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy

ifeq ($(MACHINE),virt)
UART := 0x09000000
else ifeq ($(MACHINE),versal-virt)
UART := 0xFF000000
else
$(error unsupported MACHINE=$(MACHINE) (virt or versal-virt))
endif

# Send a direct request to the Secure echo partition (ffa-guest-direct proof).
WT_NS_GUEST_ECHO ?= 0
CFLAGS := -mcpu=generic -mgeneral-regs-only -mstrict-align -ffreestanding \
    -fno-builtin -fno-pic -fno-stack-protector -nostdlib -O2 -g \
    -Wall -Wextra -Werror -I$(ROOT)/include -DWT_NS_UART=$(UART)u
ifeq ($(WT_NS_GUEST_ECHO),1)
CFLAGS += -DWT_NS_GUEST_ECHO=1
endif
# Power off through PSCI at the end of the run (the psci proof).
WT_NS_GUEST_PSCI ?= 0
ifeq ($(WT_NS_GUEST_PSCI),1)
CFLAGS += -DWT_NS_GUEST_PSCI=1
endif
# Spin long enough to be preempted by a Secure tick (the ffa-preempt proof).
WT_NS_PREEMPT ?= 0
ifeq ($(WT_NS_PREEMPT),1)
CFLAGS += -DWT_NS_PREEMPT=1
endif
# Reach the Secure services over the PSA FF-A transport (the positive/guest1
# proofs); WT_NS_GUEST_ID stamps the guest marker.
WT_NS_GUEST_PSA ?= 0
WT_NS_GUEST_ID ?= 0
LDFLAGS := -nostartfiles -Wl,--build-id=none -T ns.ld \
    -Wl,--defsym=WT_NS_BASE=$(WT_NS_BASE)

SRCS := ns.S ns.c
ifeq ($(WT_NS_GUEST_PSA),1)
CFLAGS += -DWT_NS_GUEST_PSA=1 -DWT_NS_GUEST_ID=$(WT_NS_GUEST_ID)
SRCS += $(ROOT)/src/client/psa_ffa_transport.c \
    $(ROOT)/src/arch/aarch64/ffa/psa_ffa_transport_arch.c
endif
ELF := $(BUILD_DIR)/ns.elf
BIN := $(BUILD_DIR)/ns.bin

.PHONY: all clean

all: $(ELF) $(BIN)

$(BUILD_DIR):
	mkdir -p $@

$(ELF): $(SRCS) ns.ld | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

$(BIN): $(ELF)
	$(OBJCOPY) -O binary $< $@

clean:
	rm -rf build
