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
# Sweep unimplemented function ids and confirm each is refused (the smcfuzz proof).
WT_NS_GUEST_FUZZ ?= 0
ifeq ($(WT_NS_GUEST_FUZZ),1)
CFLAGS += -DWT_NS_GUEST_FUZZ=1
endif
# Attempt to read Secure RAM from the Normal world (the secramneg proof).
WT_NS_GUEST_SECRAM ?= 0
WT_NS_SECURE_PROBE_PA ?= 0x0E300000
ifeq ($(WT_NS_GUEST_SECRAM),1)
CFLAGS += -DWT_NS_GUEST_SECRAM=1 -DWT_NS_SECURE_PROBE_PA=$(WT_NS_SECURE_PROBE_PA)u
endif
# Request a PSCI system reset that re-enters the boot chain (the resetneg proof).
WT_NS_GUEST_RESET ?= 0
ifeq ($(WT_NS_GUEST_RESET),1)
CFLAGS += -DWT_NS_GUEST_RESET=1
endif
# Offer malformed FFA_MEM_SHARE descriptors, each refused (the ffa-memneg proof).
WT_NS_GUEST_MEMNEG ?= 0
LDFLAGS := -nostartfiles -Wl,--build-id=none -T ns.ld \
    -Wl,--defsym=WT_NS_BASE=$(WT_NS_BASE)

SRCS := ns.S ns.c
# The PSA guest links the same OS-neutral PSA client and wolfHSM client
# transport every Armv8-M guest does plus the FF-A binding of its
# WolfTrust_FFM_* entry points; the service ids come from the generated
# manifest header of the matching secure build (WT_NS_MANIFEST_INC).
WT_NS_MANIFEST_INC ?=
WOLFHSM_DIR ?= $(ROOT)/lib/wolfHSM
ifeq ($(WT_NS_GUEST_PSA),1)
CFLAGS += -DWT_NS_GUEST_PSA=1 -DWT_NS_GUEST_ID=$(WT_NS_GUEST_ID) \
    -DWOLFHSM_CFG -I. -I$(WOLFHSM_DIR)
ifneq ($(WT_NS_MANIFEST_INC),)
CFLAGS += -I$(WT_NS_MANIFEST_INC)
endif
SRCS += $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/client/hsm_psa_transport.c \
    $(ROOT)/src/arch/aarch64/ffa/psa_ffa_transport_arch.c \
    $(ROOT)/src/arch/aarch64/common/libc_min.c \
    $(WOLFHSM_DIR)/src/wh_client.c \
    $(WOLFHSM_DIR)/src/wh_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_keystore.c \
    $(WOLFHSM_DIR)/src/wh_message_counter.c \
    $(WOLFHSM_DIR)/src/wh_message_customcb.c \
    $(WOLFHSM_DIR)/src/wh_message_nvm.c \
    $(WOLFHSM_DIR)/src/wh_utils.c
endif
ifeq ($(WT_NS_GUEST_MEMNEG),1)
CFLAGS += -DWT_NS_GUEST_MEMNEG=1
SRCS += $(ROOT)/src/arch/aarch64/ffa/ffa_mem.c
endif
# Round-trip an ITS object through SERVICE_ITS and the VAULT partition behind
# it (the storage proof: the first SP-to-SP message driven from the Normal
# world). Shares the PSA client and FF-A binding with the PSA guest.
WT_NS_GUEST_STORAGE ?= 0
ifeq ($(WT_NS_GUEST_STORAGE),1)
CFLAGS += -DWT_NS_GUEST_STORAGE=1
ifneq ($(WT_NS_MANIFEST_INC),)
CFLAGS += -I$(WT_NS_MANIFEST_INC)
endif
SRCS += $(ROOT)/src/client/psa_storage_client.c
ifneq ($(WT_NS_GUEST_PSA),1)
SRCS += $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/arch/aarch64/ffa/psa_ffa_transport_arch.c \
    $(ROOT)/src/arch/aarch64/common/libc_min.c
endif
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
