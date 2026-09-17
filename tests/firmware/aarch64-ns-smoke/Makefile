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
# MACHINE picks the NS console; the run address is NS DRAM (WT_NS_BASE): the
# loaded image first, then the RAM the payload copies .data into at every entry.
ROOT ?= ../../..
TOOLPREFIX ?= aarch64-none-elf-
MACHINE ?= virt
WT_NS_BASE ?= 0x40000000
WT_NS_IMG_SIZE ?= 0x60000
WT_NS_RAM_SIZE ?= 0x20000
WT_RUN_CONFORMANCE ?= 0
ifeq ($(WT_RUN_CONFORMANCE),1)
WT_NS_STACK_SIZE ?= 0x10000
endif
WT_NS_STACK_SIZE ?= 0x4000
BUILD_DIR ?= build/$(MACHINE)

CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy

ifeq ($(MACHINE),virt)
UART := 0x09000000
WT_NS_CONFDATA_PA ?= 0x0E2C0000
else ifeq ($(MACHINE),versal-virt)
UART := 0xFF000000
WT_NS_CONFDATA_PA ?= 0x7F2C0000
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
# Round-trip an ITS object through SERVICE_ITS and the VAULT partition behind
# it (the storage proof: the first SP-to-SP message driven from the Normal
# world).
WT_NS_GUEST_STORAGE ?= 0
LDFLAGS := -nostartfiles -Wl,--build-id=none -T ns.ld \
    -Wl,--defsym=WT_NS_BASE=$(WT_NS_BASE) \
    -Wl,--defsym=WT_NS_IMG_SIZE=$(WT_NS_IMG_SIZE) \
    -Wl,--defsym=WT_NS_RAM_SIZE=$(WT_NS_RAM_SIZE) \
    -Wl,--defsym=WT_NS_STACK_SIZE=$(WT_NS_STACK_SIZE)

SRCS := ns.S ns.c
# The PSA, storage and conformance guests link the same OS-neutral PSA client
# every Armv8-M guest does plus the FF-A binding of its WolfTrust_FFM_* entry
# points; the service ids come from the generated manifest header of the
# matching secure build (WT_NS_MANIFEST_INC).
WT_NS_MANIFEST_INC ?=
WOLFHSM_DIR ?= $(ROOT)/lib/wolfHSM
ifneq ($(filter 1,$(WT_NS_GUEST_PSA) $(WT_NS_GUEST_STORAGE) $(WT_RUN_CONFORMANCE)),)
ifneq ($(WT_NS_MANIFEST_INC),)
CFLAGS += -I$(WT_NS_MANIFEST_INC)
endif
SRCS += $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/arch/aarch64/ffa/psa_ffa_transport_arch.c \
    $(ROOT)/src/arch/aarch64/common/libc_min.c
endif
ifeq ($(WT_NS_GUEST_PSA),1)
CFLAGS += -DWT_NS_GUEST_PSA=1 -DWT_NS_GUEST_ID=$(WT_NS_GUEST_ID) \
    -DWOLFHSM_CFG -I. -I$(WOLFHSM_DIR)
SRCS += $(ROOT)/src/client/hsm_psa_transport.c \
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
ifeq ($(WT_NS_GUEST_STORAGE),1)
CFLAGS += -DWT_NS_GUEST_STORAGE=1
SRCS += $(ROOT)/src/client/psa_storage_client.c
endif
# Run the unmodified Arm psa-arch-tests val NSPE from this payload: the FF-M
# IPC suite (confboot, WT_CONF_SUITE=ipc) or the dev_apis storage suite
# (devstorage, WT_CONF_SUITE=storage). val and the scheduled tests come from
# the secure build's fetched upstream tree and generated test lists;
# wolfTrust's psa/*.h stay first on the include path, the NS test list before
# the SPE one.
CONF_OBJS :=
WT_CONF_SUITE ?= ipc
ifeq ($(WT_RUN_CONFORMANCE),1)
WT_NS_CONF_UPSTREAM ?= $(ROOT)/build/upstream/psa-arch-tests/api-tests
ifeq ($(WT_CONF_SUITE),storage)
CONF_LIST_DIR := $(WT_NS_MANIFEST_INC)/storage/ns
CONF_SUITE_DIR := $(WT_NS_CONF_UPSTREAM)/dev_apis/storage
CONF_SUITE_DEFS := -DSTORAGE
CONF_SUITE_SRCS := $(CONF_SUITE_DIR)/common/test_storage_common.c
CONF_SUITE_INCS := -I$(CONF_SUITE_DIR)/common
else
CONF_LIST_DIR := $(WT_NS_MANIFEST_INC)/ns
CONF_SUITE_DIR := $(WT_NS_CONF_UPSTREAM)/ff/ipc
CONF_SUITE_DEFS := -DIPC
CONF_SUITE_SRCS :=
CONF_SUITE_INCS :=
endif
CONF_TESTS := $(shell cat $(CONF_LIST_DIR)/testlist.txt 2>/dev/null)
ifeq ($(CONF_TESTS),)
$(error WT_RUN_CONFORMANCE=1 needs the secure build's generated test list at $(CONF_LIST_DIR)/testlist.txt)
endif
CFLAGS := -I$(CONF_LIST_DIR) $(CFLAGS) \
    -DWT_NS_GUEST_CONF=1 $(CONF_SUITE_DEFS) -DVAL_NSPE_BUILD \
    -DNONSECURE_TEST_BUILD -DVERBOSITY=3 \
    -DWT_SPM_CONFDATA_PA=$(WT_NS_CONFDATA_PA)u \
    -ffunction-sections -fdata-sections \
    -I$(WT_NS_CONF_UPSTREAM)/val/common \
    -I$(WT_NS_CONF_UPSTREAM)/val/nspe \
    -I$(WT_NS_CONF_UPSTREAM)/val/spe \
    -I$(WT_NS_CONF_UPSTREAM)/platform/targets/common/nspe \
    -I$(ROOT)/port/common/aarch64/conformance \
    $(CONF_SUITE_INCS) \
    $(foreach t,$(CONF_TESTS),-I$(CONF_SUITE_DIR)/$(t))
LDFLAGS += -Wl,--gc-sections
SRCS += conformance_pal.c $(ROOT)/src/client/psa_storage_client.c
CONF_CFLAGS := $(filter-out -Werror,$(CFLAGS)) -Wno-unused-function \
    -Wno-unused-variable -Wno-unused-parameter -Wno-type-limits
CONF_SRCS := $(WT_NS_CONF_UPSTREAM)/val/common/val_log.c \
    $(addprefix $(WT_NS_CONF_UPSTREAM)/val/nspe/,val_entry.c val_dispatcher.c \
        val_framework.c val_interfaces.c val_peripherals.c val_platform.c \
        val_crypto.c val_storage.c val_attestation.c) \
    $(CONF_SUITE_SRCS) \
    $(foreach t,$(CONF_TESTS),$(CONF_SUITE_DIR)/$(t)/$(t).c \
        $(CONF_SUITE_DIR)/$(t)/test_entry_$(t:test_%=%).c)
CONF_OBJS := $(addprefix $(BUILD_DIR)/conf/,$(notdir $(CONF_SRCS:.c=.o)))
vpath %.c $(sort $(dir $(CONF_SRCS)))
endif
ELF := $(BUILD_DIR)/ns.elf
BIN := $(BUILD_DIR)/ns.bin

.PHONY: all clean

all: $(ELF) $(BIN)

$(BUILD_DIR) $(BUILD_DIR)/conf:
	mkdir -p $@

$(BUILD_DIR)/conf/%.o: %.c | $(BUILD_DIR)/conf
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(ELF): $(SRCS) $(CONF_OBJS) ns.ld | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(CONF_OBJS)

$(BIN): $(ELF)
	$(OBJCOPY) -O binary $< $@

clean:
	rm -rf build
