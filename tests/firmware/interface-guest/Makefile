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
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# Bare-metal TPM 2.0 or PKCS#11 application for guest0 on any port:
#   make TARGET=<port> WT_INTERFACE=tpm|pkcs11 [WT_ENGINE=native|hsm]

.DEFAULT_GOAL := all
TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size
NM := $(TOOLPREFIX)nm

ROOT := ../../..
TARGET ?= mimxrt700
ARCH ?= armv8m
WT_ENGINE ?= native
WT_INTERFACE ?= $(if $(filter y,$(CONFIG_PKCS11)),pkcs11,tpm)
BUILD ?= build
BUILD_DIR := $(BUILD)

# The layout, profile and Secure image follow the selected interface.
WT_IF_WANT := $(if $(filter tpm,$(WT_INTERFACE)),y/n,n/y)
CONFIG_TPM ?= $(firstword $(subst /, ,$(WT_IF_WANT)))
CONFIG_PKCS11 ?= $(lastword $(subst /, ,$(WT_IF_WANT)))
ifneq ($(CONFIG_TPM)/$(CONFIG_PKCS11),$(WT_IF_WANT))
$(error WT_INTERFACE=$(WT_INTERFACE) conflicts with CONFIG_TPM=$(CONFIG_TPM) CONFIG_PKCS11=$(CONFIG_PKCS11))
endif

include $(ROOT)/mk/target-$(TARGET).mk
include $(ROOT)/mk/layout.mk
$(foreach kv,$(WT_LAYOUT_GUEST_WINDOWS),$(eval $(kv)))
include $(ROOT)/mk/crypto-profile.mk

SECURE_CMSE_IMPLIB := $(ROOT)/build/secure_cmse_implib.o

WT_M33MU_EXPECT_BKPT ?= 0
IF_GUEST_DIR := .
IF_PRE_INCLUDE := -include user_settings.h
IF_SP_MATH := sp_cortexm.c
IF_SP_MATH_CFLAGS := -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM -DWOLFSSL_ARM_ARCH=8
IF_WH_CFG_DIR := $(BUILD)/wh_include
include interface.mk

CFLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only \
    -ffreestanding -fno-builtin -nostdlib -Os -g \
    -Wall -Wextra -ffunction-sections -fdata-sections -mno-unaligned-access \
    -I$(ROOT)/tests/firmware/boards/$(TARGET) $(IF_CFLAGS)
ifeq ($(WT_M33MU_EXPECT_BKPT),1)
CFLAGS += -DWT_M33MU_EXPECT_BKPT
endif

SRCS := main.c ../psa-guest/guest_libc.c $(ROOT)/src/client/psa_ffm_client.c \
    $(IF_SRCS)
APP_NAME := $(IF_APP_NAME)
CFLAGS += -DGUEST_APP_NAME=\"$(APP_NAME)\"

OBJS := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(SRCS)))
vpath %.c $(sort $(dir $(SRCS)))

all: $(BUILD)/guest0.bin

$(SECURE_CMSE_IMPLIB): FORCE
	$(MAKE) -C $(ROOT) ARCH=$(ARCH) TARGET=$(TARGET) TOOLPREFIX=$(TOOLPREFIX) \
	    WT_ENGINE=$(WT_ENGINE) CONFIG_TPM=$(CONFIG_TPM) CONFIG_PKCS11=$(CONFIG_PKCS11) \
	    WT_TPM_DA=$(WT_TPM_DA) \
	    build/secure_cmse_implib.o

$(BUILD)/%.o: %.c $(IF_WH_CFG_DIR)/wolfhsm_cfg.h $(WT_INTERFACE_PROFILE_HEADER) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/guest0.elf: $(OBJS) $(SECURE_CMSE_IMPLIB) ../psa-guest/guest.ld
	$(CC) $(CFLAGS) $(IF_KEEP) -Wl,-T../psa-guest/guest.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(GUEST0_FLASH_ORIGIN) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(GUEST0_FLASH_LENGTH) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(GUEST0_RAM_ORIGIN) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(GUEST0_RAM_LENGTH) \
	    -Wl,--gc-sections -o $@ $(OBJS) $(SECURE_CMSE_IMPLIB) -lgcc
	$(SIZE) $@

$(BUILD)/guest0.bin: $(BUILD)/guest0.elf
	$(call wt_interface_link_check,$<)
	@if $(NM) --defined-only $< | grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then \
	    echo "FAIL: retired direct veneers linked into $<" >&2; exit 1; fi
	$(OBJCOPY) -O binary $< $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean FORCE
FORCE:
