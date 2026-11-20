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

ifeq ($(filter tpm pkcs11,$(WT_INTERFACE)),)
$(error WT_INTERFACE must be tpm or pkcs11)
endif
ifeq ($(filter native hsm,$(WT_ENGINE)),)
$(error WT_ENGINE must be native or hsm)
endif
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
WOLFSSL_DIR := $(ROOT)/lib/wolfSSL
WOLFTPM_DIR := $(ROOT)/lib/wolfTPM
WOLFPKCS11_DIR := $(ROOT)/lib/wolfPKCS11

WT_M33MU_EXPECT_BKPT ?= 0
# The default profile trims the token, so only the profile suite fits it.
WT_PKCS11_FULL_SUITE ?= all
WT_PKCS11_SUITE ?= $(if $(filter default,$(WT_INTERFACE_PROFILE)),profile,$(WT_PKCS11_FULL_SUITE))

CFLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only \
    -ffreestanding -fno-builtin -nostdlib -Os -g \
    -Wall -Wextra -Wno-unused-function -Wno-unused-variable \
    -Wno-unused-parameter -Wno-type-limits \
    -ffunction-sections -fdata-sections -mno-unaligned-access \
    -I. -I$(ROOT)/tests/firmware/boards/$(TARGET) -I$(ROOT)/include \
    -I$(WOLFSSL_DIR) -DWOLFSSL_USER_SETTINGS \
    -include user_settings.h $(WT_INTERFACE_PROFILE_FLAGS)
ifeq ($(WT_M33MU_EXPECT_BKPT),1)
CFLAGS += -DWT_M33MU_EXPECT_BKPT
endif
WT_TPM_DA ?= 1
CFLAGS += -DWT_TPM_DA=$(WT_TPM_DA)

SRCS := main.c ../psa-guest/guest_libc.c $(ROOT)/src/client/psa_ffm_client.c

ifeq ($(WT_INTERFACE),tpm)
APP_NAME := tpm-guest0
CFLAGS += -I$(WOLFTPM_DIR) -DWOLFTPM_USER_SETTINGS -DWT_TPM_ROLE_APP \
    -DWOLFTPM_SWTPM -DWOLF_CRYPTO_CB -DWOLFTPM_CRYPTOCB -DWOLFTPM_SMALL_STACK \
    -DWT_INTERFACE_TPM -DWT_TPM_APP_NAME=\"$(APP_NAME)\" \
    -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM -DWOLFSSL_ARM_ARCH=8 \
    -DNO_ERROR_STRINGS -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT \
    -DWC_RESEED_INTERVAL=1000000 -DWT_WOLFHSM_CLIENT_ID=1u
CFLAGS += -DWT_MSG_RELAY_ONESHOT=1
SRCS += tpm_tests.c $(ROOT)/src/client/tpm_psa_transport.c \
    $(ROOT)/src/client/msg_client.c \
    $(addprefix $(WOLFTPM_DIR)/src/, tpm2.c tpm2_util.c tpm2_packet.c \
        tpm2_wrap.c tpm2_asn.c tpm2_crypto.c tpm2_param_enc.c tpm2_cryptocb.c) \
    $(addprefix $(WOLFSSL_DIR)/wolfcrypt/src/, aes.c cryptocb.c ecc.c \
        random.c sha256.c asn.c coding.c error.c hash.c hmac.c memory.c sha.c \
        sp_cortexm.c sp_int.c wolfmath.c wc_port.c sha512.c kdf.c pwdbased.c)
KEEP := -Wl,-u,wt_tpm_psa_transact,-u,TPM2_SWTPM_SendCommand
WIRED := wt_tpm_psa_transact TPM2_SWTPM_SendCommand wt_tpm_psa_random
ABSENT := 'fwTPM|FWTPM_|WP11_|wh_Client|wt_crypto_native'
else
APP_NAME := pkcs11-guest0
SUITE_DEF := $(strip \
    $(if $(filter profile,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_PROFILE) \
    $(if $(filter core,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_CORE) \
    $(if $(filter objects,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_OBJECTS) \
    $(if $(filter crypto,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_CRYPTO) \
    $(if $(filter negative,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_NEGATIVE) \
    $(if $(filter all,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_ALL))
ifeq ($(SUITE_DEF),)
$(error WT_PKCS11_SUITE must be profile, core, objects, crypto, negative, or all)
endif
CFLAGS += -I$(WOLFPKCS11_DIR) -DWOLFPKCS11_USER_SETTINGS -DWOLFPKCS11_NO_ENV \
    -DWT_INTERFACE_PKCS11 -D$(SUITE_DEF)=1 -DWT_PKCS11_APP_NAME=\"$(APP_NAME)\"
CFLAGS += -DWT_MSG_RELAY_CHUNKED=1
SRCS += pkcs11_tests.c $(ROOT)/src/client/pkcs11_proxy.c $(ROOT)/src/client/msg_client.c \
    $(ROOT)/src/pkcs11/pkcs11_wire.c $(ROOT)/src/client/pkcs11_psa_transport.c
KEEP := -Wl,-u,C_GetFunctionList,-u,wt_pkcs11_psa_call
WIRED := C_GetFunctionList wt_pkcs11_psa_call
ABSENT := 'WP11_|wolfTPM|TPM2_|wc_'
endif
CFLAGS += -DGUEST_APP_NAME=\"$(APP_NAME)\"

OBJS := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(SRCS)))
vpath %.c $(sort $(dir $(SRCS)))

all: $(BUILD)/guest0.bin

$(SECURE_CMSE_IMPLIB): FORCE
	$(MAKE) -C $(ROOT) ARCH=$(ARCH) TARGET=$(TARGET) TOOLPREFIX=$(TOOLPREFIX) \
	    WT_ENGINE=$(WT_ENGINE) CONFIG_TPM=$(CONFIG_TPM) CONFIG_PKCS11=$(CONFIG_PKCS11) \
	    WT_TPM_DA=$(WT_TPM_DA) \
	    build/secure_cmse_implib.o

$(BUILD)/%.o: %.c $(WT_INTERFACE_PROFILE_HEADER) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/guest0.elf: $(OBJS) $(SECURE_CMSE_IMPLIB) ../psa-guest/guest.ld
	$(CC) $(CFLAGS) $(KEEP) -Wl,-T../psa-guest/guest.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(GUEST0_FLASH_ORIGIN) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(GUEST0_FLASH_LENGTH) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(GUEST0_RAM_ORIGIN) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(GUEST0_RAM_LENGTH) \
	    -Wl,--gc-sections -o $@ $(OBJS) $(SECURE_CMSE_IMPLIB) -lgcc
	$(SIZE) $@

# The application reaches its provider only through the SPM-mediated service.
$(BUILD)/guest0.bin: $(BUILD)/guest0.elf
	@for sym in $(WIRED); do \
	    $(NM) --defined-only $< | grep -q " $$sym$$" || \
	    { echo "FAIL: $< lacks $$sym" >&2; exit 1; }; done
	@if $(NM) --defined-only $< | grep -Eq $(ABSENT); then \
	    echo "FAIL: provider code linked into $<" >&2; exit 1; fi
	@if $(NM) --defined-only $< | grep -Eq ' psa_(crypto_init|generate_|hash_|cipher_|aead_|mac_|sign_|verify_)'; then \
	    echo "FAIL: PSA Crypto linked into the $(WT_INTERFACE) application" >&2; exit 1; fi
	@if $(NM) --defined-only $< | grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then \
	    echo "FAIL: retired direct veneers linked into $<" >&2; exit 1; fi
	$(OBJCOPY) -O binary $< $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean FORCE
FORCE:
