.DEFAULT_GOAL := all

# stm32h563-tpm end-to-end firmware-TPM test.
#
# A bare-metal wolfTPM client calls fwTPM inside the existing Secure partition.
# FreeRTOS and Zephyr clients exercise the same service and engine choices.
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
NM         := $(TOOLPREFIX)nm
M33MU      ?= m33mu

ROOT        := ../../..
PORT_DIR    := $(ROOT)/port/stm32h563
WOLFSSL_DIR := $(ROOT)/lib/wolfSSL
WOLFTPM_DIR := $(ROOT)/lib/wolfTPM

CONFIG_TPM ?= y
WT_ENGINE ?= $(if $(filter 1,$(WT_ENGINE_HSM)),hsm,native)
ifneq ($(WT_ENGINE_HSM),)
ifeq ($(filter 0 1,$(WT_ENGINE_HSM)),)
$(error unsupported WT_ENGINE_HSM=$(WT_ENGINE_HSM))
endif
ifneq ($(WT_ENGINE),$(if $(filter 1,$(WT_ENGINE_HSM)),hsm,native))
$(error conflicting WT_ENGINE and WT_ENGINE_HSM selectors)
endif
endif
ifneq ($(filter $(WT_ENGINE),native hsm),$(WT_ENGINE))
$(error unsupported WT_ENGINE=$(WT_ENGINE))
endif
EMU_TIMEOUT ?= 180
WT_MAX_GUESTS ?= 1
WT_CRYPTO_PROFILE ?= default
WT_PKCS11_SUITE ?= $(if $(filter default,$(WT_CRYPTO_PROFILE)),profile,all)

# The application window matches manifest-tpm.json; runners may override it.
WT_GUEST0_FLASH_ORIGIN ?= 0x080A0000
WT_GUEST_FLASH_SIZE    ?= 0x00020000
WT_GUEST0_RAM_BASE     ?= 0x20000000
WT_GUEST_RAM_SIZE      ?= 0x00010000
WT_GUEST0_EMU_OFFSET   ?= 0xA0000

WT_GUEST_CORE_CLOCK_HZ ?= 240000000
WT_GUEST_UART_CLOCK_HZ ?= 120000000

CPU_FLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only

GUEST_CFLAGS := $(CPU_FLAGS) -ffreestanding -fno-builtin -nostdlib -Os -g \
    -Wall -Wextra -Wno-unused-function -Wno-unused-variable \
    -Wno-unused-parameter -Wno-type-limits -mno-unaligned-access \
    -ffunction-sections -fdata-sections \
    -Inonsecure \
    -Itpm-app \
    -I$(ROOT)/include \
    -I$(PORT_DIR) \
    -I$(WOLFSSL_DIR) \
    -I$(WOLFTPM_DIR) \
    -DWOLFSSL_USER_SETTINGS -DWOLFTPM_USER_SETTINGS \
    -include nonsecure/user_settings.h \
    -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM -DWOLFSSL_ARM_ARCH=8 \
    -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_ARMASM_INLINE \
    -DWOLFSSL_ARMASM_NO_NEON -DWOLFSSL_ARMASM_THUMB2 \
    -DNO_ERROR_STRINGS -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT \
    -DWC_RESEED_INTERVAL=1000000 \
    -DWOLFTPM_SMALL_STACK \
    -DWT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ) \
    -DWT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ) \
    -DWT_GUEST0_FLASH_BASE=$(WT_GUEST0_FLASH_ORIGIN)u
WT_LTO ?= 1
ifeq ($(WT_LTO),1)
GUEST_CFLAGS += -flto=auto
else ifneq ($(WT_LTO),0)
$(error unsupported WT_LTO=$(WT_LTO))
endif
GUEST_KEEP_FLAGS := -Wl,-u,memcpy,-u,memset,-u,memmove,-u,memcmp
GUEST_CFLAGS += $(GUEST_EXTRA_CFLAGS)

# guest0: the bare-metal wolfTPM client routed through SERVICE_TPM by building
# with WOLFTPM_SWTPM and supplying TPM2_SWTPM_SendCommand.
APP_CFLAGS := -DWT_WOLFHSM_CLIENT_ID=1 -DWT_TPM_ROLE_APP -DWOLFTPM_SWTPM -DGUEST_HEAP_POOL_SZ=32768u \
    -DWOLF_CRYPTO_CB -DWOLFTPM_CRYPTOCB \
    -DWT_TPM_APP_NAME=\"tpm-guest0\"

TPM_BUILD_ROOT ?= build
BUILD_DIR     ?= $(TPM_BUILD_ROOT)/tpm
PKCS11_BUILD_DIR ?= $(TPM_BUILD_ROOT)/pkcs11-$(WT_PKCS11_SUITE)
TPM_FREERTOS_BUILD_DIR ?= $(TPM_BUILD_ROOT)/tpm-freertos
TOP_BUILD_DIR := $(ROOT)/build
SECURE_BIN    := $(TOP_BUILD_DIR)/wolftrust.bin
SECURE_CMSE_IMPLIB := $(TOP_BUILD_DIR)/secure_cmse_implib.o

WOLFCRYPT_SRCS := \
    $(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/cryptocb.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/random.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/error.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_cortexm.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha512.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/kdf.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/pwdbased.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c

COMMON_SRCS := \
    nonsecure/guest.c \
    nonsecure/guest_libc.c \
    $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/client/crypto_native_client.c \
    $(ROOT)/src/client/tpm_psa_transport.c \
    $(WOLFCRYPT_SRCS)

APP_SRCS := \
    tpm-app/tpm_tests.c \
    $(WOLFTPM_DIR)/src/tpm2.c \
    $(WOLFTPM_DIR)/src/tpm2_util.c \
    $(WOLFTPM_DIR)/src/tpm2_packet.c \
    $(WOLFTPM_DIR)/src/tpm2_wrap.c \
    $(WOLFTPM_DIR)/src/tpm2_asn.c \
    $(WOLFTPM_DIR)/src/tpm2_crypto.c \
    $(WOLFTPM_DIR)/src/tpm2_param_enc.c \
    $(WOLFTPM_DIR)/src/tpm2_cryptocb.c

ifeq ($(WT_ENGINE),hsm)
GUEST_CFLAGS += -DWT_ENGINE_HSM=1 -DWOLF_CRYPTO_CB -DWOLFHSM_CFG \
    -I$(ROOT)/lib/wolfHSM -I$(BUILD_DIR)
COMMON_SRCS := $(filter-out %/crypto_native_client.c,$(COMMON_SRCS))
COMMON_SRCS += \
    $(ROOT)/src/client/hsm_psa_transport.c \
    $(ROOT)/tests/firmware/zephyr-stm32h5/module/wolfhsm-client/src/wolfhsm_client_glue.c
COMMON_SRCS += $(addprefix $(ROOT)/lib/wolfHSM/src/, \
    wh_client.c wh_client_crypto.c wh_client_cryptocb.c wh_comm.c \
    wh_crypto.c wh_keyid.c wh_message_comm.c wh_message_crypto.c \
    wh_message_keystore.c wh_message_nvm.c wh_message_customcb.c \
    wh_message_counter.c wh_utils.c)
GUEST_ENGINE_DEPS := $(BUILD_DIR)/wolfhsm_cfg.h
else
GUEST_CFLAGS += -DWT_ENGINE_NATIVE=1
endif

include $(ROOT)/mk/crypto-profile.mk
GUEST_CFLAGS += $(WT_CRYPTO_PROFILE_FLAGS)

G0_OBJS := $(patsubst %.c,$(BUILD_DIR)/g0_%.o,$(notdir $(COMMON_SRCS) $(APP_SRCS)))

vpath %.c $(sort $(dir $(COMMON_SRCS) $(APP_SRCS)))

GUEST0_ELF := $(BUILD_DIR)/guest0.elf
GUEST0_BIN := $(BUILD_DIR)/guest0.bin

.PHONY: all secure clean run tpm tpm-freertos-app \
        pkcs11 pkcs11-guests pkcs11-freertos-app \
        run-tpm run-pkcs11

tpm:
	@$(MAKE) --no-print-directory all

pkcs11:
	@$(MAKE) --no-print-directory secure CONFIG_TPM=n CONFIG_PKCS11=y \
		WT_ENGINE=$(WT_ENGINE)
	@$(MAKE) --no-print-directory pkcs11-guests

pkcs11-guests: pkcs11-freertos-app

pkcs11-freertos-app:
	@$(MAKE) --no-print-directory -C ../zephyr-stm32h5 freertos-workspace
	@BUILD_DIR="$(abspath $(PKCS11_BUILD_DIR))" \
		SECURE_CMSE_IMPLIB="$(abspath $(SECURE_CMSE_IMPLIB))" \
		WT_PKCS11_SUITE="$(WT_PKCS11_SUITE)" \
		WT_GUEST0_FLASH_BASE="$(WT_GUEST0_FLASH_ORIGIN)" \
		WT_GUEST0_FLASH_SIZE=0x00020000 \
		WT_GUEST0_RAM_BASE="$(WT_GUEST0_RAM_BASE)" \
		WT_GUEST_RAM_SIZE="$(WT_GUEST_RAM_SIZE)" \
		sh ./scripts/build_freertos_pkcs11.sh

tpm-freertos-app:
	@$(MAKE) --no-print-directory -C ../zephyr-stm32h5 freertos-workspace
	@BUILD_DIR="$(abspath $(TPM_FREERTOS_BUILD_DIR))" \
		SECURE_CMSE_IMPLIB="$(abspath $(SECURE_CMSE_IMPLIB))" \
		WT_GUEST0_FLASH_BASE="$(WT_GUEST0_FLASH_ORIGIN)" \
		WT_GUEST0_FLASH_SIZE="$(WT_GUEST_FLASH_SIZE)" \
		WT_GUEST0_RAM_BASE="$(WT_GUEST0_RAM_BASE)" \
		WT_GUEST_RAM_SIZE="$(WT_GUEST_RAM_SIZE)" \
		sh ./scripts/build_freertos_tpm.sh

all: secure $(GUEST0_BIN)
	@$(SIZE) $(GUEST0_ELF)

secure:
	rm -rf $(TOP_BUILD_DIR)
	CONFIG_TPM=$(CONFIG_TPM) WT_MAX_GUESTS=$(WT_MAX_GUESTS) \
	    WT_GUEST0_FLASH_BASE=$(WT_GUEST0_FLASH_ORIGIN) \
	    $(MAKE) -C $(ROOT) build/wolftrust.bin build/secure_cmse_implib.o

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/wolfhsm_cfg.h: | $(BUILD_DIR)
	@printf '#include "%s"\n' '$(abspath $(ROOT)/tests/firmware/stm32h563/nonsecure/wh_settings_guest.h)' > $@

$(BUILD_DIR)/g0_%.o: %.c $(WT_CRYPTO_PROFILE_HEADER) nonsecure/user_settings.h $(GUEST_ENGINE_DEPS) | $(BUILD_DIR)
	$(CC) $(GUEST_CFLAGS) $(APP_CFLAGS) -c -o $@ $<

$(GUEST0_ELF): GUEST_KEEP_FLAGS += -Wl,-u,wt_tpm_psa_transact,-u,TPM2_SWTPM_SendCommand

define GUEST_LINK
$(BUILD_DIR)/$(1).elf: $(2) nonsecure/guest.ld $(SECURE_CMSE_IMPLIB) | $(BUILD_DIR)
	$(CC) $(GUEST_CFLAGS) $$(GUEST_KEEP_FLAGS) \
	    -Wl,-Tnonsecure/guest.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(3) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_SIZE) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(4) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(WT_GUEST_RAM_SIZE) \
	    -Wl,--gc-sections \
	    -o $$@ $(2) $(SECURE_CMSE_IMPLIB) -lgcc
	$(SIZE) $$@
endef

$(eval $(call GUEST_LINK,guest0,$(G0_OBJS),$(WT_GUEST0_FLASH_ORIGIN),$(WT_GUEST0_RAM_BASE)))

# Every Secure crossing is SPM-mediated: no retired direct veneers, the
# application rides SERVICE_TPM and contains no fwTPM implementation.
$(GUEST0_BIN): $(GUEST0_ELF)
	@! $(NM) --defined-only $< | grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_' || \
	    { echo "FAIL: retired direct veneers linked into $<" >&2; exit 1; }
	@$(NM) --defined-only $< | grep -q 'wt_tpm_psa_transact' || \
	    { echo "FAIL: $< is not wired to the SERVICE_TPM transport" >&2; exit 1; }
	@$(NM) --defined-only $< | grep -q 'TPM2_SWTPM_SendCommand' || \
	    { echo "FAIL: wolfTPM client not routed through SERVICE_TPM in $<" >&2; exit 1; }
	$(OBJCOPY) -O binary $< $@

run run-tpm:
	@cd $(ROOT) && WT_ENGINE=$(WT_ENGINE) WT_CRYPTO_PROFILE=$(WT_CRYPTO_PROFILE) \
		M33MU=$(M33MU) bash tests/target/run_suite.sh m33mu tpm

run-pkcs11:
	@cd $(ROOT) && WT_ENGINE=$(WT_ENGINE) WT_CRYPTO_PROFILE=$(WT_CRYPTO_PROFILE) \
		M33MU=$(M33MU) bash tests/target/run_suite.sh m33mu pkcs11

clean:
	rm -rf $(TPM_BUILD_ROOT)
