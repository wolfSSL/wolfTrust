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

ROOT    := ../../..
WOLFHSM := $(ROOT)/lib/wolfHSM
WOLFSSL := $(ROOT)/lib/wolfSSL
WOLFPSA := $(ROOT)/lib/wolfPSA

CC ?= cc
BUILD_DIR ?= build
# run builds and runs every WT_SECURE_PSA_PROFILE, small on GCM and tiny with
# no ECC in wolfCrypt; run-one takes PROFILE, AEAD (WT_AEAD) and NO_ECC.
PROFILE ?= default
AEAD ?=
NO_ECC ?=
PROFILES := extended default small tiny
# A pass whose EXTRA_CFLAGS already picks the AEAD skips the small-gcm run
RUNS := $(PROFILES) tiny-noecc $(if $(findstring WT_AEAD_,$(EXTRA_CFLAGS)),,small-gcm)
NO_ECC_CFLAGS := $(if $(NO_ECC),-DWT_NO_ECC=1 -DWT_VAULT_ECC=0 -DWT_KEYVAULT_P256=0)
AEAD_CFLAGS := $(if $(filter gcm,$(AEAD)),-DWT_AEAD_GCM)$(if $(filter ccm,$(AEAD)),-DWT_AEAD_CCM)
# small and tiny offer one PSA AEAD, CCM unless GCM is asked for
ONE_AEAD_GCM := $(or $(filter gcm,$(AEAD)),$(findstring WT_AEAD_GCM,$(EXTRA_CFLAGS)))
WANT_WITHOUT := $(if $(filter small tiny,$(PROFILE)),$(if $(ONE_AEAD_GCM),,--without PSA_WANT_ALG_GCM)) \
    $(if $(filter-out extended,$(PROFILE)),--without PSA_WANT_ALG_SP800_108_COUNTER_HMAC \
    --without PSA_WANT_ALG_SP800_108_COUNTER_CMAC \
    --without PSA_WANT_ALG_CCM_STAR_NO_TAG)

WARN := -std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter

# The service side: wolfPSA, wolfCrypt and the keyvault over a ramsim NVM,
# built as the crypto partition builds them.
SRV_CFLAGS := \
    -DWOLFSSL_USER_SETTINGS -UHAVE_CONFIG_H \
    -DWOLFHSM_CFG_NO_CRYPTO -DWOLFHSM_CFG_NO_SYS_TIME \
    -DWT_SECURE_PSA=1 -DWT_SECURE_PSA_$(PROFILE)=1 -DWT_MAX_GUESTS=2 -DWT_PSA_GEN_MAX=64U \
    -DWOLFSSL_PSA_ENGINE -DWOLFPSA_CUSTOM_STORE -DWOLFPSA_NO_TRACE -DWOLFPSA_AEAD_BORROW \
    -DWOLFPSA_AEAD_STREAM_AAD \
    -I. -I$(ROOT)/include -I$(WOLFHSM) -I$(WOLFSSL) -I$(WOLFPSA) \
    -I$(WOLFPSA)/wolfpsa -I$(BUILD_DIR)/wolfpsa_cfg $(AEAD_CFLAGS) \
    $(NO_ECC_CFLAGS) $(EXTRA_CFLAGS)
LIB_CFLAGS := $(SRV_CFLAGS) -O0 -g -w

# The Non-secure side: the client library only, no crypto.
CLI_CFLAGS := -I. -I$(ROOT)/include -I$(WOLFPSA)/wolfpsa -I$(BUILD_DIR)/wolfpsa_cfg $(WARN) \
    -DWT_SECURE_PSA_$(PROFILE)=1 $(AEAD_CFLAGS) \
    $(EXTRA_CFLAGS)

_SRV_WT := \
    $(ROOT)/src/services/native/psa_crypto_service.c \
    $(ROOT)/src/services/native/native_wire.c \
    $(ROOT)/src/services/native/keyvault.c \
    $(ROOT)/src/services/wolfhsm/wt_hsm_aead.c \
    $(ROOT)/src/services/wolfhsm/wt_hsm_vault.c

_SRV_WH := wh_nvm wh_nvm_flash wh_flash_ramsim wh_flash_unit wh_utils
_SRV_WC := aes coding ecc sp_int wolfmath sha256 random memory error logging \
    hash wc_port misc hmac kdf pwdbased sp_c32 sp_c64
ifneq ($(NO_ECC),)
_SRV_WC := $(filter-out ecc sp_int wolfmath sp_c32 sp_c64,$(_SRV_WC))
endif
_SRV_WP := $(notdir $(basename $(filter-out %/psa_store_posix.c \
    %/psa_store_zephyr.c %/psa_attestation.c %/psa_ffm.c %/psa_its.c \
    %/misc_impl.c %/psa_tf_psa.c,$(wildcard $(WOLFPSA)/src/*.c))))

SRV_OBJS := $(addprefix $(BUILD_DIR)/srv_,$(notdir $(_SRV_WT:.c=.o))) \
    $(addprefix $(BUILD_DIR)/wh_,$(addsuffix .o,$(_SRV_WH))) \
    $(addprefix $(BUILD_DIR)/wc_,$(addsuffix .o,$(_SRV_WC))) \
    $(addprefix $(BUILD_DIR)/wp_,$(addsuffix .o,$(_SRV_WP))) \
    $(BUILD_DIR)/server.o

CLI_OBJS := $(BUILD_DIR)/psa_crypto_client.o \
    $(BUILD_DIR)/crypto_native_client.o \
    $(BUILD_DIR)/stub_psa_api_stub.o \
    $(BUILD_DIR)/transport.o \
    $(BUILD_DIR)/want_check.o

SRV_BIN := $(BUILD_DIR)/psa_server
TEST_BIN := $(BUILD_DIR)/test_psa_secure_crypto

.PHONY: all run run-one compilers sanitize valgrind valgrind-one clean FORCE

all: $(SRV_BIN) $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

# Both sides see the PSA_WANT_* surface of the service's wolfCrypt set.
# FORCE: the generator rewrites the header only when the surface changes.
PSA_CFG_H := $(BUILD_DIR)/wolfpsa_cfg/crypto_config_generated.h
$(PSA_CFG_H): $(WOLFPSA)/tools/gen-crypto-config.py \
    $(WOLFPSA)/tools/psa_want_probe.c user_settings.h FORCE | $(BUILD_DIR)
	mkdir -p $(dir $@)
	python3 $(WOLFPSA)/tools/gen-crypto-config.py $(WANT_WITHOUT) $@ "$(CC)" \
	    $(WOLFPSA)/tools/psa_want_probe.c $(SRV_CFLAGS) -DWT_PSA_WANT_PROBE
$(SRV_OBJS) $(CLI_OBJS) $(BUILD_DIR)/main.o: $(PSA_CFG_H)

$(BUILD_DIR)/srv_%.o: $(ROOT)/src/services/native/%.c | $(BUILD_DIR)
	$(CC) $(SRV_CFLAGS) $(WARN) -c -o $@ $<

$(BUILD_DIR)/srv_%.o: $(ROOT)/src/services/wolfhsm/%.c | $(BUILD_DIR)
	$(CC) $(SRV_CFLAGS) $(WARN) -c -o $@ $<

$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wp_%.o: $(WOLFPSA)/src/%.c | $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -DWT_PSA_POOL_TU -I$(WOLFPSA)/src -c -o $@ $<

$(BUILD_DIR)/server.o: server.c | $(BUILD_DIR)
	$(CC) $(SRV_CFLAGS) -O0 -g -Wall -Wextra -Werror \
	    -DWT_PSA_FLASH_FILE='"$(abspath $(BUILD_DIR))/flash.bin"' -c -o $@ $<

$(BUILD_DIR)/psa_crypto_client.o: $(ROOT)/src/client/psa_crypto_client.c | $(BUILD_DIR)
	$(CC) $(CLI_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/crypto_native_client.o: $(ROOT)/src/client/crypto_native_client.c | $(BUILD_DIR)
	$(CC) $(CLI_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/stub_psa_api_stub.o: $(WOLFPSA)/src/psa_api_stub.c | $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -I$(WOLFPSA)/src -c -o $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CLI_CFLAGS) -D_POSIX_C_SOURCE=200809L \
	    -DWT_PSA_SERVER_BIN='"$(abspath $(SRV_BIN))"' -c -o $@ $<

$(SRV_BIN): $(SRV_OBJS)
	$(CC) $(EXTRA_LDFLAGS) -o $@ $^

$(TEST_BIN): $(CLI_OBJS) $(BUILD_DIR)/main.o
	$(CC) $(EXTRA_LDFLAGS) -o $@ $^

run valgrind:
	@for r in $(RUNS); do \
		p=$${r%-gcm}; a=; [ "$$p" = "$$r" ] || a=gcm; \
		n=; case $$r in *-noecc) p=$${r%-noecc}; n=1 ;; esac; \
		echo "== profile $$r"; \
		$(MAKE) --no-print-directory $@-one PROFILE=$$p AEAD=$$a NO_ECC=$$n \
			BUILD_DIR=$(BUILD_DIR)/$$r || exit 1; \
	done

run-one: all
	rm -f $(BUILD_DIR)/flash.bin
	$(TEST_BIN)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind-one: all
	rm -f $(BUILD_DIR)/flash.bin
	valgrind --error-exitcode=1 --leak-check=full \
		--trace-children=yes $(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)

FORCE:
