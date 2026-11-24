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

ROOT := ../../..
TARGET := stm32h563
WOLFSSL  := $(ROOT)/lib/wolfSSL
WOLFCOSE := $(ROOT)/lib/wolfCOSE
CC ?= cc
BUILD_DIR ?= build
include $(ROOT)/tests/host/layout.mk

# The tiny profile's own attestation defines, as tests/host/attestation_hmac.
ATTEST_DEFS := $(shell $(MAKE) -s --no-print-directory -C $(ROOT) \
    WT_PROFILE=tiny print-attest-defs 2>/dev/null)
ifeq ($(filter -DWT_ATTEST_KEY_hmac=1,$(ATTEST_DEFS)),)
$(error the tiny profile no longer builds an HMAC attestation key)
endif

CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter \
    -ffunction-sections -fdata-sections \
    -DWOLFSSL_USER_SETTINGS -UHAVE_CONFIG_H $(ATTEST_DEFS) \
    -DWOLFHSM_CFG_NO_CRYPTO -DWOLFHSM_CFG_NO_SYS_TIME \
    -I../attestation_hmac -I$(ROOT)/include -I$(ROOT)/lib/wolfHSM \
    -I$(WOLFSSL) -I$(WOLFCOSE)/include -I$(BUILD_DIR) $(EXTRA_CFLAGS)
include ../vendor_c99.mk
LIB_CFLAGS := $(filter-out -Werror -pedantic,$(CFLAGS))

ifeq ($(shell uname -s),Darwin)
GC_FLAGS := -Wl,-dead_strip
else
GC_FLAGS := -Wl,--gc-sections
endif

_WC := hmac sha256 hash memory error logging wc_port misc
_CO := cbor util alg ecc hdr key struct recipient sign1 sign countersign \
    encrypt0 mac0 encrypt mac eat_psa
LIB_OBJS := $(addprefix $(BUILD_DIR)/wc_,$(addsuffix .o,$(_WC))) \
    $(addprefix $(BUILD_DIR)/co_,$(addsuffix .o,$(_CO)))

TEST := $(BUILD_DIR)/test_attest_restore
GENERATOR := $(ROOT)/tools/manifest/generate.py
FIXTURE := $(BUILD_DIR)/manifest.json
GENERATED := $(BUILD_DIR)/wolftrust_manifest_generated.h

.PHONY: all run sanitize valgrind clean

all: $(TEST)

$(FIXTURE): $(WT_MANIFEST_RENDER_DEPS)
	mkdir -p $(BUILD_DIR)
	$(WT_MANIFEST_RENDER) --output $@ $(WT_MANIFEST_TEMPLATE)

$(GENERATED): $(GENERATOR) $(FIXTURE)
	python3 $(GENERATOR) $(FIXTURE) $(BUILD_DIR) \
		--supported-features 0x1 --address-bits 32 --unchecked

$(BUILD_DIR)/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(GENERATED)
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/co_%.o: $(WOLFCOSE)/src/wolfcose_%.c | $(GENERATED)
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(TEST): main.c $(ROOT)/src/spm_partitions.c \
		$(ROOT)/src/services/initial_attestation.c $(LIB_OBJS) $(GENERATED)
	$(CC) $(CFLAGS) $(GC_FLAGS) $(EXTRA_LDFLAGS) -o $@ main.c $(LIB_OBJS)

run: $(TEST)
	$(TEST)

sanitize:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: $(TEST)
	valgrind --error-exitcode=1 --leak-check=full $(TEST)

clean:
	rm -rf $(BUILD_DIR)
