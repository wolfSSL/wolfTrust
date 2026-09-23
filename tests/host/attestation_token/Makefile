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

ROOT     := ../../..
WOLFSSL  := $(ROOT)/lib/wolfSSL
WOLFCOSE := $(ROOT)/lib/wolfCOSE
WOLFHSM  := $(ROOT)/lib/wolfHSM
GUEST    := $(ROOT)/tests/firmware/zephyr-stm32h5/apps/guest0_psa/src

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
    -DWOLFSSL_USER_SETTINGS \
    -UHAVE_CONFIG_H \
    -DWOLFCOSE_ENABLE_EXT_SIGN \
    -DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_DEPRECATED_ALGS \
    -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
    -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
    -DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE \
    -DWOLFHSM_CFG_NO_CRYPTO \
    -DWOLFHSM_CFG_NO_SYS_TIME \
    -I. \
    -I$(ROOT)/include \
    -I$(WOLFSSL) \
    -I$(WOLFHSM) \
    -I$(WOLFCOSE)/include \
    -I$(GUEST) \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)
include ../vendor_c99.mk

# wolfCOSE sources are not -pedantic/-Werror clean under this profile; build
# them with the warnings relaxed while keeping wolfTrust + test code strict.
COSE_CFLAGS := $(filter-out -Werror -pedantic,$(CFLAGS))

_WT_SRCS := \
    $(ROOT)/src/services/initial_attestation.c \
    $(ROOT)/src/services/attestation_cose.c \
    $(ROOT)/src/guest_verify.c

_GUEST_SRCS := $(GUEST)/attestation_verify.c

_WC_SRCS := \
    $(WOLFSSL)/wolfcrypt/src/ecc.c      \
    $(WOLFSSL)/wolfcrypt/src/aes.c      \
    $(WOLFSSL)/wolfcrypt/src/hmac.c     \
    $(WOLFSSL)/wolfcrypt/src/sha256.c   \
    $(WOLFSSL)/wolfcrypt/src/random.c   \
    $(WOLFSSL)/wolfcrypt/src/tfm.c      \
    $(WOLFSSL)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL)/wolfcrypt/src/memory.c   \
    $(WOLFSSL)/wolfcrypt/src/error.c    \
    $(WOLFSSL)/wolfcrypt/src/logging.c  \
    $(WOLFSSL)/wolfcrypt/src/hash.c     \
    $(WOLFSSL)/wolfcrypt/src/wc_port.c  \
    $(WOLFSSL)/wolfcrypt/src/asn.c      \
    $(WOLFSSL)/wolfcrypt/src/coding.c   \
    $(WOLFSSL)/wolfcrypt/src/misc.c

_CO_SRCS := \
    $(WOLFCOSE)/src/wolfcose_cbor.c \
    $(WOLFCOSE)/src/wolfcose_util.c \
    $(WOLFCOSE)/src/wolfcose_alg.c \
    $(WOLFCOSE)/src/wolfcose_ecc.c \
    $(WOLFCOSE)/src/wolfcose_hdr.c \
    $(WOLFCOSE)/src/wolfcose_key.c \
    $(WOLFCOSE)/src/wolfcose_struct.c \
    $(WOLFCOSE)/src/wolfcose_recipient.c \
    $(WOLFCOSE)/src/wolfcose_sign1.c \
    $(WOLFCOSE)/src/wolfcose_sign.c \
    $(WOLFCOSE)/src/wolfcose_countersign.c \
    $(WOLFCOSE)/src/wolfcose_encrypt0.c \
    $(WOLFCOSE)/src/wolfcose_mac0.c \
    $(WOLFCOSE)/src/wolfcose_encrypt.c \
    $(WOLFCOSE)/src/wolfcose_mac.c \
    $(WOLFCOSE)/src/wolfcose_eat_psa.c

_TEST_SRCS := main.c

_WT_OBJS    := $(patsubst %.c,wt_%.o,$(notdir $(_WT_SRCS)))
_GUEST_OBJS := $(patsubst %.c,gt_%.o,$(notdir $(_GUEST_SRCS)))
_WC_OBJS    := $(patsubst %.c,wc_%.o,$(notdir $(_WC_SRCS)))
_CO_OBJS    := $(patsubst %.c,co_%.o,$(notdir $(_CO_SRCS)))
_TEST_OBJS  := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_WT_OBJS) $(_GUEST_OBJS) $(_WC_OBJS) $(_CO_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_attestation_token

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/gt_%.o: $(GUEST)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/co_%.o: $(WOLFCOSE)/src/%.c | $(BUILD_DIR)
	$(CC) $(COSE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(ALL_OBJS)

run: $(TEST_BIN)
	$(TEST_BIN)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full $(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
