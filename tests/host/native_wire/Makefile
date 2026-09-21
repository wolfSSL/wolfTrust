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

ROOT    := ../../..
WOLFHSM := $(ROOT)/lib/wolfHSM
WOLFSSL := $(ROOT)/lib/wolfSSL

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
    -DWOLFSSL_USER_SETTINGS \
    -UHAVE_CONFIG_H \
    -DWOLFHSM_CFG_NO_CRYPTO \
    -DWOLFHSM_CFG_NO_SYS_TIME \
    -I. \
    -I$(ROOT)/include \
    -I$(WOLFHSM) \
    -I$(WOLFSSL) \
    -std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

# wolfCrypt's ECC/ASN sources need GNU libc declarations that strict C11
# hides; wolfTrust and test sources keep the strict flags above.
WC_CFLAGS := $(filter-out -std=c11 -Werror -pedantic -Wextra,$(CFLAGS))

# The native crypto wire and its key backend over a RAM-backed NVM store:
# native_wire.c is port-free, so the packet parser and every operation run
# here exactly as SERVICE_HSM's submit hook drives them on target.
_WT_SRCS := \
    $(ROOT)/src/services/native/native_wire.c \
    $(ROOT)/src/services/native/keyvault.c \
    $(ROOT)/src/services/wolfhsm/wt_hsm_vault.c

_WH_SRCS := \
    $(WOLFHSM)/src/wh_nvm.c \
    $(WOLFHSM)/src/wh_nvm_flash.c \
    $(WOLFHSM)/src/wh_flash_ramsim.c \
    $(WOLFHSM)/src/wh_flash_unit.c \
    $(WOLFHSM)/src/wh_utils.c

_WC_SRCS := \
    $(WOLFSSL)/wolfcrypt/src/aes.c      \
    $(WOLFSSL)/wolfcrypt/src/asn.c      \
    $(WOLFSSL)/wolfcrypt/src/coding.c   \
    $(WOLFSSL)/wolfcrypt/src/ecc.c      \
    $(WOLFSSL)/wolfcrypt/src/sp_int.c   \
    $(WOLFSSL)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL)/wolfcrypt/src/sha256.c   \
    $(WOLFSSL)/wolfcrypt/src/random.c   \
    $(WOLFSSL)/wolfcrypt/src/memory.c   \
    $(WOLFSSL)/wolfcrypt/src/error.c    \
    $(WOLFSSL)/wolfcrypt/src/logging.c  \
    $(WOLFSSL)/wolfcrypt/src/hash.c     \
    $(WOLFSSL)/wolfcrypt/src/wc_port.c  \
    $(WOLFSSL)/wolfcrypt/src/misc.c

_TEST_SRCS := main.c

_WT_OBJS   := $(patsubst %.c,wt_%.o,$(notdir $(_WT_SRCS)))
_WH_OBJS   := $(patsubst %.c,wh_%.o,$(notdir $(_WH_SRCS)))
_WC_OBJS   := $(patsubst %.c,wc_%.o,$(notdir $(_WC_SRCS)))
_TEST_OBJS := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_WT_OBJS) $(_WH_OBJS) $(_WC_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_native_wire

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/native/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/wolfhsm/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(BUILD_DIR)
	$(CC) $(WC_CFLAGS) -c -o $@ $<

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
