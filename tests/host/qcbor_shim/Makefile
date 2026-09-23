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
SHIM     := $(ROOT)/tests/conformance/qcbor-shim

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
    -DWOLFSSL_USER_SETTINGS \
    -UHAVE_CONFIG_H \
    -DWOLFCOSE_ENABLE_EXT_SIGN -DWOLFCOSE_ENABLE_DEPRECATED_ALGS \
    -I. \
    -I$(SHIM) \
    -I$(ROOT)/include \
    -I$(WOLFSSL) \
    -I$(WOLFCOSE)/include \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)
include ../vendor_c99.mk

COSE_CFLAGS := $(filter-out -Werror -pedantic,$(CFLAGS))

_WT_SRCS := \
    $(ROOT)/src/services/attestation_cose.c \
    $(SHIM)/qcbor_shim.c

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

_WT_OBJS   := $(patsubst %.c,wt_%.o,$(notdir $(_WT_SRCS)))
_WC_OBJS   := $(patsubst %.c,wc_%.o,$(notdir $(_WC_SRCS)))
_CO_OBJS   := $(patsubst %.c,co_%.o,$(notdir $(_CO_SRCS)))
_TEST_OBJS := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_WT_OBJS) $(_WC_OBJS) $(_CO_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_qcbor_shim

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_attestation_cose.o: $(ROOT)/src/services/attestation_cose.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_qcbor_shim.o: $(SHIM)/qcbor_shim.c | $(BUILD_DIR)
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

# Interop: build the SAME test against the reference QCBOR library (fetched
# test-only) instead of the wolfCOSE shim, proving a wolfCOSE-produced token
# parses under upstream QCBOR too. Not in UNIT_SUITES (needs a network fetch).
QCBOR_DIR ?= $(ROOT)/build/upstream/qcbor
INTEROP_BIN := $(BUILD_DIR)/test_real_qcbor
INTEROP_CFLAGS := \
    -DWOLFSSL_USER_SETTINGS -UHAVE_CONFIG_H -DWOLFCOSE_ENABLE_EXT_SIGN \
    -DWOLFCOSE_ENABLE_DEPRECATED_ALGS \
    -I. -I$(ROOT)/include -I$(WOLFSSL) -I$(WOLFCOSE)/include \
    -I$(QCBOR_DIR)/inc -I$(QCBOR_DIR)/inc/qcbor \
    -std=c99 -O0 -g -Wall -Wextra -Wno-unused-function -Wno-unused-parameter \
    -Wno-implicit-function-declaration
INTEROP_SRCS := \
    main.c \
    $(QCBOR_DIR)/src/UsefulBuf.c $(QCBOR_DIR)/src/qcbor_encode.c \
    $(QCBOR_DIR)/src/qcbor_decode.c $(QCBOR_DIR)/src/ieee754.c \
    $(ROOT)/src/services/attestation_cose.c \
    $(WOLFCOSE)/src/wolfcose_cbor.c $(WOLFCOSE)/src/wolfcose_util.c $(WOLFCOSE)/src/wolfcose_alg.c $(WOLFCOSE)/src/wolfcose_ecc.c $(WOLFCOSE)/src/wolfcose_hdr.c $(WOLFCOSE)/src/wolfcose_key.c $(WOLFCOSE)/src/wolfcose_struct.c $(WOLFCOSE)/src/wolfcose_recipient.c $(WOLFCOSE)/src/wolfcose_sign1.c $(WOLFCOSE)/src/wolfcose_sign.c $(WOLFCOSE)/src/wolfcose_countersign.c $(WOLFCOSE)/src/wolfcose_encrypt0.c $(WOLFCOSE)/src/wolfcose_mac0.c $(WOLFCOSE)/src/wolfcose_encrypt.c $(WOLFCOSE)/src/wolfcose_mac.c $(WOLFCOSE)/src/wolfcose_eat_psa.c \
    $(_WC_SRCS)

.PHONY: run-interop

run-interop: | $(BUILD_DIR)
	$(ROOT)/tests/upstream/fetch_qcbor.sh $(QCBOR_DIR) >/dev/null
	$(CC) $(INTEROP_CFLAGS) $(EXTRA_CFLAGS) $(EXTRA_LDFLAGS) -o $(INTEROP_BIN) $(INTEROP_SRCS)
	$(INTEROP_BIN)

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
