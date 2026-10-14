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

ROOT := ../../..

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
    -I. \
    -I$(ROOT)/include \
    -DWT_PKCS11_TEST_HOOKS \
    -std=c11 -O2 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

_WT_SRCS := \
    $(ROOT)/src/ffm.c \
    $(ROOT)/src/ffm_domain.c \
    $(ROOT)/src/ipc.c \
    $(ROOT)/src/spm_gate.c

_WTS_SRCS := \
    $(ROOT)/src/services/pkcs11/pkcs11_relay_service.c

_WTC_SRCS := \
    $(ROOT)/src/client/pkcs11_psa_transport.c

_TEST_SRCS := main.c

_WT_OBJS   := $(patsubst %.c,wt_%.o,$(notdir $(_WT_SRCS)))
_WTS_OBJS  := $(patsubst %.c,wts_%.o,$(notdir $(_WTS_SRCS)))
_WTC_OBJS  := $(patsubst %.c,wtc_%.o,$(notdir $(_WTC_SRCS)))
_TEST_OBJS := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_WT_OBJS) $(_WTS_OBJS) $(_WTC_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_pkcs11_relay
RELAY_SRC := $(ROOT)/src/services/pkcs11/pkcs11_relay_service.c

.PHONY: all run check-zeroize compilers sanitize valgrind clean

all: check-zeroize $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wts_%.o: $(ROOT)/src/services/pkcs11/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wtc_%.o: $(ROOT)/src/client/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(ALL_OBJS)

check-zeroize:
	@test "$$(grep -Fc 'wt_forceZero(&chunk, sizeof(chunk));' $(RELAY_SRC))" -eq 2
	@! grep -Fq 'memset(&chunk' $(RELAY_SRC)
	@echo "PASS: PKCS11 relay chunk uses optimization-resistant zeroization"

run: check-zeroize $(TEST_BIN)
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
