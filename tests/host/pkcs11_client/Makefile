# Makefile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.

ROOT := ../../..

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
	-I. \
	-I$(ROOT)/include \
	-DWT_PKCS11_POLL_LIMIT=3U \
	-std=c11 -O2 -g -Wall -Wextra -Werror -pedantic \
	-Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

OBJS := \
	$(BUILD_DIR)/pkcs11_psa_transport.o \
	$(BUILD_DIR)/main.o
TEST_BIN := $(BUILD_DIR)/test_pkcs11_client
TRANSPORT_SRC := $(ROOT)/src/client/pkcs11_psa_transport.c

.PHONY: all run check-zeroize compilers sanitize valgrind clean

all: check-zeroize $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/pkcs11_psa_transport.o: \
		$(TRANSPORT_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/main.o: main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS)

check-zeroize:
	@grep -Fq 'wt_forceZero(&chunk, sizeof(chunk));' $(TRANSPORT_SRC)
	@! grep -Fq 'memset(&chunk' $(TRANSPORT_SRC)
	@echo "PASS: PKCS11 client chunk uses optimization-resistant zeroization"

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
