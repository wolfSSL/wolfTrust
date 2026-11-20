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
	-I$(ROOT)/lib/wolfPKCS11 \
	-DWOLFPKCS11_USER_SETTINGS \
	-std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
	-Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

OBJS := \
	$(BUILD_DIR)/pkcs11_proxy.o \
	$(BUILD_DIR)/pkcs11_wire.o \
	$(BUILD_DIR)/main.o
TEST_BIN := $(BUILD_DIR)/test_pkcs11_proxy

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/pkcs11_proxy.o: $(ROOT)/src/client/pkcs11_proxy.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/pkcs11_wire.o: $(ROOT)/src/pkcs11/pkcs11_wire.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/main.o: main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS)

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
