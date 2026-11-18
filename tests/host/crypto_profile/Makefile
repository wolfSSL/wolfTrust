# Makefile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.

ROOT := ../../..

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
	-I../pkcs11_provider \
	-I$(ROOT)/include \
	-I$(ROOT)/lib/wolfPKCS11 \
	-DWOLFPKCS11_USER_SETTINGS -DWOLFPKCS11_NO_STORE \
	-std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
	-Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

PROFILE_DIR := $(abspath $(BUILD_DIR)/profile)
PROFILE_HEADER := $(PROFILE_DIR)/selected_profile.h
CFLAGS += -include $(PROFILE_HEADER)
OBJS := $(addprefix $(BUILD_DIR)/,pkcs11_proxy.o pkcs11_provider.o pkcs11_wire.o provider_stubs.o main.o)
TEST_BIN := $(BUILD_DIR)/test_crypto_profile

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(PROFILE_HEADER): $(ROOT)/tools/crypto_profile.py $(ROOT)/config/crypto-profiles.json | $(BUILD_DIR)
	python3 $(ROOT)/tools/crypto_profile.py --output $(PROFILE_DIR) $(PROFILE_ARGS)

$(BUILD_DIR)/pkcs11_proxy.o: $(ROOT)/src/client/pkcs11_proxy.c $(PROFILE_HEADER)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/pkcs11_provider.o: $(ROOT)/src/pkcs11/pkcs11_provider.c $(PROFILE_HEADER)
	$(CC) $(CFLAGS) -include ../pkcs11_provider/provider_stubs.h -c -o $@ $<

$(BUILD_DIR)/pkcs11_wire.o: $(ROOT)/src/pkcs11/pkcs11_wire.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/provider_stubs.o: ../pkcs11_provider/provider_stubs.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/main.o: main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS)

$(OBJS): $(PROFILE_HEADER)

run: $(TEST_BIN)
	$(TEST_BIN)
	python3 test_generator.py --build-dir $(BUILD_DIR)
	$(MAKE) --no-print-directory all BUILD_DIR=$(BUILD_DIR)/custom \
		PROFILE_ARGS="--enable pkcs11:C_GetObjectSize --disable pkcs11:C_GetMechanismInfo"
	$(BUILD_DIR)/custom/test_crypto_profile

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
