# Makefile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.

ROOT := ../../..

CC ?= cc
BUILD_DIR ?= build

# The local wolftpm/fwtpm headers stand in for fwTPM.
CFLAGS := \
	-I. \
	-I$(ROOT)/include \
	-std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
	-Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

OBJS := \
	$(BUILD_DIR)/tpm_local_provider.o \
	$(BUILD_DIR)/main.o
TEST_BIN := $(BUILD_DIR)/test_tpm_local_provider

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/tpm_local_provider.o: \
		$(ROOT)/src/services/tpm/tpm_local_provider.c | $(BUILD_DIR)
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
