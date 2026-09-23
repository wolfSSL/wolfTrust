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

ROOT := ../../..

CC ?= cc
PYTHON ?= python3
BUILD_DIR ?= build

CFLAGS := \
    -I$(ROOT)/include \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic
CFLAGS += $(EXTRA_CFLAGS)

MKHANDOFF := $(ROOT)/tools/handoff/mkhandoff.py
SRCS := $(ROOT)/src/services/boot_handoff.c main.c
TEST_BIN := $(BUILD_DIR)/test_boot_handoff
RECORD := $(BUILD_DIR)/handoff.bin
DIGEST := 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN) $(RECORD)

$(BUILD_DIR):
	mkdir -p $@

$(TEST_BIN): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(SRCS)

$(RECORD): $(MKHANDOFF) | $(BUILD_DIR)
	$(PYTHON) $(MKHANDOFF) --out $@ --digest $(DIGEST) --image-version 7 \
		--lifecycle SECURED

run: $(TEST_BIN) $(RECORD)
	$(PYTHON) $(MKHANDOFF) --selftest
	$(PYTHON) $(MKHANDOFF) --check $(RECORD)
	$(TEST_BIN) $(RECORD)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: clean $(TEST_BIN) $(RECORD)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_BIN) $(RECORD)

clean:
	rm -rf $(BUILD_DIR)
