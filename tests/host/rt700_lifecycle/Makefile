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
BUILD_DIR ?= build

# The mapping header ships inside the carried wolfBoot patch; test that copy.
PATCH := $(ROOT)/tests/target/wolfboot-imxrt700-lifecycle.patch
HEADER := $(BUILD_DIR)/imx_rt7xx_lifecycle.h

CFLAGS := \
    -I$(BUILD_DIR) \
    -std=c11 -O0 -g -Wall -Wextra -Werror -pedantic
CFLAGS += $(EXTRA_CFLAGS)

TEST_BIN := $(BUILD_DIR)/test_rt700_lifecycle

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(HEADER): $(PATCH) | $(BUILD_DIR)
	awk '/^\+\+\+ b\/hal\/imx_rt7xx_lifecycle\.h$$/ { f = 1; next } \
	     f && /^diff --git / { exit } \
	     f && /^\+/ { print substr($$0, 2) }' $(PATCH) > $@
	test -s $@

$(TEST_BIN): main.c $(HEADER)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ main.c

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

valgrind: clean $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
