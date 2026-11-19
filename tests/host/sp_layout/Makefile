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
TARGET := stm32h563

CC ?= cc
BUILD_DIR ?= build
include $(ROOT)/tests/host/layout.mk

CFLAGS := \
    $(WT_LAYOUT_CFLAGS) \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic
CFLAGS += $(EXTRA_CFLAGS)

TEST_BIN := $(BUILD_DIR)/test_sp_layout
TEST_FWU := $(BUILD_DIR)/test_sp_layout_fwu
TEST_CONF := $(BUILD_DIR)/test_sp_layout_conf
TEST_VNET := $(BUILD_DIR)/test_sp_layout_vnet
TESTS := $(TEST_BIN) $(TEST_FWU) $(TEST_CONF) $(TEST_VNET)

.PHONY: all run compilers sanitize valgrind clean

all: $(TESTS)

$(BUILD_DIR):
	mkdir -p $@

$(TEST_BIN): main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -UWT_FWU $(EXTRA_LDFLAGS) -o $@ main.c

$(TEST_FWU): main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DWT_FWU=1 -DWT_ENGINE_HSM=1 $(EXTRA_LDFLAGS) -o $@ main.c

$(TEST_CONF): main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -UWT_FWU -DWT_CONFORMANCE=1 $(EXTRA_LDFLAGS) -o $@ main.c

$(TEST_VNET): main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DCONFIG_VNET=1 -DWT_FWU=1 $(EXTRA_LDFLAGS) -o $@ main.c

run: $(TESTS)
	$(foreach test,$(TESTS),$(test) &&) true

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: clean $(TEST_BIN) $(TEST_FWU)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_FWU)

clean:
	rm -rf $(BUILD_DIR)
