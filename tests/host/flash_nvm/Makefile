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
# along with this program; if not, see <https://www.gnu.org/licenses/>.

ROOT := ../../..
CC ?= cc
BUILD_DIR ?= build

CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -DWT_CONF_NVM_HOST_TEST -DWT_CONFORMANCE=1 -I$(ROOT)/include \
    $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)
H5 := $(ROOT)/port/stm32h563
A64 := $(ROOT)/port/common/aarch64
TEST := $(BUILD_DIR)/test_flash_nvm
TEST_A64 := $(BUILD_DIR)/test_flash_nvm_aarch64
WRAP := $(BUILD_DIR)/test_conf_wrap
WRAP_A64 := $(BUILD_DIR)/test_conf_wrap_aarch64
TESTS := $(TEST) $(TEST_A64) $(WRAP) $(WRAP_A64)

.PHONY: all run compilers compiler-gcc compiler-clang sanitize valgrind \
    run-valgrind clean

all: $(TESTS)

$(BUILD_DIR):
	mkdir -p $@

$(TEST): $(H5)/conformance/pal_driver_intf.c main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(H5)/conformance $(LDFLAGS) -o $@ $^

$(TEST_A64): $(A64)/conformance/pal_driver_intf.c main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(A64)/conformance $(LDFLAGS) -o $@ $^

$(WRAP): $(H5)/conformance/conf_nvm_sync.c wrap.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(H5)/conformance -I$(H5) $(LDFLAGS) -o $@ $^

$(WRAP_A64): $(A64)/conformance/conf_nvm_sync.c wrap.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(A64)/conformance $(LDFLAGS) -o $@ $^

run: $(TESTS)
	$(TEST)
	$(TEST_A64)
	$(WRAP)
	$(WRAP_A64)

compiler-gcc:
	$(MAKE) run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc

compiler-clang:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

compilers: compiler-gcc compiler-clang

sanitize:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind:
	$(MAKE) run-valgrind BUILD_DIR=$(BUILD_DIR)/valgrind

run-valgrind: $(TESTS)
	for t in $(TESTS); do \
		valgrind --error-exitcode=1 --leak-check=full \
			--show-leak-kinds=all $$t || exit 1; \
	done

clean:
	rm -rf $(BUILD_DIR)
