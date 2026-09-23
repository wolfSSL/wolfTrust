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
    -DWT_CONF_NVM_HOST_TEST \
    -I$(ROOT)/include -I$(ROOT)/port/stm32h563/conformance $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)
TEST := $(BUILD_DIR)/test_flash_nvm
SRCS := $(ROOT)/port/stm32h563/conformance/pal_driver_intf.c main.c

.PHONY: all run compilers compiler-gcc compiler-clang sanitize valgrind \
    run-valgrind clean

all: $(TEST)

$(BUILD_DIR):
	mkdir -p $@

$(TEST): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

run: $(TEST)
	$(TEST)

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

run-valgrind: $(TEST)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST)

clean:
	rm -rf $(BUILD_DIR)
