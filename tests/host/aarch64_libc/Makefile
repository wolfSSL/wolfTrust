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

CFLAGS := \
    -I$(ROOT)/include \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic
CFLAGS += $(EXTRA_CFLAGS)

LIBC_OBJ := $(BUILD_DIR)/libc_min.o
LIBC_RENAME := -Dmemset=wt_min_memset -Dmemcpy=wt_min_memcpy \
    -Dmemmove=wt_min_memmove -Dmemcmp=wt_min_memcmp
TEST_BIN := $(BUILD_DIR)/test_aarch64_libc

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(LIBC_OBJ): $(ROOT)/src/arch/aarch64/common/libc_min.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -fno-builtin $(LIBC_RENAME) -c -o $@ $<

$(TEST_BIN): main.c $(LIBC_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ main.c $(LIBC_OBJ)

run: $(TEST_BIN)
	$(TEST_BIN)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

# pointer-compare flags a relational comparison of pointers into different
# objects, which memmove must not rely on.
sanitize:
	ASAN_OPTIONS=detect_invalid_pointer_pairs=2 $(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,pointer-compare,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,pointer-compare,undefined"

valgrind: clean $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
