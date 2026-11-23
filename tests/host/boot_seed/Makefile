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
    -Wno-unused-function -Wno-unused-parameter \
    -DWT_ATTEST_COSE=1 -DWOLFHSM_CFG_NO_CRYPTO -DWOLFHSM_CFG_NO_SYS_TIME \
    -I$(ROOT)/include -I$(ROOT)/lib/wolfHSM $(EXTRA_CFLAGS)
TEST := $(BUILD_DIR)/test_boot_seed

.PHONY: all run sanitize valgrind clean
all: $(TEST)
$(TEST): main.c $(ROOT)/src/boot.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ main.c
run: $(TEST)
	$(TEST)
sanitize:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"
valgrind: $(TEST)
	valgrind --error-exitcode=1 --leak-check=full $(TEST)
clean:
	rm -rf $(BUILD_DIR)
