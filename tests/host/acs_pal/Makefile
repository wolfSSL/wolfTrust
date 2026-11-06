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

# Host rows for the FF-A ACS platform page pool (tests/conformance/ffa-acs/
# tgt_wolftrust_qemu/src/pal_misc.c), built against stub PAL headers here.

ROOT := ../../..

CC ?= cc
BUILD_DIR ?= build

PAL_SRC := $(ROOT)/tests/conformance/ffa-acs/tgt_wolftrust_qemu/src/pal_misc.c

CFLAGS := \
    -I. \
    -DSP1_COMPILE=1 \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic
CFLAGS += $(EXTRA_CFLAGS)

TEST_BIN := $(BUILD_DIR)/test_acs_pal

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(TEST_BIN): main.c $(PAL_SRC) pal_interfaces.h pal_misc_asm.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ main.c $(PAL_SRC)

# Each image's device map builds under ISO C: the dispatcher's, and a
# partition with no devices, whose map is empty.
PAL_CHECK := $(CC) -I. -std=c99 -Wall -Wextra -Werror -pedantic -c \
	-o /dev/null $(PAL_SRC)

run: $(TEST_BIN)
	$(TEST_BIN)
	@$(PAL_CHECK) -DVM1_COMPILE=1
	@echo "  [check] PASS  the dispatcher's device map builds"
	@$(PAL_CHECK)
	@echo "  [check] PASS  a partition with no devices builds an empty device map"

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: clean $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
