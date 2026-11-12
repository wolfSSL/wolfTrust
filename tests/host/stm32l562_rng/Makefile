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

CFLAGS := \
    -I$(ROOT)/include \
    -I$(ROOT)/port/stm32l562 \
    -include mock_l5_rng.h \
    -DWT_TARGET_BUILD \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic -Wno-int-to-pointer-cast
CFLAGS += $(EXTRA_CFLAGS)

ALL_OBJS := $(BUILD_DIR)/wt_rng_entropy.o $(BUILD_DIR)/main.o
TEST_BIN := $(BUILD_DIR)/test_stm32l562_rng
# The driver latches failure, so each case runs in its own process.
CASES := default seed clock seis ceisread timeout zero zeroinit zerovalid

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_%.o: $(ROOT)/port/stm32l562/%.c mock_l5_rng.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c mock_l5_rng.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(ALL_OBJS)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(ALL_OBJS)

run: $(TEST_BIN)
	for c in $(CASES); do $(TEST_BIN) $$c || exit 1; done

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: clean $(TEST_BIN)
	for c in $(CASES); do \
		valgrind --error-exitcode=1 --leak-check=full \
			--show-leak-kinds=all $(TEST_BIN) $$c || exit 1; \
	done

clean:
	rm -rf $(BUILD_DIR)
