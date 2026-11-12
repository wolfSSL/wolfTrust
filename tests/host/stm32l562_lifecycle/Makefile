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

# stm32l5_lifecycle.h is a verbatim copy of hal/stm32l5_lifecycle.h at the
# wolfBoot ref the STM32L562 runner pins; check-pin compares the two.
PIN_SH := $(ROOT)/tests/target/lib/stm32l562_wolfboot.sh
PIN_REF = $(shell sed -n 's/^STM32L562_WOLFBOOT_REF=//p' $(PIN_SH))
STM32L562_WOLFBOOT_DIR ?=

CFLAGS := \
    -I. \
    -I$(ROOT)/include \
    -std=c11 -O0 -g -Wall -Wextra -Werror -pedantic
CFLAGS += $(EXTRA_CFLAGS)

TEST_BIN := $(BUILD_DIR)/test_stm32l562_lifecycle

.PHONY: all run check-pin compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(TEST_BIN): main.c stm32l5_lifecycle.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ main.c

run: $(TEST_BIN)
	$(TEST_BIN)
	@if [ -n "$(STM32L562_WOLFBOOT_DIR)" ]; then $(MAKE) --no-print-directory check-pin; fi

check-pin:
	@test -n "$(STM32L562_WOLFBOOT_DIR)" || \
		{ echo "check-pin: set STM32L562_WOLFBOOT_DIR to a wolfBoot clone"; exit 1; }
	@test -n "$(PIN_REF)"
	git -C "$(STM32L562_WOLFBOOT_DIR)" show "$(PIN_REF):hal/stm32l5_lifecycle.h" | \
		cmp - stm32l5_lifecycle.h
	@echo "check-pin: stm32l5_lifecycle.h matches wolfBoot $(PIN_REF)"

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
