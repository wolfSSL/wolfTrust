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
# The STM32L562 PAL also fails closed when the persisted sector cannot load.
TEST_L562 := $(BUILD_DIR)/test_flash_nvm_stm32l562
SRCS_L562 := $(ROOT)/port/stm32l562/conformance/pal_driver_intf.c main.c
CFLAGS_L562 := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -DWT_CONF_NVM_HOST_TEST -DWT_CONF_NVM_LOAD_FAIL_CLOSED \
    -I$(ROOT)/include -I$(ROOT)/port/stm32l562/conformance $(EXTRA_CFLAGS)

.PHONY: all run compilers compiler-gcc compiler-clang sanitize valgrind \
    run-valgrind clean

all: $(TEST) $(TEST_L562)

$(BUILD_DIR):
	mkdir -p $@

$(TEST): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

$(TEST_L562): $(SRCS_L562) | $(BUILD_DIR)
	$(CC) $(CFLAGS_L562) $(LDFLAGS) -o $@ $(SRCS_L562)

run: $(TEST) $(TEST_L562)
	$(TEST)
	$(TEST_L562)

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

run-valgrind: $(TEST) $(TEST_L562)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_L562)

clean:
	rm -rf $(BUILD_DIR)
