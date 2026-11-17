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
TARGET := stm32l562
WOLFHSM := $(ROOT)/lib/wolfHSM
CC ?= cc
BUILD_DIR ?= build
include $(ROOT)/tests/host/layout.mk

# The STM32L562 flash driver over the port_flash controller model, for the
# controller sequences the shared port_flash suite does not see.
MODELS := $(ROOT)/tests/host/port_flash/models
CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-parameter -DWT_REMEASURE_PROBE=1 \
    -DWOLFHSM_CFG_NO_CRYPTO -DWOLFHSM_CFG_NO_SYS_TIME \
    $(WT_LAYOUT_CFLAGS) -I$(ROOT)/tests/host/port_flash -I$(MODELS) \
    -I$(WOLFHSM) -include $(MODELS)/stm32l562_mock.h $(EXTRA_CFLAGS)

SRCS := main.c $(ROOT)/port/stm32l562/flash_drv.c $(MODELS)/stm32l562.c \
    $(ROOT)/tests/host/port_flash/flash_array.c
OBJS := $(addprefix $(BUILD_DIR)/,$(patsubst %.c,%.o,$(notdir $(SRCS))))
TEST_BIN := $(BUILD_DIR)/test_stm32l562_flash

vpath %.c . $(ROOT)/port/stm32l562 $(MODELS) $(ROOT)/tests/host/port_flash

.PHONY: all run compilers sanitize valgrind clean

all: run

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(OBJS)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS)

run: $(TEST_BIN)
	$(TEST_BIN)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full $(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
