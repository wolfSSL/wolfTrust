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
WOLFHSM := $(ROOT)/lib/wolfHSM

CC ?= cc
BUILD_DIR ?= build
# The port's unit (16, the phrase) is the default run; `run` repeats the
# suite with wolfHSM's 8-byte default to show the hazard it would carry.
WT_FLASH_UNIT ?= 16

CFLAGS := \
    -DWOLFHSM_CFG_NO_CRYPTO \
    -DWOLFHSM_CFG_NO_SYS_TIME \
    -DWOLFHSM_CFG_FLASH_UNIT_SIZE=$(WT_FLASH_UNIT) \
    -I$(ROOT)/include \
    -I$(ROOT)/port/mcxn947 \
    -I$(WOLFHSM) \
    -include mock_rom_api.h \
    -std=c99 -O0 -g -Wall -Wextra -pedantic
CFLAGS += $(EXTRA_CFLAGS)

_PORT_SRCS := $(ROOT)/port/mcxn947/rom_flash.c
_WH_SRCS := \
    $(WOLFHSM)/src/wh_nvm.c \
    $(WOLFHSM)/src/wh_nvm_flash.c \
    $(WOLFHSM)/src/wh_flash_unit.c \
    $(WOLFHSM)/src/wh_utils.c
_TEST_SRCS := main.c

_PORT_OBJS := $(patsubst %.c,wt_%.o,$(notdir $(_PORT_SRCS)))
_WH_OBJS   := $(patsubst %.c,wh_%.o,$(notdir $(_WH_SRCS)))
_TEST_OBJS := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_PORT_OBJS) $(_WH_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_mcxn947_flash

.PHONY: all run run-one compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_%.o: $(ROOT)/port/mcxn947/%.c mock_rom_api.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wno-unused-parameter -c -o $@ $<

$(BUILD_DIR)/%.o: %.c mock_rom_api.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(ALL_OBJS)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(ALL_OBJS)

run: $(TEST_BIN)
	$(TEST_BIN)
	$(MAKE) --no-print-directory run-one \
		BUILD_DIR=$(BUILD_DIR)/unit8 WT_FLASH_UNIT=8

run-one: $(TEST_BIN)
	$(TEST_BIN)

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
