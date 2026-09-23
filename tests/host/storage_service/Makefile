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

ROOT    := ../../..
WOLFHSM := $(ROOT)/lib/wolfHSM

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
    -DWOLFHSM_CFG_NO_CRYPTO \
    -DWOLFHSM_CFG_NO_SYS_TIME \
    -I. \
    -I$(ROOT)/include \
    -I$(WOLFHSM) \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

_WT_SRCS := \
    $(ROOT)/src/ffm.c \
    $(ROOT)/src/ffm_domain.c \
    $(ROOT)/src/ipc.c \
    $(ROOT)/src/spm_gate.c \
    $(ROOT)/src/services/storage_service.c \
    $(ROOT)/src/services/vault_service.c \
    $(ROOT)/src/services/wolfhsm/wt_hsm_vault.c

_WH_SRCS := \
    $(WOLFHSM)/src/wh_nvm.c \
    $(WOLFHSM)/src/wh_nvm_flash.c \
    $(WOLFHSM)/src/wh_flash_ramsim.c \
    $(WOLFHSM)/src/wh_flash_unit.c \
    $(WOLFHSM)/src/wh_utils.c

_TEST_SRCS := main.c

_WT_OBJS   := $(patsubst %.c,wt_%.o,$(notdir $(_WT_SRCS)))
_WH_OBJS   := $(patsubst %.c,wh_%.o,$(notdir $(_WH_SRCS)))
_TEST_OBJS := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_WT_OBJS) $(_WH_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_storage_service

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/wolfhsm/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(ALL_OBJS)

run: $(TEST_BIN)
	$(TEST_BIN)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full $(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
