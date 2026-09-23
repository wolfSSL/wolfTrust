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
WOLFSSL := $(ROOT)/lib/wolfSSL

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
    -DWOLFSSL_USER_SETTINGS \
    -UHAVE_CONFIG_H \
    -I. \
    -I$(ROOT)/tests/host/wolfhsm_loopback \
    -I$(ROOT)/include \
    -I$(WOLFSSL) \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

_WT_SRCS := \
    $(ROOT)/src/ffm.c \
    $(ROOT)/src/ffm_boot.c \
    $(ROOT)/src/ffm_domain.c \
    $(ROOT)/src/ipc.c \
    $(ROOT)/src/spm_gate.c \
    $(ROOT)/src/services/hsm_relay_service.c \
    $(ROOT)/src/services/storage_service.c \
    $(ROOT)/src/services/vault_service.c \
    $(ROOT)/src/services/vnet/vnet_relay_service.c \
    $(ROOT)/src/vnet/vnet_mac.c \
    $(ROOT)/src/vnet/vnet_pool.c \
    $(ROOT)/src/vnet/vnet_ring.c \
    $(ROOT)/src/vnet/vnet_fdb.c \
    $(ROOT)/src/vnet/vnet_switch.c

_CLIENT_SRCS := \
    $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/client/vnet_psa_transport.c

_TEST_SRCS := main.c

_WT_OBJS     := $(patsubst %.c,wt_%.o,$(notdir $(_WT_SRCS)))
_CLIENT_OBJS := $(patsubst %.c,cl_%.o,$(notdir $(_CLIENT_SRCS)))
_TEST_OBJS   := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_WT_OBJS) $(_CLIENT_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_vnet_relay

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/vnet/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(ROOT)/src/vnet/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/cl_%.o: $(ROOT)/src/client/%.c | $(BUILD_DIR)
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

valgrind: clean $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
