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

ROOT    := ../../..
WOLFTPM := $(ROOT)/lib/wolfTPM

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
	-DWOLFTPM_SWTPM \
	-DWOLFTPM_USER_SETTINGS \
	-DWOLFTPM2_NO_WOLFCRYPT \
	-DSINGLE_THREADED \
	-DWT_TPM_POLL_LIMIT=3U \
	-ffunction-sections -fdata-sections \
	-I. \
	-I$(ROOT)/include \
	-I$(WOLFTPM) \
	-std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
	-Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

ifeq ($(shell uname -s),Darwin)
GC_LDFLAGS := -Wl,-dead_strip
else
GC_LDFLAGS := -Wl,--gc-sections
endif

_SRCS := \
	$(ROOT)/src/client/tpm_psa_transport.c \
	$(WOLFTPM)/src/tpm2.c \
	$(WOLFTPM)/src/tpm2_util.c \
	main.c

_OBJS := $(addprefix $(BUILD_DIR)/,tpm_psa_transport.o tpm2.o tpm2_util.o main.o)
TEST_BIN := $(BUILD_DIR)/test_tpm_client

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/tpm_psa_transport.o: $(ROOT)/src/client/tpm_psa_transport.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tpm2.o: $(WOLFTPM)/src/tpm2.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tpm2_util.o: $(WOLFTPM)/src/tpm2_util.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(GC_LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(_OBJS)

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
