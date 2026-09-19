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

# ---------------------------------------------------------------------------
# Paths (relative to this directory)
# ---------------------------------------------------------------------------
ROOT      := ../../..
WOLFHSM   := $(ROOT)/lib/wolfHSM
WOLFSSL   := $(ROOT)/lib/wolfSSL

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
CC ?= cc
BUILD_DIR ?= build

# ---------------------------------------------------------------------------
# Compile flags
# ---------------------------------------------------------------------------
CFLAGS := \
    -DWOLFSSL_USER_SETTINGS \
    -UHAVE_CONFIG_H \
    -DWOLFHSM_CFG_NO_SYS_TIME \
    -DWOLFHSM_CFG_ENABLE_CLIENT \
    -DWOLFHSM_CFG_ENABLE_SERVER \
    -I. \
    -I$(WOLFHSM) \
    -I$(WOLFSSL) \
    -O0 -g -Wall -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)

# ---------------------------------------------------------------------------
# Source lists (full paths; flat object output with a prefix to avoid
# collisions between files that share a basename across directories)
# ---------------------------------------------------------------------------

# wolfHSM core
_WH_SRCS := \
    $(WOLFHSM)/src/wh_client.c          \
    $(WOLFHSM)/src/wh_client_crypto.c   \
    $(WOLFHSM)/src/wh_client_cryptocb.c \
    $(WOLFHSM)/src/wh_comm.c            \
    $(WOLFHSM)/src/wh_message_comm.c    \
    $(WOLFHSM)/src/wh_message_crypto.c  \
    $(WOLFHSM)/src/wh_message_keystore.c \
    $(WOLFHSM)/src/wh_message_nvm.c     \
    $(WOLFHSM)/src/wh_message_customcb.c \
    $(WOLFHSM)/src/wh_message_counter.c  \
    $(WOLFHSM)/src/wh_server.c          \
    $(WOLFHSM)/src/wh_server_crypto.c   \
    $(WOLFHSM)/src/wh_server_keystore.c \
    $(WOLFHSM)/src/wh_server_nvm.c      \
    $(WOLFHSM)/src/wh_server_customcb.c \
    $(WOLFHSM)/src/wh_server_counter.c  \
    $(WOLFHSM)/src/wh_transport_mem.c   \
    $(WOLFHSM)/src/wh_nvm.c             \
    $(WOLFHSM)/src/wh_nvm_flash.c       \
    $(WOLFHSM)/src/wh_flash_ramsim.c    \
    $(WOLFHSM)/src/wh_flash_unit.c      \
    $(WOLFHSM)/src/wh_lock.c            \
    $(WOLFHSM)/src/wh_utils.c           \
    $(WOLFHSM)/src/wh_crypto.c          \
    $(WOLFHSM)/src/wh_keyid.c           \
    $(WOLFHSM)/src/wh_log.c             \
    $(WOLFHSM)/src/wh_timeout.c

# wolfHSM port (posix time)
_WH_PORT_SRCS := \
    $(WOLFHSM)/port/posix/posix_time.c

# wolfCrypt minimal subset
_WC_SRCS := \
    $(WOLFSSL)/wolfcrypt/src/ecc.c      \
    $(WOLFSSL)/wolfcrypt/src/sha256.c   \
    $(WOLFSSL)/wolfcrypt/src/random.c   \
    $(WOLFSSL)/wolfcrypt/src/tfm.c      \
    $(WOLFSSL)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL)/wolfcrypt/src/memory.c   \
    $(WOLFSSL)/wolfcrypt/src/error.c    \
    $(WOLFSSL)/wolfcrypt/src/logging.c  \
    $(WOLFSSL)/wolfcrypt/src/hash.c     \
    $(WOLFSSL)/wolfcrypt/src/wc_port.c  \
    $(WOLFSSL)/wolfcrypt/src/cryptocb.c \
    $(WOLFSSL)/wolfcrypt/src/asn.c      \
    $(WOLFSSL)/wolfcrypt/src/coding.c  \
    $(WOLFSSL)/wolfcrypt/src/misc.c

# Test
_TEST_SRCS := main.c

# Prefix each group to avoid basename collisions
_WH_OBJS      := $(patsubst %.c,wh_%.o,$(notdir $(_WH_SRCS)))
_WH_PORT_OBJS := $(patsubst %.c,whport_%.o,$(notdir $(_WH_PORT_SRCS)))
_WC_OBJS      := $(patsubst %.c,wc_%.o,$(notdir $(_WC_SRCS)))
_TEST_OBJS    := $(patsubst %.c,%.o,$(notdir $(_TEST_SRCS)))

ALL_OBJS := $(addprefix $(BUILD_DIR)/,$(_WH_OBJS) $(_WH_PORT_OBJS) $(_WC_OBJS) $(_TEST_OBJS))
TEST_BIN := $(BUILD_DIR)/test_attestation_iak

# ---------------------------------------------------------------------------
# Compilation rules — explicit pattern per directory
# ---------------------------------------------------------------------------

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/whport_%.o: $(WOLFHSM)/port/posix/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
.PHONY: all run run-one compilers sanitize valgrind clean

all: $(TEST_BIN)

$(TEST_BIN): $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(ALL_OBJS) -lm

run: $(TEST_BIN)
	@echo "RUN: attestation_iak (default 8-byte flash unit)"
	$(TEST_BIN)
	@echo "RUN: attestation_iak (16-byte flash unit)"
	$(MAKE) --no-print-directory run-one \
		BUILD_DIR=$(BUILD_DIR)-16 \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS) -DWOLFHSM_CFG_FLASH_UNIT_SIZE=16"

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
	rm -rf $(BUILD_DIR) $(BUILD_DIR)-16
