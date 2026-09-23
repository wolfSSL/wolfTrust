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

SHELL := /bin/bash

ROOT := ../../..
CC ?= cc
BUILD_DIR ?= build
PSA_ARCH_TESTS_DIR ?= $(ROOT)/build/upstream/psa-arch-tests
ARM_API := $(PSA_ARCH_TESTS_DIR)/api-tests
ARM_TEST_IDS := i001 i002 i003 i004 i005 i006 i007 i008 i010 i011 \
    i012 i024 i025 i026 i027 i063 i067 i071 i088 i090
ARM_TESTS := $(foreach id,$(ARM_TEST_IDS),\
    $(ARM_API)/ff/ipc/test_$(id)/test_$(id).c)
ARM_TEST_INCLUDES := $(foreach id,$(ARM_TEST_IDS),\
    -I$(ARM_API)/ff/ipc/test_$(id))

CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -include psa/client.h -DNONSECURE_TEST_BUILD -DIPC \
    -DSERVER_TEST_DISPATCHER_SID=0x0000FB01U \
    -DSERVER_TEST_DISPATCHER_VERSION=1U \
    -DSERVER_SECURE_CONNECT_ONLY_SID=0x0000FB02U \
    -DSERVER_SECURE_CONNECT_ONLY_VERSION=2U \
    -DSERVER_STRICT_VERSION_SID=0x0000FB03U \
    -DSERVER_STRICT_VERSION_VERSION=2U \
    -DSERVER_RELAX_VERSION_SID=0x0000FB05U \
    -DSERVER_RELAX_VERSION_VERSION=2U \
    -DSERVER_UNSPECIFIED_VERSION_SID=0x0000FB06U \
    -DSERVER_UNSPECIFIED_VERSION_VERSION=1U \
    -DSERVER_CONNECTION_DROP_SID=0x0000FB07U \
    -DSERVER_CONNECTION_DROP_VERSION=1U \
    -I. -I$(ROOT)/include $(ARM_TEST_INCLUDES) \
    -I$(ARM_API)/val/nspe -I$(ARM_API)/val/common \
    -I$(ARM_API)/platform/targets/common/nspe
CFLAGS += $(EXTRA_CFLAGS)
TEST := $(BUILD_DIR)/test_psa_ff_upstream
SRCS := $(ROOT)/src/ffm.c $(ROOT)/src/ffm_api.c $(ROOT)/src/ipc.c \
    main.c $(ARM_TESTS)
LOG_FILE ?= $(BUILD_DIR)/logs/conformance.log

.PHONY: all run clean

all: $(TEST)

$(BUILD_DIR):
	mkdir -p $@

$(TEST): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

run: $(TEST)
	@set -o pipefail; mkdir -p "$$(dirname "$(LOG_FILE)")"; \
	if ! $(TEST) 2>&1 | tee "$(LOG_FILE)"; then \
		echo "FAIL: conformance/psa_ff_upstream"; exit 1; \
	fi; \
	echo "LOG: $(LOG_FILE)"

clean:
	rm -rf $(BUILD_DIR)
