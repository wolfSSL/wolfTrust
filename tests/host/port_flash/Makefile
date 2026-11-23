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
PORTS := $(shell python3 $(ROOT)/tests/target/lib/scenario_matrix.py --list-ports)
TARGET ?= $(firstword $(PORTS))
include $(ROOT)/tests/host/layout.mk

# The port's model stands beneath its flash_drv.c; a *_mock.h redirects the
# driver's register and array seams into it.
MODEL_MOCK := $(wildcard models/$(TARGET)_mock.h)
PORT_UPPER := $(shell echo $(TARGET) | tr a-z A-Z)
CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter \
    -DWOLFHSM_CFG_NO_CRYPTO -DWOLFHSM_CFG_NO_SYS_TIME \
    -DWOLFHSM_CFG_FLASH_UNIT_SIZE=16 \
    -DWT_CONFORMANCE=1 -DWT_REMEASURE_PROBE=1 \
    -DWT_PORT_MODEL_$(PORT_UPPER) -DWT_PORT_MODEL_NAME=\"$(TARGET)\" \
    $(WT_LAYOUT_CFLAGS) -I. -Imodels -I$(WOLFHSM) \
    $(addprefix -include ,$(MODEL_MOCK)) $(EXTRA_CFLAGS)

PORT_SRCS := $(ROOT)/port/common/hsm_flash.c $(ROOT)/port/common/hsm_flash_ctx.c \
    $(ROOT)/port/$(TARGET)/flash_drv.c
WT_SRCS := $(ROOT)/src/ffm_domain.c \
    $(ROOT)/src/spm_gate.c $(ROOT)/src/services/fwu_service.c
WH_SRCS := $(WOLFHSM)/src/wh_nvm.c $(WOLFHSM)/src/wh_nvm_flash.c \
    $(WOLFHSM)/src/wh_flash_unit.c $(WOLFHSM)/src/wh_utils.c
TEST_SRCS := main.c flash_array.c models/$(TARGET).c

OBJS := $(addprefix $(BUILD_DIR)/,$(patsubst %.c,port_%.o,$(notdir $(PORT_SRCS))) \
    $(patsubst %.c,wt_%.o,$(notdir $(WT_SRCS))) \
    $(patsubst %.c,wh_%.o,$(notdir $(WH_SRCS))) \
    $(patsubst %.c,%.o,$(notdir $(TEST_SRCS))))
include $(ROOT)/tests/host/support/spm_host.mk
OBJS += $(SPM_HOST_OBJS)
TEST_BIN := $(BUILD_DIR)/test_port_flash_$(TARGET)

.PHONY: all run run-one compilers sanitize valgrind valgrind-one clean

all: run

run:
	@set -e; for p in $(PORTS); do \
		$(MAKE) --no-print-directory run-one TARGET=$$p \
			BUILD_DIR=$(BUILD_DIR)/$$p CC="$(CC)" \
			EXTRA_CFLAGS="$(EXTRA_CFLAGS)" EXTRA_LDFLAGS="$(EXTRA_LDFLAGS)"; \
	done

run-one: $(TEST_BIN)
	$(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

# Only the backend takes the target-build arch seam, so the test's stub of
# the privilege query replaces the host inline.
$(BUILD_DIR)/port_hsm_flash.o: $(ROOT)/port/common/hsm_flash.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DWT_TARGET_BUILD -c -o $@ $<
$(BUILD_DIR)/port_%.o: $(ROOT)/port/common/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD_DIR)/port_%.o: $(ROOT)/port/$(TARGET)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD_DIR)/wt_%.o: $(ROOT)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD_DIR)/wt_%.o: $(ROOT)/src/services/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD_DIR)/%.o: models/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DWT_TARGET_BUILD -c -o $@ $<

$(TEST_BIN): $(OBJS)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind:
	@set -e; for p in $(PORTS); do \
		$(MAKE) --no-print-directory valgrind-one TARGET=$$p \
			BUILD_DIR=$(BUILD_DIR)/$$p CC="$(CC)"; \
	done

valgrind-one: $(TEST_BIN)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
