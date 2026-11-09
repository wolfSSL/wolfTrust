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
    -Wno-unused-function -ffunction-sections -fdata-sections \
    -I$(ROOT)/include -I$(BUILD_DIR) $(EXTRA_CFLAGS)
ifeq ($(shell uname -s),Darwin)
GC_FLAGS := -Wl,-dead_strip
else
GC_FLAGS := -Wl,--gc-sections
endif
TEST := $(BUILD_DIR)/test_monitor
TEST_VNET := $(BUILD_DIR)/test_monitor_vnet
VNET_SRCS := $(ROOT)/src/services/vnet/vnet_service.c \
    $(ROOT)/src/vnet/vnet_switch.c $(ROOT)/src/vnet/vnet_fdb.c \
    $(ROOT)/src/vnet/vnet_mac.c $(ROOT)/src/vnet/vnet_pool.c \
    $(ROOT)/src/vnet/vnet_ring.c
GENERATOR := $(ROOT)/tools/manifest/generate.py
FIXTURE := $(ROOT)/port/stm32h563/manifest.json
GENERATED := $(BUILD_DIR)/wolftrust_manifest_generated.h

.PHONY: all run sanitize valgrind clean
all: $(TEST) $(TEST_VNET)
$(GENERATED): $(GENERATOR) $(FIXTURE)
	mkdir -p $(BUILD_DIR)
	python3 $(GENERATOR) $(FIXTURE) $(BUILD_DIR) \
		--supported-features 0x1 --address-bits 32
$(TEST): main.c $(ROOT)/src/monitor.c $(ROOT)/src/restart_policy.c $(GENERATED)
	$(CC) $(CFLAGS) $(GC_FLAGS) $(EXTRA_LDFLAGS) -o $@ \
		main.c $(ROOT)/src/restart_policy.c
$(TEST_VNET): main.c $(ROOT)/src/monitor.c $(ROOT)/src/restart_policy.c \
    $(VNET_SRCS) $(GENERATED)
	$(CC) $(CFLAGS) -DCONFIG_VNET $(GC_FLAGS) $(EXTRA_LDFLAGS) -o $@ \
		main.c $(ROOT)/src/restart_policy.c $(VNET_SRCS)
run: $(TEST) $(TEST_VNET)
	$(TEST)
	$(TEST_VNET)
sanitize:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"
valgrind: $(TEST) $(TEST_VNET)
	valgrind --error-exitcode=1 --leak-check=full $(TEST)
	valgrind --error-exitcode=1 --leak-check=full $(TEST_VNET)
clean:
	rm -rf $(BUILD_DIR)
