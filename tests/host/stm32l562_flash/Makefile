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
PORT := $(ROOT)/port/stm32l562

CC ?= cc
BUILD_DIR ?= build

CFLAGS := \
    -DWOLFHSM_CFG_NO_CRYPTO \
    -DWOLFHSM_CFG_NO_SYS_TIME \
    -D_DEFAULT_SOURCE \
    -DWT_TARGET_BUILD \
    -DWT_CONFORMANCE=1 \
    -I$(ROOT)/include \
    -I$(PORT) \
    -I$(WOLFHSM) \
    -include mock_l5_flash.h \
    -std=c99 -O0 -g -Wall -Wextra -pedantic -Wno-int-to-pointer-cast
CFLAGS += $(EXTRA_CFLAGS)

# The driver builds from a copy whose Cortex-M barrier, PRIMASK and WFI asm
# call host hooks and whose Secure-to-Non-secure alias mask is a subtraction;
# the checks fail the build if the source drifts from what the rewrite expects.
DRIVER_HOST := $(BUILD_DIR)/hsm_flash_host.c

_WH_SRCS := \
    $(WOLFHSM)/src/wh_nvm.c \
    $(WOLFHSM)/src/wh_nvm_flash.c \
    $(WOLFHSM)/src/wh_flash_unit.c \
    $(WOLFHSM)/src/wh_utils.c

_WH_OBJS := $(patsubst %.c,$(BUILD_DIR)/wh_%.o,$(notdir $(_WH_SRCS)))
ALL_OBJS := $(BUILD_DIR)/hsm_flash_host.o $(BUILD_DIR)/wt_hsm_flash_ctx.o \
    $(_WH_OBJS) $(BUILD_DIR)/main.o
TEST_BIN := $(BUILD_DIR)/test_stm32l562_flash

.PHONY: all run compilers sanitize valgrind clean

all: $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(DRIVER_HOST): $(PORT)/hsm_flash.c | $(BUILD_DIR)
	sed -e 's/__asm__ volatile ("dsb 0xF" ::: "memory");/wt_host_barrier();/' \
	    -e 's/__asm__ volatile ("isb 0xF" ::: "memory");/wt_host_barrier();/' \
	    -e 's/__asm__ volatile ("mrs %0, primask" : "=r" (primask));/primask = wt_host_irq_save();/' \
	    -e 's/__asm__ volatile ("cpsid i" ::: "memory");/wt_host_cpsid();/' \
	    -e 's/__asm__ volatile ("msr primask, %0" :: "r" (primask) : "memory");/wt_host_irq_restore(primask);/' \
	    -e 's/__asm__ volatile ("wfi");/wt_host_wfi();/' \
	    -e 's/data\[i\] = ((const volatile uint8_t \*)source)\[i\];/data[i] = wt_host_flash_read8(\&((const volatile uint8_t *)source)[i]);/' \
	    -e 's/ & ~0x04000000u/ - (uintptr_t)0x04000000u/g' $< > $@
	! grep -n '__asm__\|~0x04000000' $@
	test "$$(grep -c ' - (uintptr_t)0x04000000u' $@)" -eq 2
	test "$$(grep -c 'wt_host_flash_read8' $@)" -eq 1

$(BUILD_DIR)/hsm_flash_host.o: $(DRIVER_HOST) mock_l5_flash.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_%.o: $(PORT)/%.c mock_l5_flash.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wno-unused-parameter -c -o $@ $<

$(BUILD_DIR)/%.o: %.c mock_l5_flash.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BIN): $(ALL_OBJS)
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
