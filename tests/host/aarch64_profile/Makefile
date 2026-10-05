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

CFLAGS := \
    -I$(ROOT)/include \
    -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -DWT_SPM_TABLE_POOL_PAGES=128u
CFLAGS += $(EXTRA_CFLAGS)

GENERATOR := $(ROOT)/tools/manifest/generate.py
GEN_OPTS := --supported-features 0x1 --supported-framework-version 0x100 \
    --address-bits 64 --mpu-granule 4096 --spm-table-pages 8
SRCS := $(ROOT)/src/domain.c $(ROOT)/src/manifest.c $(ROOT)/src/spm.c \
    $(ROOT)/src/partition.c $(ROOT)/port/common/aarch64/partitions.c main.c

# <variant>:<port>:<manifest>:<expected fence>
VARIANTS := qemuvirt:qemuvirt:manifest:1 \
    qemuvirt-conf:qemuvirt:manifest-conformance:1 \
    versal:versal:manifest:0 \
    versal-conf:versal:manifest-conformance:0

field = $(word $(2),$(subst :, ,$(1)))
BINS := $(foreach v,$(VARIANTS),$(BUILD_DIR)/test_$(call field,$(v),1))

.PHONY: all run compilers sanitize valgrind clean

all: $(BINS)

define variant_rule
$(BUILD_DIR)/$(call field,$(1),1)/wolftrust_manifest_generated.c: \
		$(GENERATOR) $(ROOT)/port/$(call field,$(1),2)/$(call field,$(1),3).json
	python3 $(GENERATOR) $(ROOT)/port/$(call field,$(1),2)/$(call field,$(1),3).json \
		$(BUILD_DIR)/$(call field,$(1),1) $(GEN_OPTS) > /dev/null

$(BUILD_DIR)/test_$(call field,$(1),1): $(SRCS) \
		$(ROOT)/port/$(call field,$(1),2)/memory_map.h \
		$(BUILD_DIR)/$(call field,$(1),1)/wolftrust_manifest_generated.c
	$(CC) $(CFLAGS) -I$(ROOT)/port/$(call field,$(1),2) \
		-I$(BUILD_DIR)/$(call field,$(1),1) \
		-DEXPECT_NS_FENCE=$(call field,$(1),4) \
		$(if $(findstring conformance,$(call field,$(1),3)),-DWT_CONFORMANCE=1) \
		-DVARIANT_NAME='"$(call field,$(1),1)"' $(EXTRA_LDFLAGS) -o $$@ \
		$(SRCS) $(BUILD_DIR)/$(call field,$(1),1)/wolftrust_manifest_generated.c
endef
$(foreach v,$(VARIANTS),$(eval $(call variant_rule,$(v))))

# DEN0022 5.11: the reset budget that ends an emulator run on SYSTEM_RESET
# builds only for a port marked emulated.
PSCI_SRC := $(ROOT)/src/arch/aarch64/el3/psci.c
# The EL3 parking state holds WT_EL3_MAX_CPUS cores; a port may declare no
# more, and no fewer than its boot core.
EL3_MAIN_CPP := $(CC) -E -I$(ROOT)/include -DWT_SPM_BOOT_INFO_PA=0x0E040000u \
	$(ROOT)/src/arch/aarch64/el3/el3_main.c

run: $(BINS)
	@set -e; for bin in $(BINS); do $$bin; done
	@$(CC) -E -I$(ROOT)/include -DWT_EL3_RESET_LIMIT=1u -DWT_PORT_EMULATED=1 \
		$(PSCI_SRC) > /dev/null
	@if $(CC) -E -I$(ROOT)/include -DWT_EL3_RESET_LIMIT=1u $(PSCI_SRC) 2>&1 | \
		grep -q "emulated targets only"; then \
		echo "  [check] PASS  a reset budget builds only for an emulated port"; \
	else \
		echo "  [check] FAIL  a reset budget builds for a port not marked emulated"; \
		exit 1; \
	fi
	@for n in 1u 4u; do \
		$(EL3_MAIN_CPP) -DWT_PORT_BOOT_CPUS=$$n > /dev/null || exit 1; \
	done; \
	echo "  [check] PASS  a port declaring 1 to WT_EL3_MAX_CPUS boot cores builds"
	@for n in 0u 5u 32u; do \
		if ! $(EL3_MAIN_CPP) -DWT_PORT_BOOT_CPUS=$$n 2>&1 | \
			grep -q "must be between"; then \
			echo "  [check] FAIL  WT_PORT_BOOT_CPUS=$$n builds"; \
			exit 1; \
		fi; \
	done; \
	echo "  [check] PASS  no boot cores, or more than the EL3 parking state holds, is refused"

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: clean $(BINS)
	@set -e; for bin in $(BINS); do \
		valgrind --error-exitcode=1 --leak-check=full \
			--show-leak-kinds=all $$bin; \
	done

clean:
	rm -rf $(BUILD_DIR)
