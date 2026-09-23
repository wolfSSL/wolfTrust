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
    -I$(ROOT)/include $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)

MANIFEST_TEST := $(BUILD_DIR)/test_manifest
MANIFEST_SRCS := $(ROOT)/src/domain.c $(ROOT)/src/manifest.c main.c
GENERATOR := $(ROOT)/tools/manifest/generate.py
GENERATOR_TEST := test_generator.py
GENERATOR_FIXTURE := fixtures/level3.json
GENERATED_DIR := $(BUILD_DIR)/generated
GENERATED_STAMP := $(GENERATED_DIR)/.stamp
GENERATED_TEST := $(BUILD_DIR)/test_generated_manifest
GENERATED_C := $(GENERATED_DIR)/wolftrust_manifest_generated.c
GENERATED_H := $(GENERATED_DIR)/wolftrust_manifest_generated.h
GENERATED_SRCS := $(ROOT)/src/domain.c $(ROOT)/src/manifest.c \
	$(GENERATED_DIR)/wolftrust_manifest_generated.c generated_main.c

.PHONY: all run run-valgrind compiler-gcc compiler-clang compilers sanitize \
    valgrind clean

all: $(MANIFEST_TEST) $(GENERATED_TEST)

$(BUILD_DIR):
	mkdir -p $@

$(MANIFEST_TEST): $(MANIFEST_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(MANIFEST_SRCS)

$(GENERATED_STAMP): $(GENERATOR) $(GENERATOR_FIXTURE) | $(BUILD_DIR)
	python3 $(GENERATOR) $(GENERATOR_FIXTURE) $(GENERATED_DIR) \
		--supported-features 0x5 --address-bits 32
	touch $@

$(GENERATED_C) $(GENERATED_H): $(GENERATED_STAMP)

$(GENERATED_TEST): $(ROOT)/src/domain.c $(ROOT)/src/manifest.c \
	generated_main.c $(GENERATED_STAMP) $(GENERATED_C) $(GENERATED_H)
	$(CC) $(CFLAGS) -I$(GENERATED_DIR) $(LDFLAGS) -o $@ $(GENERATED_SRCS)

run: $(MANIFEST_TEST) $(GENERATED_TEST)
	$(MANIFEST_TEST)
	$(GENERATED_TEST)
	python3 $(GENERATOR_TEST)
	sh test_variant_stamp.sh $(BUILD_DIR)/variant

compiler-gcc:
	$(MAKE) run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc

compiler-clang:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

compilers: compiler-gcc compiler-clang

sanitize:
	$(MAKE) run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind:
	$(MAKE) run-valgrind BUILD_DIR=$(BUILD_DIR)/valgrind

run-valgrind: $(MANIFEST_TEST) $(GENERATED_TEST)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(MANIFEST_TEST)
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all \
		$(GENERATED_TEST)

clean:
	rm -rf $(BUILD_DIR)
