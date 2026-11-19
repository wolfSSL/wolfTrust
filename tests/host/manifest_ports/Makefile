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

# Every port manifest, generated with that port's real platform arguments and
# run through the boot-time validator and the port binding it replaces.
ROOT := ../../..
CC ?= cc
BUILD_DIR ?= build

CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -DWT_MANIFEST_RUNTIME_CHECK=1 -I$(ROOT)/include $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)

.PHONY: all run sanitize valgrind clean

all: run

run:
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
		sh ./run.sh "$(ROOT)" "$(BUILD_DIR)"

sanitize:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind:
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
		RUNNER="valgrind --error-exitcode=1 --leak-check=full" \
		sh ./run.sh "$(ROOT)" "$(BUILD_DIR)/valgrind"

clean:
	rm -rf $(BUILD_DIR)
