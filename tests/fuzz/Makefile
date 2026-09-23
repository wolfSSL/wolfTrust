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

ROOT := ../..
CC ?= clang
BUILD_DIR ?= build
FUZZ_TIME ?= 30
MAX_LEN ?= 4096

CFLAGS := -std=c99 -O1 -g -Wall -Wextra -pedantic -I$(ROOT)/include \
    -fsanitize=fuzzer,address -fno-omit-frame-pointer $(EXTRA_CFLAGS)
LDFLAGS := -fsanitize=fuzzer,address $(EXTRA_LDFLAGS)

TARGET := $(BUILD_DIR)/wt_spm_fuzz
SRCS := $(ROOT)/src/ffm.c $(ROOT)/src/ipc.c wt_spm_fuzz.c

.PHONY: all run corpus clean

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(TARGET): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

corpus:
	python3 gen_corpus.py

# Bounded local smoke run: build, seed, fuzz for FUZZ_TIME seconds, fail on a
# crash. libFuzzer exits 0 when -max_total_time expires with no finding.
run: $(TARGET) corpus
	ASAN_OPTIONS=abort_on_error=1:symbolize=1 \
	  $(TARGET) corpus/ -dict=wt_spm.dict -max_len=$(MAX_LEN) \
	    -timeout=30 -rss_limit_mb=2048 -max_total_time=$(FUZZ_TIME) \
	    -print_final_stats=1

clean:
	rm -rf $(BUILD_DIR)
