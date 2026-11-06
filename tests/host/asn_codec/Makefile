# Makefile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.

ROOT := ../../..
WOLFSSL := $(ROOT)/lib/wolfSSL
CC ?= cc
BUILD_DIR ?= build

CFLAGS := -DWOLFSSL_USER_SETTINGS -UHAVE_CONFIG_H -I../native_wire \
    -I$(WOLFSSL) -std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter
CFLAGS += $(EXTRA_CFLAGS)
WC_CFLAGS := $(filter-out -std=c11 -Werror -pedantic -Wextra,$(CFLAGS))

WC_NAMES := aes asn coding ecc sp_int wolfmath sha256 random memory error \
    logging hash wc_port misc
TEMPLATE_OBJS := $(addprefix $(BUILD_DIR)/template/wc_,$(addsuffix .o,$(WC_NAMES)))
ORIGINAL_OBJS := $(addprefix $(BUILD_DIR)/original/wc_,$(addsuffix .o,$(WC_NAMES)))
TEMPLATE_BIN := $(BUILD_DIR)/template/test_asn_codec
ORIGINAL_BIN := $(BUILD_DIR)/original/test_asn_codec

.PHONY: all run compilers sanitize valgrind clean
all: $(TEMPLATE_BIN) $(ORIGINAL_BIN)

$(BUILD_DIR)/template $(BUILD_DIR)/original:
	mkdir -p $@

$(BUILD_DIR)/template/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(BUILD_DIR)/template
	$(CC) $(WC_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/original/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(BUILD_DIR)/original
	$(CC) $(WC_CFLAGS) -DWOLFSSL_ASN_ORIGINAL -c -o $@ $<

$(BUILD_DIR)/template/main.o: main.c | $(BUILD_DIR)/template
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/original/main.o: main.c | $(BUILD_DIR)/original
	$(CC) $(CFLAGS) -DWOLFSSL_ASN_ORIGINAL -c -o $@ $<

$(TEMPLATE_OBJS) $(ORIGINAL_OBJS) $(BUILD_DIR)/template/main.o \
    $(BUILD_DIR)/original/main.o: ../native_wire/user_settings.h

$(TEMPLATE_BIN): $(TEMPLATE_OBJS) $(BUILD_DIR)/template/main.o
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $^

$(ORIGINAL_BIN): $(ORIGINAL_OBJS) $(BUILD_DIR)/original/main.o
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ $^

run: all
	$(TEMPLATE_BIN) --write $(BUILD_DIR)/template.der
	$(ORIGINAL_BIN) --write $(BUILD_DIR)/original.der
	$(TEMPLATE_BIN) --read $(BUILD_DIR)/original.der
	$(ORIGINAL_BIN) --read $(BUILD_DIR)/template.der

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: run
	valgrind --error-exitcode=1 --leak-check=full $(TEMPLATE_BIN) --read $(BUILD_DIR)/original.der
	valgrind --error-exitcode=1 --leak-check=full $(ORIGINAL_BIN) --read $(BUILD_DIR)/template.der

clean:
	rm -rf $(BUILD_DIR)
