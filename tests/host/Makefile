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
CC ?= cc
BUILD_ROOT ?= build
TEST_KIND ?= unit
LOG_FILE ?= $(BUILD_ROOT)/logs/$(TEST_KIND).log
VERBOSE ?= 0
EXTRA_CFLAGS ?=

ifeq ($(VERBOSE),1)
SUBMAKE_FLAGS := --no-print-directory
else
SUBMAKE_FLAGS := --no-print-directory -s
endif

UNIT_SUITES := domain manifest lifecycle guest_verify rollback sp_recovery \
    ipc ffm spm \
    vnet wolfhsm_loopback wolfhsm_relay native_wire native_wire_client \
    keystore_isolation \
    attestation_service attestation attestation_token \
    attestation_golden attestation_negatives attestation_replay \
    attestation_iak ffm_domain sp_layout port_binding boot_handoff spm_gate \
    flash_nvm ffm_veneer \
    vault_service storage_service ps_service negatives qcbor_shim \
    fwu_service runtime_verify psa_ffm_client psa_storage_client vnet_relay \
    psa_headers

.PHONY: all test test-compilers test-sanitize test-valgrind print-suites clean

all: test

print-suites:
	@echo $(UNIT_SUITES)

test:
	@set -e -o pipefail; mkdir -p "$$(dirname "$(LOG_FILE)")"; : > "$(LOG_FILE)"; \
	for suite in $(UNIT_SUITES); do \
		suite_log="$(BUILD_ROOT)/logs/$(TEST_KIND)-$$suite.log"; \
		echo "RUN: $(TEST_KIND)/$$suite"; \
		echo "RUN: $(TEST_KIND)/$$suite" >> "$(LOG_FILE)"; \
		if [ "$(VERBOSE)" = "1" ]; then \
			if $(MAKE) $(SUBMAKE_FLAGS) -C $$suite clean run \
				CC="$(CC)" BUILD_DIR="$(BUILD_ROOT)/$$suite" \
				EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
				2>&1 | tee "$$suite_log"; then \
				status=0; \
			else \
				status=$${PIPESTATUS[0]}; \
			fi; \
		else \
			if $(MAKE) $(SUBMAKE_FLAGS) -C $$suite clean run \
				CC="$(CC)" BUILD_DIR="$(BUILD_ROOT)/$$suite" \
				EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
				> "$$suite_log" 2>&1; then \
				status=0; \
			else \
				status=$$?; \
			fi; \
		fi; \
		cat "$$suite_log" >> "$(LOG_FILE)"; \
		if [ $$status -ne 0 ]; then \
			echo "FAIL: $(TEST_KIND)/$$suite"; cat "$$suite_log"; exit 1; \
		fi; \
		grep '^PASS:' "$$suite_log" || true; \
		echo "PASS: $(TEST_KIND)/$$suite"; \
	done
	@echo "PASS: $(TEST_KIND)/all"; echo "LOG: $(LOG_FILE)"

test-compilers:
	$(MAKE) test TEST_KIND=compiler CC="$(CC)" \
		BUILD_ROOT="$(BUILD_ROOT)/compiler"

test-sanitize: TEST_KIND=sanitizer
test-sanitize: LOG_FILE=$(BUILD_ROOT)/logs/sanitizer.log

test-sanitize:
	@set -e -o pipefail; mkdir -p "$$(dirname "$(LOG_FILE)")"; : > "$(LOG_FILE)"; \
	for suite in $(UNIT_SUITES); do \
		suite_log="$(BUILD_ROOT)/logs/sanitizer-$$suite.log"; \
		echo "RUN: sanitizer/$$suite"; \
		echo "RUN: sanitizer/$$suite" >> "$(LOG_FILE)"; \
		if [ "$(VERBOSE)" = "1" ]; then \
			if $(MAKE) $(SUBMAKE_FLAGS) -C $$suite clean sanitize \
				BUILD_DIR="$(BUILD_ROOT)/sanitize/$$suite" \
				2>&1 | tee "$$suite_log"; then \
				status=0; \
			else \
				status=$${PIPESTATUS[0]}; \
			fi; \
		else \
			if $(MAKE) $(SUBMAKE_FLAGS) -C $$suite clean sanitize \
				BUILD_DIR="$(BUILD_ROOT)/sanitize/$$suite" \
				> "$$suite_log" 2>&1; then \
				status=0; \
			else \
				status=$$?; \
			fi; \
		fi; \
		cat "$$suite_log" >> "$(LOG_FILE)"; \
		if [ $$status -ne 0 ]; then \
			echo "FAIL: sanitizer/$$suite"; cat "$$suite_log"; exit 1; \
		fi; \
		echo "PASS: sanitizer/$$suite"; \
	done
	@echo "PASS: sanitizer/all"; echo "LOG: $(LOG_FILE)"

test-valgrind: TEST_KIND=valgrind
test-valgrind: LOG_FILE=$(BUILD_ROOT)/logs/valgrind.log

test-valgrind:
	@set -e -o pipefail; mkdir -p "$$(dirname "$(LOG_FILE)")"; : > "$(LOG_FILE)"; \
	for suite in $(UNIT_SUITES); do \
		suite_log="$(BUILD_ROOT)/logs/valgrind-$$suite.log"; \
		echo "RUN: valgrind/$$suite"; \
		echo "RUN: valgrind/$$suite" >> "$(LOG_FILE)"; \
		if [ "$(VERBOSE)" = "1" ]; then \
			if $(MAKE) $(SUBMAKE_FLAGS) -C $$suite clean valgrind \
				BUILD_DIR="$(BUILD_ROOT)/valgrind/$$suite" \
				2>&1 | tee "$$suite_log"; then \
				status=0; \
			else \
				status=$${PIPESTATUS[0]}; \
			fi; \
		else \
			if $(MAKE) $(SUBMAKE_FLAGS) -C $$suite clean valgrind \
				BUILD_DIR="$(BUILD_ROOT)/valgrind/$$suite" \
				> "$$suite_log" 2>&1; then \
				status=0; \
			else \
				status=$$?; \
			fi; \
		fi; \
		cat "$$suite_log" >> "$(LOG_FILE)"; \
		if [ $$status -ne 0 ]; then \
			echo "FAIL: valgrind/$$suite"; cat "$$suite_log"; exit 1; \
		fi; \
		echo "PASS: valgrind/$$suite"; \
	done
	@echo "PASS: valgrind/all"; echo "LOG: $(LOG_FILE)"

clean:
	@for suite in $(UNIT_SUITES); do \
		$(MAKE) -C $$suite clean; \
	done
	rm -rf $(BUILD_ROOT)
