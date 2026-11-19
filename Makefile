ARCH ?= armv8m
TARGET ?= stm32h563

ROOT := .
BUILD_DIR ?= build
WOLFHSM_RUNNER_DIR := $(ROOT)/src/services/wolfhsm/runner
WOLFHSM_DIR := $(ROOT)/lib/wolfHSM
WOLFSSL_DIR := $(ROOT)/lib/wolfSSL
WOLFHAL_DIR := $(ROOT)/lib/wolfhal
WOLFCOSE_DIR := $(ROOT)/lib/wolfCOSE
WOLFTPM_DIR := $(ROOT)/lib/wolfTPM
WOLFPKCS11_DIR := $(ROOT)/lib/wolfPKCS11

ifeq ($(wildcard mk/target-$(TARGET).mk),)
$(error unsupported secure build target TARGET=$(TARGET))
endif
ifeq ($(wildcard mk/arch-$(ARCH).mk),)
$(error unsupported secure build architecture ARCH=$(ARCH))
endif
include mk/target-$(TARGET).mk
# A port that ships its own manifest (WT_PORT_MANIFEST) also owns its layout.
include $(if $(WT_PORT_MANIFEST),,mk/layout.mk)
include mk/arch-$(ARCH).mk
include mk/common.mk

.DEFAULT_GOAL := all

.PHONY: all secure-image size-report test test-provisioning c99-check test-conformance test-target test-target-a test-hardware fetch-psa-ff-tests \
		clean firmware-stm32h563 run-stm32h563 run-stm32h563-tui run-stm32h563-uarts \
		test-domain-host test-domain-compilers test-domain-sanitize \
		test-domain-valgrind test-manifest-host test-manifest-compilers \
		test-manifest-sanitize test-manifest-valgrind test-vnet-host \
		test-vnet test-vnet-target test-vnet-hardware \
		test-lifecycle-host test-lifecycle-compilers test-lifecycle-sanitize \
		test-lifecycle-valgrind \
		test-ipc-host test-ipc-compilers test-ipc-sanitize \
		test-ipc-valgrind test-ffm-host test-ffm-compilers \
		test-ffm-sanitize test-ffm-valgrind \
		test-spm-host test-spm-compilers \
		test-spm-sanitize test-spm-valgrind \
		test-wolfcose-host \
		run-stm32h563-vnet

all: $(ARCH_DEFAULT_GOALS)

test:
	@python3 tests/target/lib/scenario_matrix.py --selftest
	@python3 tests/target/lib/scenarios.py --selftest
	@python3 tests/scripts/test_scenario_asserts.py
	@python3 tools/gen-port-docs.py --check
	@tools/new-port/test-new-port.sh
	@tools/check-no-port-names.sh
	@python3 tests/scripts/test_m33mu_console.py
	@$(MAKE) --no-print-directory -C tests/host test
	@$(MAKE) --no-print-directory test-provisioning
	@tests/target/test_hw_runner.sh

# Production lock gates of both provisioning backends, against stub tools.
test-provisioning:
	@mkdir -p $(BUILD_DIR)
	@tests/target/provisioning/test_provisioning_gates.sh > $(BUILD_DIR)/provisioning-gates.log 2>&1 \
		|| { cat $(BUILD_DIR)/provisioning-gates.log; exit 1; }
	@tail -1 $(BUILD_DIR)/provisioning-gates.log

C99_CFLAGS := -std=c99 -pedantic-errors -Werror=vla \
	-D_POSIX_C_SOURCE=200809L
C99_CC_VERSION := $(shell $(CC) --version 2>/dev/null)
ifneq ($(findstring clang,$(C99_CC_VERSION)),)
C99_CFLAGS += -Wno-newline-eof \
	--system-header-prefix=wolfssl/ \
	--system-header-prefix=wolfhsm/ \
	--system-header-prefix=wolftpm/ \
	--system-header-prefix=wolfpkcs11/
else
C99_CFLAGS += -isystem $(abspath $(WOLFSSL_DIR)) \
	-isystem $(abspath $(WOLFHSM_DIR)) \
	-isystem $(abspath $(WOLFTPM_DIR)) \
	-isystem $(abspath $(WOLFPKCS11_DIR))
endif

c99-check:
	@CC="$(CC)" sh tests/c99/check.sh
	@$(MAKE) --no-print-directory -C tests/host test \
		TEST_KIND=c99 CC="$(CC)" \
		BUILD_ROOT="$(abspath $(BUILD_DIR))/c99" \
		EXTRA_CFLAGS="$(C99_CFLAGS)"

# M33MU scenarios for one registered port (TARGET): WT_TIER=smoke (default) or
# full, from its port.json. WT_PROFILE picks the build profile: default (the
# lean image make builds with no options), full (every add-on) or both, the
# default here, which runs default then full. Skips, never passes, without an
# emulator; runs in the wolfboot-ci-m33mu container, never bare-metal.
WT_TIER ?= smoke
WT_PROFILE ?= both
WT_SCENARIOS = $(shell python3 tests/target/lib/scenario_matrix.py \
    --port $(TARGET) --tier $(WT_TIER) --engine $(WT_ENGINE) \
    --profile $(1) --flat)
test-target:
	@case "$(WT_PROFILE)" in default|full|both) ;; *) \
		echo "unsupported WT_PROFILE='$(WT_PROFILE)' (want default, full or both)" >&2; \
		exit 2 ;; esac
	@if ! tests/target/detect_m33mu.sh $(TARGET) >/dev/null 2>&1; then \
		echo "SKIP: FF-M target scenarios ($$(tests/target/detect_m33mu.sh $(TARGET) 2>&1))"; \
	else \
		$(foreach p,$(if $(filter both,$(WT_PROFILE)),default full,$(WT_PROFILE)),\
		WT_PROFILE=$(p) WT_SUITE_LOG_DIR=$(if $(filter both,$(WT_PROFILE)),logs/$(p),logs) \
		    tests/target/run_suite.sh $(TARGET) \
		    $(call WT_SCENARIOS,$(p)) || exit 1;) \
	fi

# AArch64 twin of test-target on QEMU (virt GICv2/GICv3, xlnx-versal-virt);
# auto-detect qemu-system-aarch64 + aarch64-none-elf (or WT_TARGET_SCENARIOS=1),
# skip explicitly otherwise. MACHINE/GIC/CPU/SMP pass through to the runner.
# WT_TIER=smoke (default) runs the per-PR subset, WT_TIER=full the whole suite,
# both from tests/target/lib/scenario_matrix.py (the FF-A ACS stays in CI).
WT_QEMU_A_SCENARIOS ?= $(shell python3 tests/target/lib/scenario_matrix.py --aarch64-flat --tier $(WT_TIER))
test-target-a:
	@if ! tests/target/detect_qemu_a.sh >/dev/null 2>&1; then \
		echo "SKIP: AArch64 QEMU scenarios ($$(tests/target/detect_qemu_a.sh 2>&1))"; \
	else \
		MACHINE="$(MACHINE)" GIC="$(GIC)" CPU="$(CPU)" SMP="$(SMP)" \
			tests/target/run_suite.sh qemu-a $(WT_QEMU_A_SCENARIOS); \
	fi

# Real hardware suite, the on-silicon counterpart of test-target, on the host
# that owns the board's probe: WT_HW_TIER=smoke runs the eight scenarios every
# board runs, qualification adds the port's merge-gating extras. Skips without
# a board so it never silently passes.
WT_HW_TIER ?= smoke
test-hardware:
	@tests/target/run_hardware_suite.sh $(TARGET) $(WT_HW_TIER)

test-compilers:
	@$(MAKE) --no-print-directory -C tests/host test-compilers

test-sanitize:
	@$(MAKE) --no-print-directory -C tests/host test-sanitize

test-valgrind:
	@$(MAKE) --no-print-directory -C tests/host test-valgrind

fetch-psa-ff-tests:
	@tests/upstream/fetch_psa_arch_tests.sh \
		$(BUILD_DIR)/upstream/psa-arch-tests

test-manifest-ingest: fetch-psa-ff-tests
	@echo "RUN: conformance/manifest_ingest"
	@python3 tests/host/manifest_ingest/run.py \
		$(abspath $(BUILD_DIR))/upstream/psa-arch-tests

# One conformance entry point. With an M33MU emulator (or WT_TARGET_SCENARIOS=1)
# it runs the full FF-M IPC suite on the target — the real conformance evidence
# (85 passed / 4 skipped). Without one it falls back to the host subset (20
# client-side IPC/policy tests) and prints an explicit non-hardware warning, so
# a host-only run is never mistaken for the full suite. Detection is shared with
# test-target via tests/target/detect_m33mu.sh. CI runs the same target suite
# through the confboot leg of the wolfboot-wolftrust-m33mu-scenarios matrix.
test-conformance: fetch-psa-ff-tests test-manifest-ingest
	@if tests/target/detect_m33mu.sh $(TARGET) >/dev/null 2>&1; then \
		mkdir -p logs; \
		echo "RUN: conformance/target (full FF-M IPC suite on M33MU)"; \
		if tests/target/run_target.sh $(TARGET) confboot \
				> logs/conformance-target.log 2>&1; then \
			grep -F '  [check] ' logs/conformance-target.log || true; \
			echo "PASS: conformance/target"; \
			echo "LOG: logs/conformance-target.log"; \
		else \
			grep -F '  [check] ' logs/conformance-target.log || true; \
			echo "FAIL: conformance/target (tail of the log):"; \
			tail -25 logs/conformance-target.log; \
			echo "LOG: logs/conformance-target.log"; \
			exit 1; \
		fi; \
	else \
		echo "RUN: conformance/host-subset"; \
		$(MAKE) --no-print-directory -C tests/host/psa_ff_upstream run \
			BUILD_DIR=$(abspath $(BUILD_DIR))/psa-ff-upstream \
			PSA_ARCH_TESTS_DIR=$(abspath $(BUILD_DIR))/upstream/psa-arch-tests; \
		echo "WARNING: host-only conformance subset (20 client-side IPC/policy tests) — NOT emulator/hardware evidence."; \
		echo "WARNING: isolation, panic-reset, IRQ, and cross-domain tests need M33MU ($$(tests/target/detect_m33mu.sh $(TARGET) 2>&1))."; \
		echo "WARNING: run the full 85/4 suite with an emulator, or: make test-target."; \
		echo "PASS: conformance/host-subset (partial — see warnings above)"; \
	fi

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C tests/firmware/stm32h563 clean
	$(MAKE) -C tests/firmware/stm32h563-vnet clean
	$(MAKE) -C tests/firmware/aarch64-smoke clean
	$(MAKE) -C tests/firmware/aarch64-ns-smoke clean
	$(MAKE) -C tests/host/domain clean
	$(MAKE) -C tests/host/manifest clean
	$(MAKE) -C tests/host/lifecycle clean
	$(MAKE) -C tests/host/ipc clean
	$(MAKE) -C tests/host/ffm clean
	$(MAKE) -C tests/host/ffm_domain clean
	$(MAKE) -C tests/host/ffm_veneer clean
	$(MAKE) -C tests/host/sp_layout clean
	$(MAKE) -C tests/host/spm_gate clean
	$(MAKE) -C tests/host/psa_ff_upstream clean
	$(MAKE) -C tests/host/spm clean
	$(MAKE) -C tests/host/vnet clean
	$(MAKE) -C tests/host/wolfcose clean

test-domain-host:
	$(MAKE) -C tests/host/domain run

test-domain-compilers:
	$(MAKE) -C tests/host/domain compilers

test-domain-sanitize:
	$(MAKE) -C tests/host/domain sanitize

test-domain-valgrind:
	$(MAKE) -C tests/host/domain valgrind

test-manifest-host:
	$(MAKE) -C tests/host/manifest run

test-manifest-compilers:
	$(MAKE) -C tests/host/manifest compilers

test-manifest-sanitize:
	$(MAKE) -C tests/host/manifest sanitize

test-manifest-valgrind:
	$(MAKE) -C tests/host/manifest valgrind

test-lifecycle-host:
	$(MAKE) -C tests/host/lifecycle run

test-lifecycle-compilers:
	$(MAKE) -C tests/host/lifecycle compilers

test-lifecycle-sanitize:
	$(MAKE) -C tests/host/lifecycle sanitize

test-lifecycle-valgrind:
	$(MAKE) -C tests/host/lifecycle valgrind

test-ipc-host:
	$(MAKE) -C tests/host/ipc run

test-ipc-compilers:
	$(MAKE) -C tests/host/ipc compilers

test-ipc-sanitize:
	$(MAKE) -C tests/host/ipc sanitize

test-ipc-valgrind:
	$(MAKE) -C tests/host/ipc valgrind

test-ffm-host:
	$(MAKE) -C tests/host/ffm run

test-ffm-compilers:
	$(MAKE) -C tests/host/ffm compilers

test-ffm-sanitize:
	$(MAKE) -C tests/host/ffm sanitize

test-ffm-valgrind:
	$(MAKE) -C tests/host/ffm valgrind

test-spm-host:
	$(MAKE) -C tests/host/spm run

test-spm-compilers:
	$(MAKE) -C tests/host/spm compilers

test-spm-sanitize:
	$(MAKE) -C tests/host/spm sanitize

test-spm-valgrind:
	$(MAKE) -C tests/host/spm valgrind

test-vnet-host:
	$(MAKE) -C tests/host/vnet run

# wolfIP virtual network support host proof: the Ethernet switch dataplane
# (tests/host/vnet) plus the SPM-mediated SERVICE_VNET dispatch round trip
# (tests/host/vnet_relay), where guest0 -> SERVICE_VNET -> switch -> guest1.
# Both also run individually as CI unit suites; this is the one-command
# aggregate.
test-vnet: test-vnet-host
	$(MAKE) -C tests/host/vnet_relay run

# wolfIP virtual network end-to-end scenario on the M33MU emulator: two
# authenticated bare-metal wolfIP guests exchange an ICMP echo through
# SERVICE_VNET (CONFIG_VNET=y). Auto-detect-or-skip like test-target, so it
# never silently passes; runs inside the wolfboot-ci-m33mu container.
test-vnet-target:
	@if ! tests/target/detect_m33mu.sh $(TARGET) >/dev/null 2>&1; then \
		echo "SKIP: wolfIP vnet target scenario ($$(tests/target/detect_m33mu.sh $(TARGET) 2>&1))"; \
	else \
		tests/target/run_suite.sh m33mu vnet; \
	fi

# wolfIP virtual network end-to-end scenario on real STM32H563 silicon: the
# on-board counterpart of test-vnet-target. Needs the ST-Link + board; skips
# otherwise. HARDWARE evidence, recorded separately from the emulator.
test-vnet-hardware:
	@tests/target/run_hardware_suite.sh stm32h563 vnet

test-wolfcose-host:
	$(MAKE) -C tests/host/wolfcose run

run-stm32h563-vnet:
	$(MAKE) -C tests/firmware/stm32h563-vnet ARCH=$(ARCH) TARGET=$(TARGET) run

firmware-stm32h563:
	$(MAKE) -C tests/firmware/stm32h563 ARCH=$(ARCH) TARGET=$(TARGET) all

run-stm32h563:
	$(MAKE) -C tests/firmware/stm32h563 ARCH=$(ARCH) TARGET=$(TARGET) run

run-stm32h563-tui:
	$(MAKE) -C tests/firmware/stm32h563 ARCH=$(ARCH) TARGET=$(TARGET) run-tui

run-stm32h563-uarts:
	$(MAKE) -C tests/firmware/stm32h563 ARCH=$(ARCH) TARGET=$(TARGET) run-uarts
