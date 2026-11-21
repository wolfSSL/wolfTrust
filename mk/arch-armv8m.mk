# Armv8-M architecture inputs for the secure image build. Included after
# mk/target-<soc>.mk and before mk/common.mk.
TOOLPREFIX ?= arm-none-eabi-
CPU_FLAGS := -mcpu=$(WT_CPU) -mthumb -mgeneral-regs-only
ARCH_CFLAGS := -mcmse -DWT_TARGET_BUILD=1
ifneq ($(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),)
WT_INTERFACE_LOCAL_PROVIDER := 1
ARCH_CFLAGS += -DWT_INTERFACE_LOCAL_PROVIDER=1 -DWT_PKCS11_HEAP_SIZE=0x7000U
endif

# Architectural-context isolation negatives, test builds only. The FP-probe
# build must carry exactly its one deliberate FP instruction and no other.
WT_FP_NEG_PROBE ?= 0
WT_SEAL_NEG_PROBE ?= 0
WT_MSP_OVF_PROBE ?= 0
WT_XN_NEG_PROBE ?= 0
ARCH_FP_SCAN_FLAGS :=
ifeq ($(WT_FP_NEG_PROBE),1)
ARCH_CFLAGS += -DWT_FP_NEG_PROBE=1
ARCH_FP_SCAN_FLAGS := --allow-probe
endif
ifneq ($(filter 1 2 3 4,$(WT_SEAL_NEG_PROBE)),)
ARCH_CFLAGS += -DWT_SEAL_NEG_PROBE=$(WT_SEAL_NEG_PROBE)
endif
ifeq ($(WT_MSP_OVF_PROBE),1)
ARCH_CFLAGS += -DWT_MSP_OVF_PROBE=1
endif
ifeq ($(WT_XN_NEG_PROBE),1)
ARCH_CFLAGS += -DWT_XN_NEG_PROBE=1
endif
# Portable C by default for size; the assembly is a speed opt-in.
WT_WOLFCRYPT_SP_ASM ?= 0
WT_WOLFCRYPT_ARMASM ?= 0
WT_SHA256_FAST ?= 0
ifneq ($(words $(WT_SHA256_FAST))/$(filter 0 1,$(WT_SHA256_FAST)),1/$(WT_SHA256_FAST))
$(error unsupported WT_SHA256_FAST='$(WT_SHA256_FAST)' (want 0 or 1))
endif

ARCH_HSM_DEFS :=
ifeq ($(WT_WOLFCRYPT_SP_ASM),1)
ARCH_HSM_DEFS += -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM \
    -DWOLFSSL_ARM_ARCH=8
endif
ifeq ($(WT_WOLFCRYPT_ARMASM),1)
ARCH_HSM_DEFS += -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO \
    -DWOLFSSL_ARMASM_INLINE -DWOLFSSL_ARMASM_NO_NEON \
    -DWOLFSSL_ARMASM_THUMB2
ifeq ($(WT_SHA256_FAST),0)
ARCH_HSM_DEFS += -DWOLFSSL_ARMASM_SHA256_SMALL
endif
else
ARCH_HSM_DEFS += -DWOLFSSL_AES_SMALL_TABLES -DWOLFSSL_AES_NO_UNROLL
ifeq ($(WT_SHA256_FAST),0)
ARCH_HSM_DEFS += -DUSE_SLOW_SHA256
endif
endif

ifeq ($(WT_WOLFCRYPT_SP_ASM),1)
ARCH_WOLFCRYPT_SP_SRCS := $(WOLFSSL_DIR)/wolfcrypt/src/sp_cortexm.c
else
ARCH_WOLFCRYPT_SP_SRCS := $(WOLFSSL_DIR)/wolfcrypt/src/sp_c32.c
endif
ARCH_WOLFCRYPT_ASM_SRCS :=
ifeq ($(WT_WOLFCRYPT_ARMASM),1)
ARCH_WOLFCRYPT_ASM_SRCS += \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
endif

ARCH_START_SRCS := $(WOLFHSM_RUNNER_DIR)/ivt.c
ARCH_SRCS := \
    $(ROOT)/src/arch/armv8m/cmse.c \
    $(ROOT)/src/arch/armv8m/coroutine_armv8m.c \
    $(ROOT)/src/arch/armv8m/ffm_nsc.c \
    $(ROOT)/src/arch/armv8m/spm_svc.c \
    $(ROOT)/src/arch/armv8m/guest_context_armv8m.c \
    $(ROOT)/src/arch/armv8m/sp_fault_armv8m.c \
    $(ROOT)/src/arch/armv8m/irq_armv8m.c \
    $(ROOT)/src/arch/armv8m/mpu_armv8m.c \
    $(ROOT)/src/arch/armv8m/sau_armv8m.c \
    $(ROOT)/src/arch/armv8m/start_armv8m.c

# Isolation level the secure image implements (mk/layout.mk). Only level 3
# exists, so any other value stops the build; the shared layer is gated on it.
ifneq ($(WT_ISOLATION_LEVEL),3)
$(error only isolation level 3 is implemented (WT_ISOLATION_LEVEL=$(WT_ISOLATION_LEVEL)))
endif

ifeq ($(WT_ISOLATION_LEVEL),3)
# Isolation level 3 layer shared by every Armv8-M port: the band layout, its
# linker fragments and the platform hooks. A port's memory_map.h supplies
# WT_RAM_S_BASE, from which every band is placed.
PORT_HEADERS += $(wildcard $(PORT_COMMON_DIR)/*.h)
TARGET_EXTRA_SRCS += $(PORT_COMMON_DIR)/platform_l3.c \
    $(PORT_COMMON_DIR)/platform_armv8m.c $(PORT_COMMON_DIR)/fabric_sau.c
# The guest and capability tables, parameterised by the port's memory_map.h.
TARGET_PARTITIONS_SRC := $(PORT_COMMON_DIR)/partitions.c
WT_RAM_S_ORIGIN := $(shell sed -n \
    's/^\#define WT_RAM_S_BASE[[:space:]]*\(0x[0-9A-Fa-f]*\)u.*/\1/p' \
    $(PORT_DIR)/memory_map.h)
ifeq ($(WT_RAM_S_ORIGIN),)
$(error $(PORT_DIR)/memory_map.h has no literal WT_RAM_S_BASE)
endif
TARGET_LDFLAGS += -Wl,-L$(PORT_COMMON_DIR) \
    -Wl,--defsym=WT_RAM_S_ORIGIN=$(WT_RAM_S_ORIGIN)
# One linker script for every Armv8-M port, preprocessed by mk/common.mk;
# WT_LD_RAM_CODE_BAND=1 selects the XIP-from-NOR shape (RAM code band).
SECURE_LD_IN := $(PORT_COMMON_DIR)/secure.ld.in
SECURE_LD_DEFS := -DWT_LD_RAM_CODE_BAND=$(WT_LD_RAM_CODE_BAND)
SECURE_LD := $(BUILD_DIR)/secure.ld
# Band placement for the linker fragments, read from memory_map.h under the
# firmware's own layout configuration at link time.
WT_L3_LINK_ARGS = $(or $(strip $(shell $(WT_LAYOUT_TOOL) --link \
    --cc $(WT_LAYOUT_CPP) --cflags '$(WT_LAYOUT_CFLAGS)' \
    $(PORT_DIR)/memory_map.h)),$(error \
    cannot read the level 3 band placement from $(PORT_DIR)/memory_map.h))
# Partition stacks the generator checks the rendered manifest against, under
# the same layout configuration.
WT_L3_MANIFEST_ARGS = $(or $(strip $(shell $(WT_LAYOUT_TOOL) --stacks \
    --cc $(WT_LAYOUT_CPP) --cflags '$(WT_LAYOUT_CFLAGS)' \
    $(PORT_DIR)/memory_map.h)),$(error \
    cannot read the level 3 partition stacks from $(PORT_DIR)/memory_map.h))
# Immutable platform capabilities for the manifest generator; they must equal
# port/common/armv8m/platform_caps.h, which the generated manifest asserts.
WT_PLATFORM_CAPABILITIES ?= 0x7F
WT_PLATFORM_MAX_DOMAINS ?= 11
WT_PLATFORM_MAX_MEMORY_RESOURCES ?= 3
WT_PLATFORM_MAX_INTERRUPTS ?= 1
# A port that defines WT_PORT_CAPABILITIES in memory_map.h sets this to the
# same value in mk/target-<soc>.mk; the generated manifest asserts they agree.
WT_PLATFORM_PORT_CAPABILITIES ?= 0x7
# Post-link band check inputs, read the same way at link time; an unreadable
# layout stops the link rather than checking the default bands.
WT_L3_BAND_ARGS = $(shell $(WT_LAYOUT_TOOL) \
    --cc $(WT_LAYOUT_CPP) --cflags '$(WT_LAYOUT_CFLAGS)' \
    $(PORT_DIR)/memory_map.h)
WT_SECURE_LAYOUT_ARGS = $(or $(strip $(WT_L3_BAND_ARGS)),$(error \
    cannot read the level 3 bands from $(PORT_DIR)/memory_map.h)) \
    $(WT_SECURE_LAYOUT_EXTRA_ARGS)
endif

# CMSE import library for the Non-secure guests, produced by the secure link.
SECURE_CMSE_IMPLIB := $(BUILD_DIR)/secure_cmse_implib.o
ARCH_LINK_OUTPUTS := $(SECURE_CMSE_IMPLIB)
ARCH_LDFLAGS = -Wl,--cmse-implib -Wl,--out-implib=$(SECURE_CMSE_IMPLIB) \
    $(WT_LAYOUT_LDFLAGS) $(WT_L3_LINK_ARGS)

# The owner map the post-link layout check reads: the shared map plus the
# port's own objects (port/<soc>/secure_owners.txt), so a port adds its
# owners without editing the shared file.
WT_SECURE_OWNERS := $(BUILD_DIR)/secure_owners-$(TARGET).txt
$(WT_SECURE_OWNERS): $(ROOT)/tools/secure_owners.txt \
    $(wildcard $(PORT_DIR)/secure_owners.txt) | $(BUILD_DIR)
	cat $^ > $@

# A changed post-link checker must relink so the image is checked again.
$(BUILD_DIR)/wolftrust.elf $(ARCH_LINK_OUTPUTS): \
    $(ROOT)/tools/check_no_fp_insn.py $(ROOT)/tools/check_stack_seal.py \
    $(ROOT)/tools/l3_layout_args.py $(wildcard $(PORT_COMMON_DIR)/*.ld) \
    $(WT_SECURE_OWNERS)

# Whitelist of non-secure-callable veneers the linked secure image may
# export: exactly the five mediated FF-M gateway entries, pinned by full
# name so a renamed or added veneer fails the link in every build,
# CONFIG_VNET included (virtual networking rides SERVICE_VNET psa_call).
NSC_ALLOWED := __acle_se_WolfTrust_FFM_(FrameworkVersion|ServiceVersion|Connect|Call|Close)$$
NSC_COUNT := 5
WT_INTERFACE_BODY := $(strip $(if $(filter y,$(CONFIG_TPM)),FWTPM_ProcessCommand,\
    $(if $(filter y,$(CONFIG_PKCS11)),wt_pkcs11_provider_dispatch)))

define arch_interface_checks
	@if grep -Eq ' (vTaskStartScheduler|xTaskCreate|pvPortMalloc|vPortFree)$$' \
            $(BUILD_DIR)/nsc-syms.txt; then \
        echo "FAIL: interface handler links an RTOS runtime" >&2; exit 1; \
    fi
	@if ! grep -Eq ' [TW] $(WT_INTERFACE_BODY)$$' $(BUILD_DIR)/nsc-syms.txt; then \
        echo "FAIL: selected interface handler is absent from wolfTrust" >&2; exit 1; \
    fi
endef

# Post-link image checks run by the common link rule.
define arch_image_checks
	@$(TOOLPREFIX)nm $(SECURE_ELF) > $(BUILD_DIR)/nsc-syms.txt || \
		{ echo "FAIL: nm on the secure image failed" >&2; exit 1; }
	$(if $(WT_INTERFACE_BODY),$(arch_interface_checks))
	@if grep ' __acle_se_' $(BUILD_DIR)/nsc-syms.txt | \
			grep -vE '$(NSC_ALLOWED)'; then \
		echo "FAIL: non-secure-callable veneer outside the FF-M gateway (WT-FFM-0054)" >&2; \
		exit 1; \
	fi
	@n=$$(grep -cE ' __acle_se_' $(BUILD_DIR)/nsc-syms.txt); \
	if [ "$$n" -ne $(NSC_COUNT) ]; then \
		echo "FAIL: expected $(NSC_COUNT) FF-M veneers, found $$n (WT-FFM-0057)" >&2; \
		exit 1; \
	fi
	@python3 $(ROOT)/tools/check_secure_layout.py \
		--nm $(TOOLPREFIX)nm $(WT_SECURE_LAYOUT_ARGS) $(SECURE_ELF) \
		--map $(SECURE_MAP) --owners $(WT_SECURE_OWNERS) \
		$(if $(filter 1,$(WT_CONFORMANCE)),,--production) \
		--objects-nm $(TOOLPREFIX)gcc-nm --objects $(ALL_SECURE_OBJS)
	@if grep -E ' (malloc|free|calloc|realloc|_sbrk|_malloc_r|_free_r)$$' \
			$(BUILD_DIR)/nsc-syms.txt; then \
		echo "FAIL: heap allocator symbol in the zero-heap secure image" >&2; \
		exit 1; \
	fi
	@$(TOOLPREFIX)objdump -d --no-show-raw-insn $(SECURE_ELF) \
		> $(BUILD_DIR)/sec-disasm.txt || \
		{ echo "FAIL: objdump on the secure image failed" >&2; exit 1; }
	@python3 $(ROOT)/tools/check_no_fp_insn.py $(ARCH_FP_SCAN_FLAGS) \
		$(BUILD_DIR)/sec-disasm.txt
	@$(TOOLPREFIX)size -A -x $(SECURE_ELF) > $(BUILD_DIR)/sec-sections.txt || \
		{ echo "FAIL: size on the secure image failed" >&2; exit 1; }
	@estack=$$(awk '$$3 == "_estack" { print $$1 }' $(BUILD_DIR)/nsc-syms.txt); \
	sstack=$$(awk '$$3 == "_sstack" { print $$1 }' $(BUILD_DIR)/nsc-syms.txt); \
	python3 $(ROOT)/tools/check_stack_seal.py --estack "$$estack" \
		--sstack "$$sstack" $(BUILD_DIR)/sec-sections.txt
endef
