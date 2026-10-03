# Armv8-M architecture inputs for the secure image build. Included after
# mk/target-<soc>.mk and before mk/common.mk.
TOOLPREFIX ?= arm-none-eabi-
CPU_FLAGS := -mcpu=$(WT_CPU) -mthumb -mgeneral-regs-only
ARCH_CFLAGS := -mcmse -DWT_TARGET_BUILD=1

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
WT_WOLFCRYPT_SP_ASM ?= 1
WT_WOLFCRYPT_ARMASM ?= 1

ARCH_HSM_DEFS :=
ifeq ($(WT_WOLFCRYPT_SP_ASM),1)
ARCH_HSM_DEFS += -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM \
    -DWOLFSSL_ARM_ARCH=8
endif
ifeq ($(WT_WOLFCRYPT_ARMASM),1)
ARCH_HSM_DEFS += -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO \
    -DWOLFSSL_ARMASM_INLINE -DWOLFSSL_ARMASM_NO_NEON \
    -DWOLFSSL_ARMASM_THUMB2
endif

ARCH_WOLFCRYPT_SP_SRCS := $(WOLFSSL_DIR)/wolfcrypt/src/sp_cortexm.c
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

# Isolation level the secure image implements. Only level 3 exists, so any
# other value stops the build; the shared level 3 layer is gated on it.
WT_ISOLATION_LEVEL ?= 3
ifneq ($(WT_ISOLATION_LEVEL),3)
$(error only isolation level 3 is implemented (WT_ISOLATION_LEVEL=$(WT_ISOLATION_LEVEL)))
endif
ARCH_CFLAGS += -DWT_ISOLATION_LEVEL=$(WT_ISOLATION_LEVEL)

ifeq ($(WT_ISOLATION_LEVEL),3)
# Isolation level 3 layer shared by every Armv8-M port: the band layout, its
# linker fragments and the platform hooks. A port's memory_map.h supplies
# WT_RAM_S_BASE, from which every band is placed.
PORT_COMMON_DIR := $(ROOT)/port/common/armv8m
PORT_HEADERS += $(wildcard $(PORT_COMMON_DIR)/*.h)
TARGET_EXTRA_SRCS += $(PORT_COMMON_DIR)/platform_l3.c
WT_RAM_S_ORIGIN := $(shell sed -n \
    's/^\#define WT_RAM_S_BASE[[:space:]]*\(0x[0-9A-Fa-f]*\)u.*/\1/p' \
    $(PORT_DIR)/memory_map.h)
ifeq ($(WT_RAM_S_ORIGIN),)
$(error $(PORT_DIR)/memory_map.h has no literal WT_RAM_S_BASE)
endif
TARGET_LDFLAGS += -Wl,-L$(PORT_COMMON_DIR) \
    -Wl,--defsym=WT_RAM_S_ORIGIN=$(WT_RAM_S_ORIGIN)
# Post-link band check inputs, read from the port's memory_map.h at link time;
# an unreadable layout stops the link rather than checking the default bands.
WT_L3_BAND_ARGS = $(shell python3 $(ROOT)/tools/l3_layout_args.py \
    --cc $(TOOLPREFIX)gcc $(PORT_DIR)/memory_map.h)
WT_SECURE_LAYOUT_ARGS = $(or $(strip $(WT_L3_BAND_ARGS)),$(error \
    cannot read the level 3 bands from $(PORT_DIR)/memory_map.h)) \
    $(WT_SECURE_LAYOUT_EXTRA_ARGS)
endif

# CMSE import library for the Non-secure guests, produced by the secure link.
SECURE_CMSE_IMPLIB := $(BUILD_DIR)/secure_cmse_implib.o
ARCH_LINK_OUTPUTS := $(SECURE_CMSE_IMPLIB)
ARCH_LDFLAGS := -Wl,--cmse-implib -Wl,--out-implib=$(SECURE_CMSE_IMPLIB)

# A changed post-link checker must relink so the image is checked again.
$(BUILD_DIR)/wolftrust.elf $(ARCH_LINK_OUTPUTS): \
    $(ROOT)/tools/check_no_fp_insn.py $(ROOT)/tools/check_stack_seal.py \
    $(ROOT)/tools/l3_layout_args.py $(wildcard $(PORT_COMMON_DIR)/*.ld)

# Whitelist of non-secure-callable veneers the linked secure image may
# export: exactly the five mediated FF-M gateway entries, pinned by full
# name so a renamed or added veneer fails the link in every build,
# CONFIG_VNET included (virtual networking rides SERVICE_VNET psa_call).
NSC_ALLOWED := __acle_se_WolfTrust_FFM_(FrameworkVersion|ServiceVersion|Connect|Call|Close)$$
NSC_COUNT := 5

# Post-link image checks run by the common link rule.
define arch_image_checks
	@$(TOOLPREFIX)nm $(SECURE_ELF) > $(BUILD_DIR)/nsc-syms.txt || \
		{ echo "FAIL: nm on the secure image failed" >&2; exit 1; }
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
		--map $(SECURE_MAP) --owners $(ROOT)/tools/secure_owners.txt \
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
