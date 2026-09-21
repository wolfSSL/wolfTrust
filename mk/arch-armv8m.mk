# Armv8-M architecture inputs for the secure image build. Included after
# mk/target-<soc>.mk and before mk/common.mk.
TOOLPREFIX ?= arm-none-eabi-
CPU_FLAGS := -mcpu=$(WT_CPU) -mthumb -mgeneral-regs-only
ARCH_CFLAGS := -mcmse -DWT_TARGET_BUILD=1
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

# CMSE import library for the Non-secure guests, produced by the secure link.
SECURE_CMSE_IMPLIB := $(BUILD_DIR)/secure_cmse_implib.o
ARCH_LINK_OUTPUTS := $(SECURE_CMSE_IMPLIB)
ARCH_LDFLAGS := -Wl,--cmse-implib -Wl,--out-implib=$(SECURE_CMSE_IMPLIB)

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
	@if grep -E ' (malloc|free|calloc|realloc|_sbrk|_malloc_r|_free_r)$$' \
			$(BUILD_DIR)/nsc-syms.txt; then \
		echo "FAIL: heap allocator symbol in the zero-heap secure image" >&2; \
		exit 1; \
	fi
endef
