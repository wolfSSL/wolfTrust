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

# A changed post-link checker must relink so the image is checked again.
$(BUILD_DIR)/wolftrust.elf $(ARCH_LINK_OUTPUTS): \
    $(ROOT)/tools/check_no_fp_insn.py $(ROOT)/tools/check_stack_seal.py

# Whitelist of non-secure-callable veneers the linked secure image may
# export: exactly the five mediated FF-M gateway entries, pinned by full
# name so a renamed or added veneer fails the link in every build,
# CONFIG_VNET included (virtual networking rides SERVICE_VNET psa_call).
NSC_ALLOWED := __acle_se_WolfTrust_FFM_(FrameworkVersion|ServiceVersion|Connect|Call|Close)$$
NSC_COUNT := 5
WT_INTERFACE_BODY := $(if $(filter y,$(CONFIG_TPM)),FWTPM_ProcessCommand,\
    $(if $(filter y,$(CONFIG_PKCS11)),wt_pkcs11_provider_dispatch))

# Post-link image checks run by the common link rule.
define arch_image_checks
	@$(TOOLPREFIX)nm $(SECURE_ELF) > $(BUILD_DIR)/nsc-syms.txt || \
		{ echo "FAIL: nm on the secure image failed" >&2; exit 1; }
	@if grep -Eq ' (vTaskStartScheduler|xTaskCreate|pvPortMalloc|vPortFree)$$' \
            $(BUILD_DIR)/nsc-syms.txt; then \
        echo "FAIL: interface handler links an RTOS runtime" >&2; exit 1; \
    fi
	@if test -n "$(strip $(WT_INTERFACE_BODY))" && \
            ! grep -Eq ' [TW] $(strip $(WT_INTERFACE_BODY))$$' $(BUILD_DIR)/nsc-syms.txt; then \
        echo "FAIL: selected interface handler is absent from wolfTrust" >&2; exit 1; \
    fi
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

ifneq ($(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),)
ifeq ($(TARGET),stm32h563)
WT_SECURE_LAYOUT_ARGS += --tpm-band 0x30065000:0x30071000 \
    --pkcs11-band 0x30065000:0x30071000
else ifeq ($(TARGET),mimxrt700)
WT_SECURE_LAYOUT_ARGS += --tpm-band 0x301C5000:0x301D1000 \
    --pkcs11-band 0x301C5000:0x301D1000
endif
endif
