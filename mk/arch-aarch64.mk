# AArch64 architecture inputs for the secure image build. Included after
# mk/target-<soc>.mk and before mk/common.mk. Until the SPM runs at S-EL1 the
# default goal is the EL3 monitor image alone (libwt_el3.a + the S-EL1 stub).
TOOLPREFIX ?= aarch64-none-elf-
WT_CPU ?= cortex-a72
WT_GIC_VERSION ?= 3
AR := $(TOOLPREFIX)ar
CPU_FLAGS := -mcpu=$(WT_CPU) -mgeneral-regs-only -mstrict-align
ARCH_CFLAGS := -DWT_TARGET_BUILD=1 -DWT_GIC_VERSION=$(WT_GIC_VERSION)
WT_WOLFCRYPT_SP_ASM := 0
WT_WOLFCRYPT_ARMASM := 0
ARCH_HSM_DEFS :=
ARCH_WOLFCRYPT_SP_SRCS :=
ARCH_WOLFCRYPT_ASM_SRCS :=
ARCH_START_SRCS :=
ARCH_SRCS :=

ARCH_DIR := $(ROOT)/src/arch/aarch64
EL3_C_SRCS := \
    $(ARCH_DIR)/el3/console.c \
    $(ARCH_DIR)/el3/esr.c \
    $(ARCH_DIR)/el3/monitor_calls.c \
    $(ARCH_DIR)/el3/timer.c \
    $(ARCH_DIR)/el3/el3_main.c \
    $(ARCH_DIR)/ffa/ffa_spmd.c \
    $(ARCH_DIR)/gic/gicv$(WT_GIC_VERSION).c \
    $(ARCH_DIR)/common/libc_min.c \
    $(ARCH_DIR)/drivers/pl011.c \
    $(EL3_PORT_SRCS)
EL3_ASM_SRCS := \
    $(ARCH_DIR)/el3/start.S \
    $(ARCH_DIR)/el3/vectors.S
SPM_STUB_C_SRCS := $(ARCH_DIR)/spm/spm_main_stub.c
SPM_STUB_ASM_SRCS := $(ARCH_DIR)/spm/spm_entry.S
ARCH_TREE_SRCS := $(EL3_C_SRCS) $(SPM_STUB_C_SRCS)
ARCH_ASM_SRCS := $(EL3_ASM_SRCS) $(SPM_STUB_ASM_SRCS)

wt_arch_objs = $(foreach s,$(1),$(BUILD_DIR)/wt_sec_$(notdir $(basename $(s))).o)
EL3_ARCHIVE_OBJS := $(call wt_arch_objs,$(EL3_C_SRCS) $(EL3_ASM_SRCS))
EL3_STUB_OBJS := $(call wt_arch_objs,$(SPM_STUB_C_SRCS) $(SPM_STUB_ASM_SRCS))
EL3_LIB := $(BUILD_DIR)/libwt_el3.a
EL3_ELF := $(BUILD_DIR)/wolftrust_el3.elf
EL3_BIN := $(BUILD_DIR)/wolftrust_el3.bin
EL3_LD := $(ARCH_DIR)/el3/el3.ld

SECURE_CMSE_IMPLIB :=
ARCH_LINK_OUTPUTS :=
ARCH_LDFLAGS :=
define arch_image_checks
endef
ARCH_DEFAULT_GOALS := el3-image

.PHONY: el3-image
el3-image: $(EL3_BIN) $(EL3_ELF)
	@$(SIZE) $(EL3_ELF)

$(EL3_LIB): $(EL3_ARCHIVE_OBJS) | $(BUILD_DIR)
	rm -f $@
	$(AR) rcs $@ $(EL3_ARCHIVE_OBJS)

# WT-PORT-0012: the archive is linked whole and audited before the image exists.
$(EL3_ELF): $(EL3_LIB) $(EL3_STUB_OBJS) $(EL3_LD)
	$(CC) $(SECURE_CFLAGS) -nostartfiles -Wl,--build-id=none \
		$(TARGET_LDFLAGS) -Wl,-T$(EL3_LD) -Wl,--gc-sections \
		-o $@ $(EL3_STUB_OBJS) \
		-Wl,--whole-archive $(EL3_LIB) -Wl,--no-whole-archive -lgcc
	$(ROOT)/tools/check-el3-symbols.sh $(EL3_LIB) --nm $(TOOLPREFIX)nm

$(EL3_BIN): $(EL3_ELF)
	$(OBJCOPY) -O binary $< $@
