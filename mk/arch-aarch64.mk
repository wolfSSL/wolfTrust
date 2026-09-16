# AArch64 architecture inputs. Included after mk/target-<soc>.mk and before
# mk/common.mk. Two products: the EL3 monitor (libwt_el3.a linked whole into
# wolftrust_el3.elf) and the S-EL1 SPMC image (wolftrust.elf: the neutral core,
# the services, wolfCrypt/wolfHSM, the S-EL1 arch layer, and the port).
TOOLPREFIX ?= aarch64-none-elf-
WT_CPU ?= cortex-a72
WT_GIC_VERSION ?= 3
AR := $(TOOLPREFIX)ar
CPU_FLAGS := -mcpu=$(WT_CPU) -mgeneral-regs-only -mstrict-align
ARCH_CFLAGS := -DWT_TARGET_BUILD=1 -DWT_GIC_VERSION=$(WT_GIC_VERSION)
WT_WOLFCRYPT_SP_ASM := 0
WT_WOLFCRYPT_ARMASM := 0
# 64-bit SP math words, C implementation (no WOLFSSL_SP_ARM64_ASM).
ARCH_HSM_DEFS := -DWOLFSSL_SP_ARM64 -DHAVE___UINT128_T=1
ARCH_WOLFCRYPT_SP_SRCS := $(WOLFSSL_DIR)/wolfcrypt/src/sp_c64.c
ARCH_WOLFCRYPT_ASM_SRCS :=
# RAM-backed NVM until the QEMU ports have a flash controller model.
ARCH_WOLFHSM_SRCS := $(WOLFHSM_DIR)/src/wh_flash_ramsim.c
ARCH_START_SRCS :=
ARCH_SRCS :=
WT_SPM_TABLE_PAGES ?= 8
MANIFEST_ARCH_OPTS := --address-bits 64 --mpu-granule 4096 \
    --spm-table-pages $(WT_SPM_TABLE_PAGES)

ARCH_DIR := $(ROOT)/src/arch/aarch64
ARCH_SHARED_C_SRCS := \
    $(ARCH_DIR)/el3/console.c \
    $(ARCH_DIR)/el3/timer.c \
    $(ARCH_DIR)/ffa/ffa_boot_info.c \
    $(ARCH_DIR)/gic/gicv$(WT_GIC_VERSION).c \
    $(ARCH_DIR)/drivers/pl011.c \
    $(EL3_PORT_SRCS)
EL3_C_SRCS := \
    $(ARCH_SHARED_C_SRCS) \
    $(ARCH_DIR)/el3/esr.c \
    $(ARCH_DIR)/el3/monitor_calls.c \
    $(ARCH_DIR)/el3/el3_main.c \
    $(ARCH_DIR)/el3/world.c \
    $(ARCH_DIR)/el3/psci.c \
    $(ARCH_DIR)/ffa/ffa_spmd.c \
    $(ARCH_DIR)/ffa/ffa_msg.c \
    $(ARCH_DIR)/common/libc_min.c
EL3_ASM_SRCS := \
    $(ARCH_DIR)/el3/start.S \
    $(ARCH_DIR)/el3/vectors.S
SPM_C_SRCS := \
    $(ARCH_SHARED_C_SRCS) \
    $(ARCH_DIR)/spm/spm_main.c \
    $(ARCH_DIR)/spm/tables.c \
    $(ARCH_DIR)/spm/domain.c \
    $(ARCH_DIR)/spm/spm_irq.c \
    $(ARCH_DIR)/spm/platform_arch.c \
    $(ARCH_DIR)/spm/coroutine_aarch64.c \
    $(ARCH_DIR)/spm/sp_trap.c \
    $(ARCH_DIR)/spm/spm_svc_glue.c \
    $(ARCH_DIR)/ffa/ffa_msg.c \
    $(ARCH_DIR)/ffa/ffa_partinfo.c \
    $(ARCH_DIR)/el3/esr.c
SPM_ASM_SRCS := $(ARCH_DIR)/spm/spm_entry.S $(ARCH_DIR)/spm/mmu.S \
    $(ARCH_DIR)/spm/spm_switch.S $(ARCH_DIR)/spm/sp_entry.S
ARCH_TREE_SRCS := $(sort $(EL3_C_SRCS) $(SPM_C_SRCS))
ARCH_ASM_SRCS := $(EL3_ASM_SRCS) $(SPM_ASM_SRCS)

wt_arch_objs = $(foreach s,$(1),$(BUILD_DIR)/wt_sec_$(notdir $(basename $(s))).o)
EL3_ARCHIVE_OBJS := $(call wt_arch_objs,$(EL3_C_SRCS) $(EL3_ASM_SRCS))
ARCH_SECURE_OBJS := $(call wt_arch_objs,$(SPM_C_SRCS) $(SPM_ASM_SRCS))
EL3_LIB := $(BUILD_DIR)/libwt_el3.a
EL3_ELF := $(BUILD_DIR)/wolftrust_el3.elf
EL3_BIN := $(BUILD_DIR)/wolftrust_el3.bin
EL3_LD := $(ARCH_DIR)/el3/el3.ld

SECURE_CMSE_IMPLIB :=
ARCH_LINK_OUTPUTS :=
# The core is not entered yet; keep it linked so the closure is proven.
ARCH_LDFLAGS := -Wl,--undefined=wt_boot_run
define arch_image_checks
endef
ARCH_DEFAULT_GOALS := el3-image secure-image

.PHONY: el3-image
el3-image: $(EL3_BIN) $(EL3_ELF)
	@$(SIZE) $(EL3_ELF)

$(EL3_LIB): $(EL3_ARCHIVE_OBJS) | $(BUILD_DIR)
	rm -f $@
	$(AR) rcs $@ $(EL3_ARCHIVE_OBJS)

# WT-PORT-0012: the archive is linked whole and audited before the image exists.
$(EL3_ELF): $(EL3_LIB) $(EL3_LD)
	$(CC) $(SECURE_CFLAGS) -nostartfiles -Wl,--build-id=none \
		$(TARGET_LDFLAGS) -Wl,-T$(EL3_LD) -Wl,--gc-sections \
		-o $@ -Wl,--whole-archive $(EL3_LIB) -Wl,--no-whole-archive -lgcc
	$(ROOT)/tools/check-el3-symbols.sh $(EL3_LIB) --nm $(TOOLPREFIX)nm

$(EL3_BIN): $(EL3_ELF)
	$(OBJCOPY) -O binary $< $@
