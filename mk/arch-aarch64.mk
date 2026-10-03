# AArch64 architecture inputs. Included after mk/target-<soc>.mk and before
# mk/common.mk. Two products: the EL3 monitor (libwt_el3.a linked whole into
# wolftrust_el3.elf) and the S-EL1 SPMC image (wolftrust.elf: the neutral core,
# the services, wolfCrypt/wolfHSM, the S-EL1 arch layer, and the port).
TOOLPREFIX ?= aarch64-none-elf-
WT_CPU ?= cortex-a72
WT_GIC_VERSION ?= 3
AR := $(TOOLPREFIX)ar
# wolftrust.ld and the EL3 guard select objects by name, which LTO renames.
WT_LTO ?= 0
ifneq ($(WT_LTO),0)
$(error WT_LTO=$(WT_LTO) is unsupported on AArch64 (want 0))
endif
CPU_FLAGS := -mcpu=$(WT_CPU) -mgeneral-regs-only -mstrict-align
ARCH_CFLAGS := -DWT_TARGET_BUILD=1 -DWT_GIC_VERSION=$(WT_GIC_VERSION)
# Enter the Normal world at EL2 instead of EL1 (a boot loader or an EL2 payload).
WT_EL3_NS_EL2 ?= 0
ifeq ($(WT_EL3_NS_EL2),1)
ARCH_CFLAGS += -DWT_EL3_NS_EL2=1
endif
# Test only: the monitor starts on EL2 state an earlier stage left dirty.
# Isolation level gate: only level 3 is implemented, so any other level stops
# the build rather than linking an image without the level 3 layer.
WT_ISOLATION_LEVEL ?= 3
ifneq ($(WT_ISOLATION_LEVEL),3)
$(error only isolation level 3 is implemented (WT_ISOLATION_LEVEL=$(WT_ISOLATION_LEVEL)))
endif
ARCH_CFLAGS += -DWT_ISOLATION_LEVEL=$(WT_ISOLATION_LEVEL)

# Level 3 layer shared by every AArch64 port: the board's memory_map.h names
# WT_L3_BAND_BASE and port/common/aarch64/l3_layout.h places every Secure band
# from it; the build reads them back, and an unreadable layout stops it.
PORT_COMMON_DIR := $(ROOT)/port/common/aarch64
PORT_HEADERS += $(wildcard $(PORT_COMMON_DIR)/*.h)
# A band overridden on the command line reaches the tool too, so the compiler,
# the linker and the manifest check all see the same layout.
WT_L3_OVERRIDABLE := WT_SPM_BOOT_INFO_PA WT_SPM_TABLE_POOL_PA WT_SPM_IMAGE_PA \
    WT_SPM_IMAGE_SIZE WT_SPM_RAM_PA WT_SPM_RAM_SIZE WT_SPM_CONFDATA_PA \
    WT_SPM_CONFDATA_SIZE WT_SPM_KEYSTORE_PA WT_SPM_KEYSTORE_SIZE \
    WT_SPM_RXTX_PA WT_SPM_RXTX_SIZE WT_SPM_SHARE_PA WT_SPM_SHARE_SIZE
WT_L3_TOOL := python3 $(ROOT)/tools/aarch64_l3_layout.py \
    --cc $(TOOLPREFIX)gcc -I$(PORT_COMMON_DIR) \
    -DWT_ISOLATION_LEVEL=$(WT_ISOLATION_LEVEL) \
    $(foreach v,$(WT_L3_OVERRIDABLE),$(if $(filter command \
    line,$(origin $(v))),-D$(v)=$($(v))u))
WT_L3_LAYOUT := $(shell $(WT_L3_TOOL) --shell $(PORT_DIR)/memory_map.h)
ifeq ($(strip $(WT_L3_LAYOUT)),)
$(error cannot read the level 3 layout from $(PORT_DIR)/memory_map.h)
endif
$(foreach kv,$(WT_L3_LAYOUT),$(eval $(kv)))
WT_SPM_TABLE_POOL_PAGES ?= 128
ifeq ($(WT_EL3_TEST_HANDOFF),1)
TARGET_CFLAGS += -DWT_PORT_HANDOFF_PA=$(WT_L3_HANDOFF_PA)u
endif
ifeq ($(WT_FFA_ACS),1)
TARGET_CFLAGS += -DWT_FFA_ACS_BASE=$(WT_L3_FFA_ACS_PA)u
endif
WT_L3_CFLAGS := $(foreach v,WT_SPM_BOOT_INFO_PA WT_SPM_TABLE_POOL_PA \
    WT_SPM_IMAGE_PA WT_SPM_IMAGE_SIZE WT_SPM_RAM_PA WT_SPM_RAM_SIZE \
    WT_SPM_KEYSTORE_PA WT_SPM_KEYSTORE_SIZE WT_SPM_RXTX_PA WT_SPM_RXTX_SIZE \
    WT_SPM_SHARE_PA WT_SPM_SHARE_SIZE WT_SPM_CONFDATA_PA \
    WT_SPM_CONFDATA_SIZE,-D$(v)=$($(v))u) \
    -DWT_SPM_TABLE_POOL_PAGES=$(WT_SPM_TABLE_POOL_PAGES)u -I$(PORT_COMMON_DIR)
WT_L3_LDFLAGS := $(foreach v,WT_SPM_IMAGE_PA WT_SPM_IMAGE_SIZE \
    WT_SPM_RAM_PA WT_SPM_RAM_SIZE WT_SPM_KEYSTORE_PA WT_SPM_KEYSTORE_SIZE \
    WT_SPM_VAULT_PA WT_SPM_VAULT_SIZE WT_SPM_ATTEST_PA WT_SPM_ATTEST_SIZE \
    WT_SPM_HSMDATA_PA WT_SPM_HSMDATA_SIZE WT_SPM_CONFDATA_PA \
    WT_SPM_CONFDATA_SIZE,-Wl,--defsym=$(v)=$($(v)))
TARGET_CFLAGS += $(WT_L3_CFLAGS)
TARGET_LDFLAGS += $(WT_L3_LDFLAGS)
TARGET_EXTRA_SRCS += $(PORT_COMMON_DIR)/platform_l3.c

WT_FP_NEG_PROBE ?= 0
ifeq ($(WT_FP_NEG_PROBE),1)
ARCH_CFLAGS += -DWT_FP_NEG_PROBE=1
endif

WT_MSP_OVF_PROBE ?= 0
ifeq ($(WT_MSP_OVF_PROBE),1)
ARCH_CFLAGS += -DWT_MSP_OVF_PROBE=1
endif

WT_XN_NEG_PROBE ?= 0
ifeq ($(WT_XN_NEG_PROBE),1)
ARCH_CFLAGS += -DWT_XN_NEG_PROBE=1
endif

WT_EL3_EL2_DIRTY_PROBE ?= 0
ifeq ($(WT_EL3_EL2_DIRTY_PROBE),1)
ARCH_CFLAGS += -DWT_EL3_EL2_DIRTY_PROBE=1
endif
# Test only: an earlier stage left every GICv3 SPI routed to an absent PE.
WT_GIC_SPI_ROUTE_PROBE ?= 0
ifeq ($(WT_GIC_SPI_ROUTE_PROBE),1)
ARCH_CFLAGS += -DWT_GIC_SPI_ROUTE_PROBE=1
endif
# Test only: the monitor sees its redistributor asleep (1) or never gets its
# secure tick (2), or an SPMC boot self-test fails (3), and the boot must stop.
WT_EL3_BOOT_NEG_PROBE ?= 0
ifneq ($(WT_EL3_BOOT_NEG_PROBE),0)
ARCH_CFLAGS += -DWT_EL3_BOOT_NEG_PROBE=$(WT_EL3_BOOT_NEG_PROBE)
endif
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
    $(ARCH_DIR)/ffa/ffa_mem.c \
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
    $(ARCH_DIR)/spm/psa_service.c \
    $(ARCH_DIR)/spm/spm_mem.c \
    $(ARCH_DIR)/ffa/ffa_msg.c \
    $(ARCH_DIR)/ffa/ffa_mem.c \
    $(ARCH_DIR)/ffa/ffa_notif.c \
    $(ARCH_DIR)/ffa/ffa_partinfo.c \
    $(ARCH_DIR)/ffa/ffa_runtime.c \
    $(ARCH_DIR)/el3/esr.c
# The conformance image adds the privileged NVM/interrupt backend the SVC gate
# calls for the unprivileged DRIVER partition (WT_CONFORMANCE is a command-line
# override, so it is already set here before mk/common.mk seats its default).
ifeq ($(WT_CONFORMANCE),1)
SPM_C_SRCS += $(ROOT)/port/common/aarch64/conf_backend.c
endif
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
# The manifest must grant exactly the keystore bands the shared layout places.
define arch_image_checks
	$(WT_L3_TOOL) --check-manifest $(MANIFEST_INPUT) $(PORT_DIR)/memory_map.h \
		|| { rm -f $(SECURE_ELF); exit 1; }
endef
$(BUILD_DIR)/wolftrust.elf: $(ROOT)/tools/aarch64_l3_layout.py \
    $(PORT_COMMON_DIR)/l3_layout.h $(MANIFEST_INPUT)
ARCH_DEFAULT_GOALS := el3-image secure-image

.PHONY: el3-image
el3-image: $(EL3_BIN) $(EL3_ELF)
	@$(SIZE) $(EL3_ELF)

$(EL3_LIB): $(EL3_ARCHIVE_OBJS) | $(BUILD_DIR)
	rm -f $@
	$(AR) rcs $@ $(EL3_ARCHIVE_OBJS)

# WT-PORT-0012: the archive is audited, then linked whole. A policy change
# re-audits, and a failed audit leaves no image, stale or new, behind.
EL3_AUDIT := $(ROOT)/tools/check-el3-symbols.sh $(ROOT)/tools/el3-symbols.allow \
    $(ROOT)/tools/el3-defines.allow
$(EL3_ELF): $(EL3_LIB) $(EL3_LD) $(EL3_AUDIT)
	rm -f $@ $(EL3_BIN)
	$(ROOT)/tools/check-el3-symbols.sh $(EL3_LIB) --nm $(TOOLPREFIX)nm
	$(CC) $(SECURE_CFLAGS) -nostartfiles -Wl,--build-id=none \
		$(TARGET_LDFLAGS) -Wl,-T$(EL3_LD) -Wl,--gc-sections \
		-o $@ -Wl,--whole-archive $(EL3_LIB) -Wl,--no-whole-archive -lgcc

$(EL3_BIN): $(EL3_ELF)
	$(OBJCOPY) -O binary $< $@
