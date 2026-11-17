# The one resolved layout configuration. Every consumer of a port's memory
# map (the secure firmware, the linker script, the layout tools, the guests
# and the host fixtures) takes WT_LAYOUT_CFLAGS: defines and include paths
# only, no ISA flags, so a host compiler accepts it. Included right after
# mk/target-<soc>.mk, which gives every input its default.
ARCH ?= armv8m
PORT_NEUTRAL_DIR := $(ROOT)/port/common
PORT_COMMON_DIR := $(ROOT)/port/common/$(ARCH)
WT_ISOLATION_LEVEL ?= 3
WT_LD_RAM_CODE_BAND ?= 0

WT_LAYOUT_INPUTS := WT_SECURE_FLASH_BASE WT_SECURE_FLASH_SIZE \
    WT_SECURE_IMAGE_HEADER_SIZE WT_GUEST0_FLASH_BASE WT_GUEST1_FLASH_BASE \
    WT_GUEST0_FLASH_SIZE WT_GUEST1_FLASH_SIZE WT_SHARED_UART \
    WT_GUEST_CORE_CLOCK_HZ WT_GUEST_UART_CLOCK_HZ WT_CONF_IRQ \
    WT_CONF_IRQ_HANDLER WT_ISOLATION_LEVEL WT_LD_RAM_CODE_BAND
# Overrides of the shared level 3 bands; unset keeps l3_layout.h's defaults.
WT_LAYOUT_OPTIONAL_INPUTS := WT_L3_SPM_RAM_SIZE WT_SP_HSM_DATA_SIZE \
    WT_SP_VAULT_DATA_SIZE WT_SP_ATTEST_DATA_SIZE WT_SP_PS_STACK_SIZE \
    WT_SP_ITS_STACK_SIZE WT_SP_VAULT_STACK_SIZE WT_SP_CRYPTO_STACK_SIZE \
    WT_SP_ATTEST_STACK_SIZE WT_SP_FWU_STACK_SIZE_RESERVED
# The Cortex-M assembly P-256 verify peaks at 7,240 bytes on the native crypto
# stack. Parsed before mk/arch-armv8m.mk, so only a set WT_WOLFCRYPT_SP_ASM counts.
ifeq ($(filter 1,$(WT_WOLFCRYPT_SP_ASM))/$(filter hsm,$(WT_ENGINE))$(filter 1,$(WT_ENGINE_HSM)),1/)
WT_SP_CRYPTO_STACK_SIZE ?= 0x00002400u
endif

$(foreach v,$(WT_LAYOUT_INPUTS),$(if $(strip $($(v))),,$(error \
    mk/target-$(TARGET).mk gives $(v) no default)))

# Layout inputs reach the compiler through these variables only, so the
# stamp, the tools and the firmware can never see different values.
ifneq ($(filter -D -U,$(WT_EXTRA_CFLAGS)),)
$(error write WT_EXTRA_CFLAGS defines as -DNAME[=value]: a split -D could \
    carry a layout input that must be a make variable)
endif
WT_LAYOUT_EXTRA_DEFS := $(filter $(foreach \
    v,$(WT_LAYOUT_INPUTS) $(WT_LAYOUT_OPTIONAL_INPUTS),-D$(v) -D$(v)=% -U$(v)),\
    $(WT_EXTRA_CFLAGS))
ifneq ($(WT_LAYOUT_EXTRA_DEFS),)
$(error set $(patsubst -U%,%,$(patsubst -D%,%,$(firstword \
    $(WT_LAYOUT_EXTRA_DEFS)))) as a make \
    variable, not as a WT_EXTRA_CFLAGS define)
endif

WT_LAYOUT_DEFS := \
    -DWT_ISOLATION_LEVEL=$(WT_ISOLATION_LEVEL) \
    -DWT_SHARED_UART=$(WT_SHARED_UART) \
    -DWT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ) \
    -DWT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ) \
    -DWT_CONF_IRQ=$(WT_CONF_IRQ)u \
    -DWT_CONF_IRQ_HANDLER=$(WT_CONF_IRQ_HANDLER) \
    -DWT_SECURE_FLASH_BASE=$(WT_SECURE_FLASH_BASE) \
    -DWT_SECURE_FLASH_SIZE=$(WT_SECURE_FLASH_SIZE) \
    -DWT_SECURE_IMAGE_HEADER_SIZE=$(WT_SECURE_IMAGE_HEADER_SIZE) \
    -DWT_GUEST0_FLASH_BASE=$(WT_GUEST0_FLASH_BASE) \
    -DWT_GUEST1_FLASH_BASE=$(WT_GUEST1_FLASH_BASE) \
    -DWT_GUEST0_FLASH_SIZE=$(WT_GUEST0_FLASH_SIZE) \
    -DWT_GUEST1_FLASH_SIZE=$(WT_GUEST1_FLASH_SIZE)
# A Secure PSA crypto band holds the wolfPSA pool plus about 1.4 KB of slot
# tables and service state; wolfPSA needs the larger stack for ECDSA.
ifeq ($(WT_SECURE_PSA),1)
WT_SP_HSM_DATA_SIZE ?= $(shell echo $$(( ($(or $(WT_PSA_POOL_BYTES),6144) + \
    2048 + 31) / 32 * 32 )) 2>/dev/null)
WT_SP_CRYPTO_STACK_SIZE ?= 0x2000
endif
WT_LAYOUT_DEFS += $(foreach v,$(WT_LAYOUT_OPTIONAL_INPUTS),\
    $(if $(strip $($(v))),-D$(v)=$($(v))))
# The bands a build mode adds or resizes: the update stack (WT_FWU), the
# conformance window and stacks, the VNET band, and the engine-sized crypto
# stack and data band.
WT_LAYOUT_DEFS += $(if $(filter 1,$(WT_FWU)),-DWT_FWU=1) \
    $(if $(filter 1,$(WT_CONFORMANCE)),-DWT_CONFORMANCE=1) \
    $(if $(filter y,$(CONFIG_VNET)),-DCONFIG_VNET=1) \
    $(if $(or $(filter hsm,$(WT_ENGINE)),$(filter 1,$(WT_ENGINE_HSM))),\
        -DWT_ENGINE_HSM=1,-DWT_ENGINE_NATIVE=1)
WT_LAYOUT_INCLUDE_DIRS := $(ROOT)/include $(PORT_DIR) $(PORT_COMMON_DIR) \
    $(PORT_NEUTRAL_DIR)
WT_LAYOUT_CFLAGS := $(strip $(WT_LAYOUT_DEFS) \
    $(addprefix -I,$(WT_LAYOUT_INCLUDE_DIRS)))
# The same configuration for a consumer outside this directory.
WT_LAYOUT_CFLAGS_ABS := $(strip $(WT_LAYOUT_DEFS) \
    $(addprefix -I,$(abspath $(WT_LAYOUT_INCLUDE_DIRS))))

# Secure image placement for the linker, the same values the firmware sees.
WT_LAYOUT_LDFLAGS := \
    -Wl,--defsym=WT_SECURE_FLASH_ORIGIN=$(WT_SECURE_FLASH_BASE) \
    -Wl,--defsym=WT_SECURE_FLASH_SIZE=$(WT_SECURE_FLASH_SIZE) \
    -Wl,--defsym=WT_SECURE_IMAGE_HEADER_SIZE=$(WT_SECURE_IMAGE_HEADER_SIZE)

# The system manifest is rendered from the shared template under exactly
# this configuration (tools/manifest/render.py); a variant adds its overlay.
WT_MANIFEST_TEMPLATE := $(ROOT)/manifest/base.json
WT_MANIFEST_RENDER = python3 $(ROOT)/tools/manifest/render.py \
    --cc $(WT_LAYOUT_CPP) --cflags '$(WT_LAYOUT_CFLAGS)'
WT_MANIFEST_RENDER_DEPS = $(ROOT)/tools/manifest/render.py \
    $(WT_MANIFEST_TEMPLATE) $(PORT_HEADERS)

# Non-secure guest windows, read from the port's memory_map.h under exactly
# this configuration; a guest build takes them instead of copying numbers.
WT_LAYOUT_TOOL := python3 $(ROOT)/tools/l3_layout_args.py
WT_LAYOUT_GUEST_WINDOWS = $(or $(strip $(shell $(WT_LAYOUT_TOOL) --guest \
    --cc $(WT_LAYOUT_CPP) --cflags '$(WT_LAYOUT_CFLAGS)' \
    $(PORT_DIR)/memory_map.h)),$(error \
    cannot read the guest windows from $(PORT_DIR)/memory_map.h))
WT_LAYOUT_CPP ?= $(TOOLPREFIX)gcc
