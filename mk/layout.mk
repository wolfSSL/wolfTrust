# The one resolved layout configuration. Every consumer of a port's memory
# map (the secure firmware, the linker script, the layout tools, the guests
# and the host fixtures) takes WT_LAYOUT_CFLAGS: defines and include paths
# only, no ISA flags, so a host compiler accepts it. Included right after
# mk/target-<soc>.mk, which gives every input its default.
ARCH ?= armv8m
PORT_COMMON_DIR := $(ROOT)/port/common/$(ARCH)
WT_ISOLATION_LEVEL ?= 3
WT_LD_RAM_CODE_BAND ?= 0

WT_LAYOUT_INPUTS := WT_SECURE_FLASH_BASE WT_SECURE_FLASH_SIZE \
    WT_SECURE_IMAGE_HEADER_SIZE WT_GUEST0_FLASH_BASE WT_GUEST1_FLASH_BASE \
    WT_GUEST0_FLASH_SIZE WT_GUEST1_FLASH_SIZE WT_SHARED_UART \
    WT_GUEST_CORE_CLOCK_HZ WT_GUEST_UART_CLOCK_HZ WT_CONF_IRQ \
    WT_CONF_IRQ_HANDLER WT_ISOLATION_LEVEL WT_LD_RAM_CODE_BAND
# Overrides of the shared level 3 bands; unset keeps l3_layout.h's defaults.
WT_LAYOUT_OPTIONAL_INPUTS := WT_L3_SPM_RAM_SIZE WT_SP_HSM_DATA_SIZE

$(foreach v,$(WT_LAYOUT_INPUTS),$(if $(strip $($(v))),,$(error \
    mk/target-$(TARGET).mk gives $(v) no default)))

# Layout inputs reach the compiler through these variables only, so the
# stamp, the tools and the firmware can never see different values.
WT_LAYOUT_EXTRA_DEFS := $(filter $(foreach \
    v,$(WT_LAYOUT_INPUTS) $(WT_LAYOUT_OPTIONAL_INPUTS),-D$(v) -D$(v)=%),\
    $(WT_EXTRA_CFLAGS))
ifneq ($(WT_LAYOUT_EXTRA_DEFS),)
$(error set $(patsubst -D%,%,$(firstword $(WT_LAYOUT_EXTRA_DEFS))) as a make \
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
WT_LAYOUT_DEFS += $(foreach v,$(WT_LAYOUT_OPTIONAL_INPUTS),\
    $(if $(strip $($(v))),-D$(v)=$($(v))))
WT_LAYOUT_INCLUDE_DIRS := $(ROOT)/include $(PORT_DIR) $(PORT_COMMON_DIR)
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
