# Bare-metal Non-secure guests for every registered port. Builds the wolfTrust
# Secure image (and its CMSE import library) through the top-level Makefile,
# then links guest0 and guest1 against that import library so the
# WolfTrust_FFM_* veneers resolve. The board seams (console, probe addresses)
# come from tests/firmware/boards/$(TARGET); image assembly and the boot are
# driven by the emulator and hardware runners under tests/target.
TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size

ROOT := ../../..
TARGET ?= mcxn947
ARCH ?= armv8m

BUILD ?= build
# The Secure image's build directory, relative to the repository root; the
# hardware runner points both at its own tree so an emulator run can share
# the checkout.
WT_BUILD_DIR ?= build
TOP_BUILD_DIR := $(ROOT)/$(WT_BUILD_DIR)
SECURE_CMSE_IMPLIB := $(TOP_BUILD_DIR)/secure_cmse_implib.o
BOARD_DIR := $(ROOT)/tests/firmware/boards/$(TARGET)

# The same guest links into both Non-secure windows, read from the port's
# memory map under the Secure image's layout configuration; the monitor
# refuses to start unless every configured guest has an image.
include $(ROOT)/mk/profile.mk
include $(ROOT)/mk/target-$(TARGET).mk
include $(ROOT)/mk/layout.mk
$(foreach kv,$(WT_LAYOUT_GUEST_WINDOWS),$(eval $(kv)))
include $(BOARD_DIR)/board.mk

CFLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only -ffreestanding \
    -fno-builtin -nostdlib -Os -g -Wall -Wextra \
    -ffunction-sections -fdata-sections -mno-unaligned-access \
    -I$(ROOT)/include -I$(BOARD_DIR) \
    -DGUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ)

GUEST0_CFLAGS := -DGUEST_NAME=\"guest0\"
GUEST1_CFLAGS := -DGUEST_NAME=\"guest1\"
# WT_ISO_PROBE=1 builds guest0's isolation probe: it stores into guest1's RAM
# window, which the per-dispatch fabric window keeps Secure while guest0 runs.
# guest1 carries no probe; it is the peer that must keep running. The former
# per-port names WT_AHBSC_PROBE and WT_SAU_PROBE still select it.
WT_AHBSC_PROBE ?= 0
WT_SAU_PROBE ?= 0
WT_ISO_PROBE ?= $(if $(filter 1,$(WT_AHBSC_PROBE) $(WT_SAU_PROBE)),1,0)
ifeq ($(WT_ISO_PROBE),1)
GUEST0_CFLAGS += -DWT_ISO_PROBE -DGUEST_ISO_PROBE_ADDR=$(GUEST_ISO_PROBE_ADDR) \
    -DGUEST_PROBE_VALUE=0xDEADBEEFu
endif
# WT_PERIPH_NEG_PROBE=1 makes guest0, its MPU off, reach the SPM's peripheral
# through the Non-secure alias (board.h); the fabric must refuse it on every
# launch (periphneg).
WT_PERIPH_NEG_PROBE ?= 0
ifeq ($(WT_PERIPH_NEG_PROBE),1)
GUEST0_CFLAGS += -DWT_PERIPH_NEG_PROBE
endif
# WT_GUEST_FAULT_PROBE=1 makes guest0 read Secure RAM on every launch, so the
# monitor spends its restart budget and quarantines it (restart).
WT_GUEST_FAULT_PROBE ?= 0
ifeq ($(WT_GUEST_FAULT_PROBE),1)
GUEST0_CFLAGS += -DWT_GUEST_FAULT_PROBE
endif
# WT_HANDLER_OVERRUN_PROBE=1 makes guest0 enter a Non-secure handler that
# never returns on every launch, so the monitor restarts it (handlerneg).
WT_HANDLER_OVERRUN_PROBE ?= 0
ifeq ($(WT_HANDLER_OVERRUN_PROBE),1)
GUEST0_CFLAGS += -DWT_HANDLER_OVERRUN_PROBE
endif
# WT_HANDLER_IRQ_PROBE=<irq> parks guest0 in that external IRQ's handler on
# every launch, and guest1 keeps taking its own PendSV (handlerirqneg).
WT_HANDLER_IRQ_PROBE ?= 0
ifneq ($(filter-out 0,$(WT_HANDLER_IRQ_PROBE)),)
GUEST0_CFLAGS += -DWT_HANDLER_IRQ_PROBE=$(WT_HANDLER_IRQ_PROBE)
GUEST1_CFLAGS += -DWT_PEER_IRQ_PROBE
endif
# WT_NS_ENTRY_MASK_PROBE=1 makes guest0 call FF-M from a Non-secure SysTick
# that comes due during an FF-M entry (hardware nsentrymask).
WT_NS_ENTRY_MASK_PROBE ?= 0
ifeq ($(WT_NS_ENTRY_MASK_PROBE),1)
GUEST0_CFLAGS += -DWT_NS_ENTRY_MASK_PROBE
endif

CLIENT_OBJ := $(BUILD)/psa_ffm_client.o
BOARD_NAMES := $(notdir $(GUEST_BOARD_SRCS))
GUEST0_BOARD_OBJS := $(patsubst %.c,$(BUILD)/g0_%.o,$(BOARD_NAMES))
GUEST1_BOARD_OBJS := $(patsubst %.c,$(BUILD)/g1_%.o,$(BOARD_NAMES))

vpath %.c $(BOARD_DIR)

all: $(BUILD)/guest0.bin $(BUILD)/guest1.bin

# One build directory serves every port: a change of target, layout or probe
# flags rebuilds every object, which make alone would keep from another board.
CONFIG_ID := $(TARGET) $(ARCH) $(WT_BUILD_DIR) $(WT_LAYOUT_GUEST_WINDOWS) \
    $(CFLAGS) $(GUEST0_CFLAGS) $(GUEST1_CFLAGS)
CONFIG_STAMP := $(BUILD)/config.stamp
$(CONFIG_STAMP): FORCE | $(BUILD)
	@printf '%s\n' '$(CONFIG_ID)' | cmp -s - $@ 2>/dev/null || printf '%s\n' '$(CONFIG_ID)' > $@

# The image's build mode comes from the environment; forcing one here would
# relink the image in another mode and drop the wolftrust.bin the runners sign.
$(SECURE_CMSE_IMPLIB): FORCE
	$(MAKE) -C $(ROOT) ARCH=$(ARCH) TARGET=$(TARGET) TOOLPREFIX=$(TOOLPREFIX) \
	    BUILD_DIR=$(WT_BUILD_DIR) $(WT_BUILD_DIR)/secure_cmse_implib.o

$(BUILD)/guest0.o: guest.c $(BOARD_DIR)/board.h $(BOARD_DIR)/board.mk $(CONFIG_STAMP) | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST0_CFLAGS) -c -o $@ $<

$(BUILD)/guest1.o: guest.c $(BOARD_DIR)/board.h $(BOARD_DIR)/board.mk $(CONFIG_STAMP) | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST1_CFLAGS) -c -o $@ $<

$(BUILD)/g0_%.o: %.c $(BOARD_DIR)/board.h $(BOARD_DIR)/board.mk $(CONFIG_STAMP) | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST0_CFLAGS) -c -o $@ $<

$(BUILD)/g1_%.o: %.c $(BOARD_DIR)/board.h $(BOARD_DIR)/board.mk $(CONFIG_STAMP) | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST1_CFLAGS) -c -o $@ $<

$(BUILD)/psa_ffm_client.o: $(ROOT)/src/client/psa_ffm_client.c $(CONFIG_STAMP) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

define link_guest
	$(CC) $(CFLAGS) \
	    -Wl,-Tguest.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(1) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(2) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(3) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(4) \
	    -Wl,--gc-sections \
	    -o $@ $(5) $(CLIENT_OBJ) $(SECURE_CMSE_IMPLIB) -lgcc
	$(SIZE) $@
endef

$(BUILD)/guest0.elf: $(BUILD)/guest0.o $(GUEST0_BOARD_OBJS) $(CLIENT_OBJ) $(SECURE_CMSE_IMPLIB) guest.ld | $(BUILD)
	$(call link_guest,$(GUEST0_FLASH_ORIGIN),$(GUEST0_FLASH_LENGTH),$(GUEST0_RAM_ORIGIN),$(GUEST0_RAM_LENGTH),$(BUILD)/guest0.o $(GUEST0_BOARD_OBJS))

$(BUILD)/guest1.elf: $(BUILD)/guest1.o $(GUEST1_BOARD_OBJS) $(CLIENT_OBJ) $(SECURE_CMSE_IMPLIB) guest.ld | $(BUILD)
	$(call link_guest,$(GUEST1_FLASH_ORIGIN),$(GUEST1_FLASH_LENGTH),$(GUEST1_RAM_ORIGIN),$(GUEST1_RAM_LENGTH),$(BUILD)/guest1.o $(GUEST1_BOARD_OBJS))

$(BUILD)/%.bin: $(BUILD)/%.elf
	$(OBJCOPY) -O binary $< $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean FORCE
FORCE:
